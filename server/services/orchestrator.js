/**
 * OSTE - Open Source Tool Evaluation
 * Analysis Orchestrator
 * 
 * Coordinates the two analysis flows (open source & freeware),
 * manages the pipeline of services, and produces final results.
 */

const GitHubService = require('./github');
const OSVService = require('./osv');
const NVDService = require('./nvd');
const EPSSService = require('./epss');
const VirusTotalService = require('./virustotal');
const HybridAnalysisService = require('./hybrid');
const GroqService = require('./groq');
const ScorerService = require('./scorer');
const ReportGenerator = require('./report');

const BINARY_EXT = /\.(exe|msi|dmg|pkg|zip|7z|rar|tar|gz|tgz|xz|bz2|deb|rpm|apk|appimage|jar|bin|iso|run|sh|ps1|bat|scr|dll)$/i;
const MAX_JOBS = 200;
const JOB_TTL_MS = 24 * 3600 * 1000;

class AnalysisOrchestrator {
  constructor(config) {
    this.github = new GitHubService(config.githubToken);
    this.osv = new OSVService();
    this.nvd = new NVDService(config.nvdApiKey);
    this.epss = new EPSSService();
    this.virusTotal = new VirusTotalService(config.virusTotalApiKey);
    this.hybridAnalysis = new HybridAnalysisService(config.hybridAnalysisApiKey);
    this.groq = new GroqService(config.groqApiKey);
    this.scorer = new ScorerService();
    this.reportGenerator = new ReportGenerator();

    // In-memory job store
    this.jobs = new Map();
  }

  /**
   * Determine analysis type from input.
   */
  detectType(input) {
    const trimmed = input.trim();

    // Direct links to binaries hosted on GitHub (release assets, raw files) are freeware downloads
    if (/^https?:\/\/(github\.com\/[^/]+\/[^/]+\/releases\/download\/|objects\.githubusercontent\.com\/|raw\.githubusercontent\.com\/)/i.test(trimmed)
      || (/^https?:\/\/(www\.)?github\.com\//i.test(trimmed) && BINARY_EXT.test(trimmed.split(/[?#]/)[0]))) {
      return 'freeware';
    }

    // GitHub repository URL or owner/repo shorthand
    if (/^(https?:\/\/)?(www\.)?github\.com\/[^/\s]+\/[^/\s]+/i.test(trimmed) || /^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9._-]+$/.test(trimmed)) {
      return 'opensource';
    }

    // URL to a download/installer
    if (/^https?:\/\//i.test(trimmed)) {
      return 'freeware';
    }

    // File hash (SHA256, MD5, SHA1)
    if (/^([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$/.test(trimmed)) {
      return 'freeware';
    }

    // Default: treat as a tool name to search
    return 'search';
  }

  /**
   * Start an analysis job.
   */
  async startAnalysis(input, options = {}) {
    const jobId = this._generateJobId();
    const type = options.type || this.detectType(input);

    const job = {
      id: jobId,
      input,
      type,
      status: 'running',
      progress: 0,
      currentStep: 'Initializing',
      steps: [],
      startedAt: new Date().toISOString(),
      completedAt: null,
      result: null,
      error: null,
    };

    this._evictJobs();
    this.jobs.set(jobId, job);

    // Run analysis asynchronously
    this._runAnalysis(jobId, input, type, options).catch(err => {
      job.status = 'failed';
      job.error = err.message;
      job.completedAt = new Date().toISOString();
    });

    return { jobId, type };
  }

  /** Drop old finished jobs so the in-memory store cannot grow without bound. */
  _evictJobs() {
    const now = Date.now();
    for (const [id, j] of this.jobs) {
      if (j.status !== 'running' && now - new Date(j.startedAt).getTime() > JOB_TTL_MS) this.jobs.delete(id);
    }
    if (this.jobs.size >= MAX_JOBS) {
      const finished = [...this.jobs.values()].filter((j) => j.status !== 'running')
        .sort((a, b) => new Date(a.startedAt) - new Date(b.startedAt));
      for (const j of finished.slice(0, this.jobs.size - MAX_JOBS + 1)) this.jobs.delete(j.id);
    }
  }

  /**
   * Get job status and results.
   */
  getJob(jobId) {
    return this.jobs.get(jobId) || null;
  }

  /**
   * Run the full analysis pipeline.
   */
  async _runAnalysis(jobId, input, type, options) {
    const job = this.jobs.get(jobId);

    try {
      if (type === 'opensource') {
        await this._runOpenSourceFlow(job, input, options);
      } else if (type === 'freeware') {
        await this._runFreewareFlow(job, input, options);
      } else {
        // Search flow: try GitHub first, fall back to freeware
        await this._runSearchFlow(job, input, options);
      }
    } catch (err) {
      job.status = 'failed';
      job.error = err.message;
      job.completedAt = new Date().toISOString();
      throw err;
    }
  }

  /**
   * Open Source Analysis Flow
   */
  async _runOpenSourceFlow(job, input, options) {
    const data = {};

    // Step 1: GitHub repository analysis
    this._updateProgress(job, 10, 'Fetching repository data from GitHub...');
    try {
      const githubData = await this.github.analyzeRepository(input);
      Object.assign(data, githubData);
      job.steps.push({ name: 'GitHub Analysis', status: 'completed', timestamp: new Date().toISOString() });
    } catch (err) {
      const status = err.response?.status;
      const isRateLimit = status === 403 || status === 429;
      job.steps.push({
        name: 'GitHub Analysis',
        status: isRateLimit ? 'rate_limited' : 'failed',
        error: err.message,
        timestamp: new Date().toISOString(),
      });
      if (status === 404) throw new Error(`GitHub repository not found: "${input}". Check the owner/repo name (private repositories are not supported).`);
      if (isRateLimit) throw new Error(err.message.includes('rate limit') ? err.message : 'GitHub API rate limit exceeded. Set GITHUB_TOKEN for 5000 req/hr.');
      throw new Error(`GitHub analysis failed: ${err.message}`);
    }

    // Step 2: Dependency vulnerability scan via OSV
    this._updateProgress(job, 30, 'Scanning dependencies for vulnerabilities (OSV)...');
    let vulnerabilities = [];
    if (data.dependencies && data.dependencies.length > 0) {
      const osvResult = await this.osv.analyzeDependencies(data.dependencies);
      vulnerabilities = osvResult.vulnerabilities;
      data.osvResult = { totalPackages: osvResult.totalPackages, meta: osvResult.meta };
      data.vulnerabilitySummary = { ...osvResult.summary, totalPackages: osvResult.totalPackages, notHydrated: osvResult.meta?.notHydrated || 0 };
    } else {
      data.vulnerabilitySummary = { total: 0, totalPackages: 0, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    }

    // Advisories for the project's own package (latest release version)
    if (data.selfPackage) {
      const latestTag = data.releases?.find((r) => !r.prerelease && !r.draft)?.tag;
      try {
        data.selfAdvisories = await this.osv.analyzeSelf(data.selfPackage, latestTag || data.selfPackage.version);
      } catch (err) {
        data.selfAdvisories = null;
        console.error(`Self advisory lookup failed: ${err.message}`);
      }
      if (data.selfAdvisories?.current?.length) {
        const ids = new Set(vulnerabilities.map((v) => v.id));
        vulnerabilities.push(...data.selfAdvisories.current.filter((v) => !ids.has(v.id)));
      }
    }
    if (vulnerabilities.length) {
      const sum = this.osv._createSummary(vulnerabilities);
      data.vulnerabilitySummary = { ...data.vulnerabilitySummary, ...sum };
    }
    job.steps.push({ name: 'OSV Scan', status: 'completed', count: vulnerabilities.length, packagesScanned: data.vulnerabilitySummary.totalPackages, timestamp: new Date().toISOString() });

    // Step 3: NVD enrichment (limit to top vulnerabilities)
    this._updateProgress(job, 50, 'Enriching findings with NVD data...');
    const topVulns = vulnerabilities
      .sort((a, b) => (b.cvssScore || 0) - (a.cvssScore || 0))
      .slice(0, options.maxNvdEnrich || 8);

    if (topVulns.length > 0) {
      const enriched = await this.nvd.enrichVulnerabilities(topVulns);
      // Replace enriched vulns back
      const enrichedIds = new Set(enriched.map(v => v.id));
      vulnerabilities = [
        ...enriched,
        ...vulnerabilities.filter(v => !enrichedIds.has(v.id)),
      ];
    }
    job.steps.push({ name: 'NVD Enrichment', status: 'completed', timestamp: new Date().toISOString() });

    // Step 4: EPSS exploit prediction
    this._updateProgress(job, 65, 'Calculating exploit prediction scores (EPSS)...');
    vulnerabilities = await this.epss.enrichVulnerabilities(vulnerabilities);
    job.steps.push({ name: 'EPSS Scoring', status: 'completed', timestamp: new Date().toISOString() });

    data.vulnerabilities = vulnerabilities;
    // Severities may have changed after NVD enrichment: recompute summary so report/scorer agree
    data.vulnerabilitySummary = { ...data.vulnerabilitySummary, ...this.osv._createSummary(vulnerabilities) };
    data.topVulnerabilities = vulnerabilities
      .sort((a, b) => {
        const aScore = (b.cvssScore || 0) + (b.epss?.score || 0) * 10;
        const bScore = (a.cvssScore || 0) + (a.epss?.score || 0) * 10;
        return aScore - bScore;
      })
      .slice(0, 20);

    data.epssData = vulnerabilities
      .filter(v => v.epss?.score)
      .sort((a, b) => (b.epss?.score || 0) - (a.epss?.score || 0))
      .slice(0, 10);

    // Step 5: Risk scoring
    this._updateProgress(job, 75, 'Calculating risk score...');
    const riskScore = this.scorer.scoreOpenSource(data);
    job.steps.push({ name: 'Risk Scoring', status: 'completed', timestamp: new Date().toISOString() });

    // Step 6: AI assessment
    this._updateProgress(job, 85, 'Generating AI risk assessment (Groq LLM)...');
    const aiAssessment = this._reconcileAI(await this.groq.assessOpenSource(data, riskScore), riskScore);
    job.steps.push({ name: 'AI Assessment', status: aiAssessment._meta?.source === 'llm' ? 'completed' : 'fallback', model: aiAssessment._meta?.model, timestamp: new Date().toISOString() });

    // Step 7: Generate reports
    this._updateProgress(job, 95, 'Generating reports...');
    const analysis = {
      target: input,
      type: 'opensource',
      data,
      riskScore,
      aiAssessment,
    };

    const reports = options.skipReports ? null : await this.reportGenerator.generate(analysis);
    job.steps.push({ name: 'Report Generation', status: options.skipReports ? 'skipped' : 'completed', timestamp: new Date().toISOString() });

    // Finalize
    job.result = {
      ...analysis,
      reports,
    };
    job.status = 'completed';
    job.progress = 100;
    job.currentStep = 'Complete';
    job.completedAt = new Date().toISOString();
  }

  /**
   * Freeware Analysis Flow
   */
  async _runFreewareFlow(job, input, options) {
    const data = {
      toolInfo: {
        input,
        type: this._classifyFreewareInput(input),
      },
    };

    if (data.toolInfo.type === 'name') {
      throw new Error(`No GitHub repository found for "${input}". For freeware, provide a download URL or a file hash (MD5/SHA-1/SHA-256).`);
    }

    // Step 1: VirusTotal analysis
    this._updateProgress(job, 15, 'Analyzing with VirusTotal...');
    if (data.toolInfo.type === 'url') {
      data.virusTotal = await this.virusTotal.analyzeURL(input);

      // Also check domain reputation
      try {
        const domain = new URL(input).hostname;
        data.domainReputation = await this.virusTotal.analyzeDomain(domain);
      } catch {
        data.domainReputation = null;
      }
    } else if (data.toolInfo.type === 'hash') {
      data.virusTotal = await this.virusTotal.analyzeFileHash(input);
    }
    job.steps.push({ name: 'VirusTotal Analysis', status: data.virusTotal?.status || 'unknown', timestamp: new Date().toISOString() });

    // Step 2: Hybrid Analysis
    this._updateProgress(job, 45, 'Checking behavioral analysis (Hybrid Analysis)...');
    if (data.toolInfo.type === 'hash') {
      data.hybridAnalysis = await this.hybridAnalysis.searchByHash(input);
    } else {
      const searchTerm = this._extractSearchTerm(input);
      data.hybridAnalysis = await this.hybridAnalysis.searchByTerm(searchTerm);
    }
    job.steps.push({ name: 'Hybrid Analysis', status: data.hybridAnalysis?.status || 'unknown', timestamp: new Date().toISOString() });

    // Step 3: Risk scoring
    this._updateProgress(job, 70, 'Calculating risk score...');
    const riskScore = this.scorer.scoreFreeware(data);
    job.steps.push({ name: 'Risk Scoring', status: 'completed', timestamp: new Date().toISOString() });

    // Step 4: AI assessment
    this._updateProgress(job, 85, 'Generating AI risk assessment (Groq LLM)...');
    const aiAssessment = this._reconcileAI(await this.groq.assessFreeware(data, riskScore), riskScore);
    job.steps.push({ name: 'AI Assessment', status: aiAssessment._meta?.source === 'llm' ? 'completed' : 'fallback', model: aiAssessment._meta?.model, timestamp: new Date().toISOString() });

    // Step 5: Generate reports
    this._updateProgress(job, 95, 'Generating reports...');
    const analysis = {
      target: input,
      type: 'freeware',
      data,
      riskScore,
      aiAssessment,
    };

    const reports = options.skipReports ? null : await this.reportGenerator.generate(analysis);
    job.steps.push({ name: 'Report Generation', status: options.skipReports ? 'skipped' : 'completed', timestamp: new Date().toISOString() });

    // Finalize
    job.result = {
      ...analysis,
      reports,
    };
    job.status = 'completed';
    job.progress = 100;
    job.currentStep = 'Complete';
    job.completedAt = new Date().toISOString();
  }

  /**
   * Search Flow: try to find the tool on GitHub, else treat as freeware.
   */
  async _runSearchFlow(job, input, options) {
    this._updateProgress(job, 5, 'Searching for tool...');

    // Try GitHub search. Only a *search* failure falls back; errors inside the open-source
    // flow (rate limit, etc.) must surface instead of silently switching to the freeware flow.
    let repoName = null;
    try {
      const q = encodeURIComponent(input);
      const found = await this.github._get(`/search/repositories?q=${q}&sort=stars&order=desc&per_page=1`, { ttl: 6 * 3600 * 1000 });
      repoName = found?.items?.[0]?.full_name || null;
    } catch (err) {
      job.steps.push({ name: 'GitHub Search', status: 'failed', error: err.message, timestamp: new Date().toISOString() });
      if ([403, 429].includes(err.response?.status)) {
        throw new Error(`GitHub search is rate limited (${err.message}). Try again later or enter owner/repo directly.`);
      }
    }
    if (repoName) {
      job.steps.push({ name: 'GitHub Search', status: 'completed', match: repoName, timestamp: new Date().toISOString() });
      job.type = 'opensource';
      job.resolvedInput = repoName;
      await this._runOpenSourceFlow(job, repoName, options);
      return;
    }

    // Fallback to freeware flow
    job.type = 'freeware';
    await this._runFreewareFlow(job, input, options);
  }

  /**
   * The deterministic scorer is authoritative for score/level/decision (reproducible, CI-safe).
   * The LLM supplies narrative; its own numbers are kept under aiOriginal for transparency.
   */
  _reconcileAI(ai, score) {
    if (!ai || !score) return ai;
    ai.aiOriginal = { overallRiskScore: ai.overallRiskScore, riskLevel: ai.riskLevel, decision: ai.decision };
    ai.overallRiskScore = score.overallRiskScore;
    ai.riskLevel = score.riskLevel;
    ai.decision = score.decision;
    return ai;
  }

  _updateProgress(job, progress, step) {
    job.progress = progress;
    job.currentStep = step;
  }

  _classifyFreewareInput(input) {
    if (/^https?:\/\//i.test(input)) return 'url';
    if (/^([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$/.test(input)) return 'hash';
    return 'name';
  }

  _extractSearchTerm(input) {
    try {
      const url = new URL(input);
      const pathParts = url.pathname.split('/');
      return pathParts[pathParts.length - 1] || input;
    } catch {
      return input;
    }
  }

  _generateJobId() {
    return `oste-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }
}

module.exports = AnalysisOrchestrator;
