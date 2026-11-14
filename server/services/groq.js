/**
 * OSTE - Open Source Tool Evaluation
 * Groq LLM Risk Assessment Service
 *
 * Free-tier aware: 8,000 tokens/minute and ~1000 requests/day per model.
 *  - prompts are compacted (~2k tokens)
 *  - a sliding-window token budget delays calls instead of hitting 429
 *  - 429s honor Retry-After, then fail over to the next model
 *  - if every model fails, a deterministic assessment is built from the scorer output
 */

const axios = require('axios');
const { sleep } = require('./util');

const DEFAULT_MODELS = ['openai/gpt-oss-120b', 'openai/gpt-oss-20b', 'qwen/qwen3.8-27b'];
const TPM_BUDGET = 7000; // stay under the 8000 TPM free-tier cap

class GroqService {
  constructor(apiKey) {
    this.apiKey = apiKey;
    this.models = process.env.GROQ_MODEL ? [process.env.GROQ_MODEL, ...DEFAULT_MODELS] : DEFAULT_MODELS;
    this.api = axios.create({
      baseURL: 'https://api.groq.com/openai/v1',
      timeout: 90000,
      headers: apiKey ? { Authorization: `Bearer ${apiKey}` } : {},
    });
    this.window = []; // [{t, tokens}]
    this.lastLimits = null;
  }

  _estimateTokens(text) {
    return Math.ceil(text.length / 3.2);
  }

  async _reserve(tokens) {
    for (;;) {
      const now = Date.now();
      this.window = this.window.filter((w) => now - w.t < 61000);
      const used = this.window.reduce((a, w) => a + w.tokens, 0);
      if (used + tokens <= TPM_BUDGET) {
        this.window.push({ t: now, tokens });
        return;
      }
      const oldest = this.window[0];
      await sleep(Math.max(1000, oldest.t + 61000 - now));
    }
  }

  async assessOpenSource(data, score) {
    return this._analyze(this._buildOpenSourcePrompt(data, score), 'opensource', score);
  }

  async assessFreeware(data, score) {
    return this._analyze(this._buildFreewarePrompt(data, score), 'freeware', score);
  }

  async _analyze(prompt, kind, score) {
    if (!this.apiKey) {
      return this._fallbackAssessment(kind, score, 'No GROQ_API_KEY configured');
    }
    const system = `You are OSTE, an expert security analyst assessing software for enterprise adoption.
Respond ONLY with one valid JSON object matching the requested schema. Be concise (short sentences, max 5 items per list).
Base findings strictly on the data provided; if data is missing say so rather than guessing. Never invent CVEs.
The deterministic risk score supplied is authoritative: keep your overallRiskScore within 10 points of it.`;
    const maxTokens = 2200;
    const errors = [];

    for (const model of this.models) {
      const promptTokens = this._estimateTokens(system + prompt);
      for (let attempt = 0; attempt < 2; attempt++) {
        await this._reserve(promptTokens + maxTokens);
        try {
          const body = {
            model,
            messages: [{ role: 'system', content: system }, { role: 'user', content: prompt }],
            temperature: 0.1,
            max_tokens: maxTokens,
            response_format: { type: 'json_object' },
          };
          if (model.startsWith('openai/gpt-oss')) body.reasoning_effort = 'low';
          const resp = await this.api.post('/chat/completions', body);
          this.lastLimits = {
            remainingTokens: resp.headers['x-ratelimit-remaining-tokens'],
            remainingRequests: resp.headers['x-ratelimit-remaining-requests'],
          };
          const content = resp.data.choices?.[0]?.message?.content;
          const parsed = this._parseJson(content);
          const missing = ['overallRiskScore', 'executiveSummary', 'recommendations'].filter((k) => parsed[k] === undefined);
          if (missing.length) throw new Error(`LLM response missing fields: ${missing.join(', ')}`);
          parsed._meta = { source: 'llm', model, usage: resp.data.usage };
          return parsed;
        } catch (err) {
          const status = err.response?.status;
          const msg = err.response?.data?.error?.message || err.message;
          errors.push(`${model}: ${status || ''} ${msg}`.slice(0, 200));
          if (status === 429) {
            const ra = parseFloat(err.response.headers['retry-after']);
            if (Number.isFinite(ra) && ra <= 30 && attempt === 0) { await sleep(ra * 1000 + 500); continue; }
            break; // daily/long limit: next model
          }
          if (status === 400 || status === 404) break; // bad model or request: next model
          if (attempt === 0) { await sleep(2000); continue; }
        }
      }
    }
    console.error(`Groq analysis failed on all models: ${errors.join(' | ')}`);
    return this._fallbackAssessment(kind, score, errors.join(' | '));
  }

  _parseJson(content) {
    if (!content) throw new Error('empty LLM response');
    try {
      return JSON.parse(content);
    } catch {
      const m = content.match(/\{[\s\S]*\}/);
      if (!m) throw new Error('LLM response is not JSON');
      return JSON.parse(m[0]);
    }
  }

  // ---- prompt builders (compact) ----

  _slimVuln(v) {
    return {
      id: v.id,
      cve: v.cveIds?.[0],
      severity: v.severity,
      cvss: v.cvssScore,
      pkg: v.affectedPackage ? `${v.affectedPackage}@${v.affectedVersion}` : undefined,
      summary: (v.summary || '').slice(0, 110),
      epss: v.epss ? Number(v.epss.score.toFixed(4)) : undefined,
    };
  }

  _buildOpenSourcePrompt(data, score) {
    const r = data.repository || {};
    const failed = (data.healthScore?.details || []).filter((d) => d.passed === false).map((d) => d.label);
    const compact = {
      repository: {
        name: r.name, description: (r.description || '').slice(0, 160), language: r.language, stars: r.stars, forks: r.forks,
        license: r.license?.spdxId || r.license?.name || null, archived: r.archived, isFork: r.isFork,
        createdAt: r.createdAt, pushedAt: r.pushedAt, topics: (r.topics || []).slice(0, 6),
        dataQuality: r._partial ? `PARTIAL: ${r._error}` : 'ok',
      },
      health: { score: data.healthScore?.score, failedChecks: failed },
      contributors: data.contributors ? { count: data.contributors.count, cappedAt30: data.contributors.capped } : null,
      latestReleases: (data.releases || []).slice(0, 3).map((x) => ({ tag: x.tag, date: x.publishedAt?.slice(0, 10), pre: x.prerelease })),
      lastCommitDate: data.commits?.lastCommitDate,
      community: data.community,
      dependencyScan: {
        ...(data.vulnerabilitySummary || {}),
        ...(data.dependencyStats ? { runtimePackages: data.dependencyStats.runtimePackages, manifests: data.dependencyStats.manifestsFound } : {}),
      },
      topDependencyVulns: (data.topVulnerabilities || []).slice(0, 8).map((v) => this._slimVuln(v)),
      ownPackageAdvisories: data.selfAdvisories
        ? {
            package: data.selfAdvisories.package, version: data.selfAdvisories.version,
            affectingLatestVersion: (data.selfAdvisories.current || []).map((v) => this._slimVuln(v)).slice(0, 5),
            historicalAdvisoryCount: data.selfAdvisories.historicalCount, historicalSeverity: data.selfAdvisories.historicalSeverity,
          }
        : null,
    };
    return `Assess this open source project.

DETERMINISTIC RISK SCORE: ${score?.overallRiskScore} (${score?.riskLevel}, decision ${score?.decision}); component scores: ${JSON.stringify(Object.fromEntries(Object.entries(score?.components || {}).map(([k, c]) => [k, c.score])))}

DATA:
${JSON.stringify(compact)}

JSON schema to return:
{"overallRiskScore":<0-100>,"riskLevel":"CRITICAL|HIGH|MEDIUM|LOW|MINIMAL","decision":"APPROVE|APPROVE_WITH_CONDITIONS|REVIEW_REQUIRED|REJECT",
"executiveSummary":"<2-3 sentences>",
"securityPosture":{"score":<0-100>,"strengths":[],"weaknesses":[],"criticalFindings":[]},
"projectHealth":{"score":<0-100>,"maintainerActivity":"ACTIVE|MODERATE|LOW|DORMANT","communityEngagement":"STRONG|MODERATE|WEAK","releaseMaturity":"MATURE|DEVELOPING|EARLY|STALE"},
"vulnerabilityAnalysis":{"overallExposure":"CRITICAL|HIGH|MEDIUM|LOW|MINIMAL","exploitableVulns":<count with EPSS>=0.1>,"keyFindings":[],"remediationPriority":[]},
"licenseCompliance":{"risk":"HIGH|MEDIUM|LOW|NONE","type":"<license>","concerns":[]},
"recommendations":[{"priority":"CRITICAL|HIGH|MEDIUM|LOW","action":"","rationale":""}],
"mitigations":[]}`;
  }

  _buildFreewarePrompt(data, score) {
    const vt = data.virusTotal || {};
    const dom = data.domainReputation || {};
    const ha = data.hybridAnalysis || {};
    const compact = {
      input: data.toolInfo,
      virusTotal: {
        status: vt.status, target: vt.target, name: vt.name, fileType: vt.fileType, size: vt.size,
        malicious: vt.malicious, suspicious: vt.suspicious, harmless: vt.harmless, undetected: vt.undetected,
        reputation: vt.reputation, tags: (vt.tags || []).slice(0, 8), signed: !!vt.signatureInfo,
        signer: vt.signatureInfo?.['signers'] || vt.signatureInfo?.product,
        detections: (vt.detectionNames || []).slice(0, 8), message: vt.message || vt.error,
      },
      domain: {
        status: dom.status, domain: dom.target, reputation: dom.reputation, malicious: dom.malicious, suspicious: dom.suspicious,
        harmless: dom.harmless, categories: dom.categories ? Object.values(dom.categories).slice(0, 4) : undefined,
        registrar: dom.registrar, created: dom.creationDate ? new Date(dom.creationDate * 1000).toISOString().slice(0, 10) : undefined,
      },
      hybridAnalysis: { status: ha.status, message: ha.message, primary: ha.primary },
    };
    return `Assess this freeware / downloadable tool.

DETERMINISTIC RISK SCORE: ${score?.overallRiskScore} (${score?.riskLevel}, decision ${score?.decision}); components: ${JSON.stringify(Object.fromEntries(Object.entries(score?.components || {}).map(([k, c]) => [k, c.available === false ? 'n/a' : c.score])))}

DATA:
${JSON.stringify(compact)}

JSON schema to return:
{"overallRiskScore":<0-100>,"riskLevel":"CRITICAL|HIGH|MEDIUM|LOW|MINIMAL","decision":"APPROVE|APPROVE_WITH_CONDITIONS|REVIEW_REQUIRED|REJECT",
"executiveSummary":"<2-3 sentences>",
"malwareAnalysis":{"detectionRate":"","engineFlags":<number>,"verdict":"CLEAN|SUSPICIOUS|MALICIOUS|UNKNOWN","keyFindings":[]},
"behavioralAnalysis":{"riskLevel":"CRITICAL|HIGH|MEDIUM|LOW|CLEAN|UNKNOWN","networkActivity":"","fileSystemActivity":"","registryActivity":"","suspiciousBehaviors":[]},
"publisherReputation":{"score":<0-100>,"signed":<bool>,"publisher":"","trustLevel":"TRUSTED|MODERATE|UNTRUSTED|UNKNOWN"},
"recommendations":[{"priority":"CRITICAL|HIGH|MEDIUM|LOW","action":"","rationale":""}],
"mitigations":[]}`;
  }

  /**
   * Deterministic assessment used when the LLM is unavailable. Built from the scorer output,
   * so it is still meaningful (and clearly labelled as non-AI).
   */
  _fallbackAssessment(kind, score, reason) {
    const comps = score?.components || {};
    const weak = Object.values(comps).filter((c) => c.available !== false && c.score >= 50).map((c) => `${c.label} (${c.score}/100)`);
    const strong = Object.values(comps).filter((c) => c.available !== false && c.score < 25).map((c) => `${c.label} (${c.score}/100)`);
    return {
      overallRiskScore: score?.overallRiskScore ?? 50,
      riskLevel: score?.riskLevel || 'MEDIUM',
      decision: score?.decision || 'REVIEW_REQUIRED',
      executiveSummary: `Rule-based assessment (AI analysis unavailable). Risk score ${score?.overallRiskScore ?? 'n/a'}/100 (${score?.riskLevel || 'n/a'}). ${weak.length ? 'Main concerns: ' + weak.join(', ') + '.' : 'No component exceeded the concern threshold.'}`,
      securityPosture: { score: score ? 100 - score.overallRiskScore : 50, strengths: strong, weaknesses: weak, criticalFindings: [] },
      recommendations: score?.recommendations?.length ? score.recommendations : [
        { priority: 'MEDIUM', action: 'Review the collected data manually', rationale: 'AI assessment was unavailable for this run.' },
      ],
      mitigations: ['Perform manual security review before adoption'],
      _meta: { source: 'fallback', reason: (reason || '').slice(0, 300) },
    };
  }
}

module.exports = GroqService;
