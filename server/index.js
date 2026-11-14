/**
 * OSTE - Open Source Tool Evaluation
 * Express Server & API Routes
 * 
 * Main entry point. Serves the web UI and exposes
 * the REST API for analysis jobs and reports.
 */

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const AnalysisOrchestrator = require('./services/orchestrator');
const { pruneCache } = require('./services/util');

const app = express();
const MAX_CONCURRENT_JOBS = parseInt(process.env.OSTE_MAX_CONCURRENT || '3', 10);

// Housekeeping: prune API response cache entries older than 7 days
pruneCache(7 * 24 * 3600 * 1000);
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, '..', 'public')));

// Initialize orchestrator
const orchestrator = new AnalysisOrchestrator({
  githubToken: process.env.GITHUB_TOKEN,
  nvdApiKey: process.env.NVD_API_KEY,
  virusTotalApiKey: process.env.VIRUSTOTAL_API_KEY,
  hybridAnalysisApiKey: process.env.HYBRID_ANALYSIS_API_KEY,
  groqApiKey: process.env.GROQ_API_KEY,
});

// ============================================================
// API Routes
// ============================================================

/**
 * POST /api/analyze
 * Start a new analysis job.
 * Body: { input: string, type?: 'opensource' | 'freeware' }
 */
app.post('/api/analyze', async (req, res) => {
  try {
    const { input, type } = req.body || {};
    if (!input || typeof input !== 'string' || input.trim().length === 0) {
      return res.status(400).json({
        error: 'Missing or invalid "input" field. Provide a GitHub URL, repository name, download URL, or file hash.',
      });
    }
    if (input.length > 2048) {
      return res.status(400).json({ error: '"input" is too long (max 2048 characters).' });
    }
    if (type !== undefined && type !== null && type !== '' && !['opensource', 'freeware'].includes(type)) {
      return res.status(400).json({ error: '"type" must be "opensource", "freeware" or omitted for auto-detection.' });
    }
    const running = [...orchestrator.jobs.values()].filter((j) => j.status === 'running').length;
    if (running >= MAX_CONCURRENT_JOBS) {
      return res.status(429).json({ error: `Too many analyses in progress (${running}). Wait for one to finish; free-tier API limits make parallel runs slow.` });
    }

    const job = await orchestrator.startAnalysis(input.trim(), { type: type || undefined });
    res.json({
      success: true,
      jobId: job.jobId,
      type: job.type,
      message: `Analysis started. Poll /api/jobs/${job.jobId} for status.`,
    });
  } catch (err) {
    console.error('Analysis start failed:', err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/jobs/:jobId
 * Get the status and results of an analysis job.
 */
app.get('/api/jobs/:jobId', (req, res) => {
  const job = orchestrator.getJob(req.params.jobId);
  if (!job) {
    return res.status(404).json({ error: 'Job not found' });
  }

  // Return a safe subset (avoid sending huge data in progress checks)
  const response = {
    id: job.id,
    input: job.input,
    type: job.type,
    resolvedInput: job.resolvedInput,
    status: job.status,
    progress: job.progress,
    currentStep: job.currentStep,
    steps: job.steps,
    startedAt: job.startedAt,
    completedAt: job.completedAt,
    error: job.error,
  };

  if (job.status === 'completed' && job.result) {
    response.result = {
      target: job.result.target,
      type: job.result.type,
      riskScore: job.result.riskScore,
      aiAssessment: job.result.aiAssessment,
      reports: job.result.reports,
      data: {
        // Send summary data, not full vulnerability lists
        repository: job.result.data?.repository,
        healthScore: job.result.data?.healthScore,
        vulnerabilitySummary: job.result.data?.vulnerabilitySummary,
        selfAdvisories: job.result.data?.selfAdvisories
          ? { ...job.result.data.selfAdvisories, current: (job.result.data.selfAdvisories.current || []).slice(0, 10) }
          : null,
        dependencyStats: job.result.data?.dependencyStats,
        topVulnerabilities: (job.result.data?.topVulnerabilities || []).slice(0, 10),
        languages: job.result.data?.languages,
        contributors: job.result.data?.contributors,
        releases: (job.result.data?.releases || []).slice(0, 5),
        community: job.result.data?.community,
        commits: job.result.data?.commits,
        // Freeware data
        toolInfo: job.result.data?.toolInfo,
        virusTotal: job.result.data?.virusTotal,
        hybridAnalysis: job.result.data?.hybridAnalysis,
        domainReputation: job.result.data?.domainReputation,
      },
    };
  }

  res.json(response);
});

/**
 * GET /api/jobs/:jobId/report/:format
 * Download a report (json or pdf).
 */
app.get('/api/jobs/:jobId/report/:format', (req, res) => {
  const job = orchestrator.getJob(req.params.jobId);
  if (!job) {
    return res.status(404).json({ error: 'Job not found' });
  }
  if (job.status !== 'completed') {
    return res.status(400).json({ error: 'Job not completed yet' });
  }

  const format = req.params.format.toLowerCase();
  if (!['pdf', 'json'].includes(format)) {
    return res.status(400).json({ error: 'Format must be "pdf" or "json".' });
  }
  const reportPath = format === 'pdf'
    ? job.result?.reports?.pdfPath
    : job.result?.reports?.jsonPath;

  if (!reportPath || !fs.existsSync(reportPath)) {
    return res.status(404).json({ error: `${format.toUpperCase()} report not found` });
  }

  const contentType = format === 'pdf' ? 'application/pdf' : 'application/json';
  res.setHeader('Content-Type', contentType);
  res.setHeader('Content-Disposition', `attachment; filename="${path.basename(reportPath)}"`);
  fs.createReadStream(reportPath).pipe(res);
});

/**
 * GET /api/config/status
 * Check which API keys are configured.
 */
app.get('/api/config/status', (req, res) => {
  res.json({
    github: !!process.env.GITHUB_TOKEN,
    nvd: !!process.env.NVD_API_KEY,
    virusTotal: !!process.env.VIRUSTOTAL_API_KEY,
    hybridAnalysis: !!process.env.HYBRID_ANALYSIS_API_KEY,
    groq: !!process.env.GROQ_API_KEY,
  });
});

/**
 * GET /api/jobs
 * List recent jobs.
 */
app.get('/api/jobs', (req, res) => {
  const jobs = Array.from(orchestrator.jobs.values())
    .sort((a, b) => new Date(b.startedAt) - new Date(a.startedAt))
    .slice(0, 50)
    .map(j => ({
      id: j.id,
      input: j.input,
      type: j.type,
      status: j.status,
      progress: j.progress,
      startedAt: j.startedAt,
      completedAt: j.completedAt,
      riskScore: j.result?.riskScore?.overallRiskScore,
      riskLevel: j.result?.riskScore?.riskLevel,
      decision: j.result?.riskScore?.decision,
    }));

  res.json({ jobs });
});

// Unknown API routes -> JSON 404 (instead of the SPA HTML)
app.use('/api', (req, res) => res.status(404).json({ error: `Unknown API route: ${req.method} ${req.originalUrl}` }));

// Malformed JSON bodies and other errors -> JSON instead of an HTML stack trace
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Request body is not valid JSON.' });
  if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Request body too large.' });
  console.error('Unhandled request error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Serve index.html for all non-API routes (SPA)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

process.on('unhandledRejection', (err) => console.error('Unhandled promise rejection:', err));

// Start server
const server = app.listen(PORT, () => {
  console.log(`
  ╔═══════════════════════════════════════════════════╗
  ║                                                   ║
  ║     ██████╗ ███████╗████████╗███████╗             ║
  ║    ██╔═══██╗██╔════╝╚══██╔══╝██╔════╝             ║
  ║    ██║   ██║███████╗   ██║   █████╗               ║
  ║    ██║   ██║╚════██║   ██║   ██╔══╝               ║
  ║    ╚██████╔╝███████║   ██║   ███████╗             ║
  ║     ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝             ║
  ║                                                   ║
  ║    Open Source Tool Evaluation                    ║
  ║    Security Risk Assessment Platform              ║
  ║                                                   ║
  ╚═══════════════════════════════════════════════════╝

  🚀 Server running at http://localhost:${PORT}
  📊 API available at http://localhost:${PORT}/api

  API Keys Status:
    GitHub:          ${process.env.GITHUB_TOKEN ? '✅ Configured' : '⚠️  Not set'}
    NVD:             ${process.env.NVD_API_KEY ? '✅ Configured' : '⚠️  Not set (rate limited)'}
    VirusTotal:      ${process.env.VIRUSTOTAL_API_KEY ? '✅ Configured' : '⚠️  Not set'}
    Hybrid Analysis: ${process.env.HYBRID_ANALYSIS_API_KEY ? '✅ Configured' : '⚠️  Not set'}
    Groq:            ${process.env.GROQ_API_KEY ? '✅ Configured' : '⚠️  Not set (fallback mode)'}
  `);
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`Port ${PORT} is already in use. Stop the other process or set PORT in .env.`);
    process.exit(1);
  }
  throw err;
});

module.exports = app;
