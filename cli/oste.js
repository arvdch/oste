#!/usr/bin/env node

/**
 * OSTE CLI - Open Source Tool Evaluation
 * Command-line interface for security risk assessment.
 *
 * Usage:
 *   node cli/oste.js analyze facebook/react
 *   node cli/oste.js analyze https://example.com/tool.exe --type freeware
 *   node cli/oste.js analyze <sha256-hash>
 */

const { Command } = require('commander');
const path = require('path');
const fs = require('fs');

// Load .env from project root
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const AnalysisOrchestrator = require('../server/services/orchestrator');

const program = new Command();

// ---- Helpers for colorized output (no chalk needed at runtime) ----
const c = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  bgRed: '\x1b[41m',
  bgGreen: '\x1b[42m',
  bgYellow: '\x1b[43m',
  bgBlue: '\x1b[44m',
};

function riskStyle(level) {
  const map = {
    CRITICAL: c.bgRed + c.white + c.bold,
    HIGH: c.red + c.bold,
    MEDIUM: c.yellow + c.bold,
    LOW: c.blue + c.bold,
    MINIMAL: c.green + c.bold,
    CLEAN: c.green + c.bold,
  };
  return (map[level] || c.dim) + ` ${level} ` + c.reset;
}

function spinner(text) {
  const frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
  let i = 0;
  const id = setInterval(() => {
    process.stdout.write(`\r${c.cyan}${frames[i++ % frames.length]}${c.reset} ${text}`);
  }, 80);
  return {
    update(newText) { text = newText; },
    succeed(msg) { clearInterval(id); process.stdout.write(`\r${c.green}✔${c.reset} ${msg}\n`); },
    fail(msg) { clearInterval(id); process.stdout.write(`\r${c.red}✖${c.reset} ${msg}\n`); },
    stop() { clearInterval(id); process.stdout.write('\r'); },
  };
}

function printBanner() {
  console.log(`
${c.cyan}${c.bold}  ╔═══════════════════════════════════════╗
  ║   ██████╗ ███████╗████████╗███████╗  ║
  ║  ██╔═══██╗██╔════╝╚══██╔══╝██╔════╝  ║
  ║  ██║   ██║███████╗   ██║   █████╗    ║
  ║  ██║   ██║╚════██║   ██║   ██╔══╝    ║
  ║  ╚██████╔╝███████║   ██║   ███████╗  ║
  ║   ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝  ║
  ╠═══════════════════════════════════════╣
  ║  Open Source Tool Evaluation  v1.1.0  ║
  ║  Security Risk Assessment Platform    ║
  ╚═══════════════════════════════════════╝${c.reset}
`);
}

function printTable(rows, headers) {
  const colWidths = headers.map((h, i) =>
    Math.max(h.length, ...rows.map((r) => String(r[i] || '').length))
  );

  const border = colWidths.map((w) => '─'.repeat(w + 2)).join('┼');
  const headerLine = headers
    .map((h, i) => ` ${c.bold}${h.padEnd(colWidths[i])}${c.reset} `)
    .join('│');

  console.log(`┌${border.replace(/┼/g, '┬')}┐`);
  console.log(`│${headerLine}│`);
  console.log(`├${border}┤`);

  for (const row of rows) {
    const line = row
      .map((cell, i) => ` ${String(cell || '').padEnd(colWidths[i])} `)
      .join('│');
    console.log(`│${line}│`);
  }

  console.log(`└${border.replace(/┼/g, '┴')}┘`);
}

// ---- CLI Commands ----

program
  .name('oste')
  .description('OSTE - Open Source Tool Evaluation CLI')
  .version(require('../package.json').version);

program
  .command('analyze')
  .description('Analyze an open source tool or freeware for security risks')
  .argument('<input>', 'GitHub repo (owner/repo or URL), download URL, or file hash')
  .option('-t, --type <type>', 'Force analysis type: opensource or freeware')
  .option('--json', 'Output raw JSON result')
  .option('--no-report', 'Skip PDF/JSON report generation')
  .option('--fail-above <score>', 'Exit with code 2 when the risk score is above this value (CI gate)')
  .action(async (input, options) => {
    if (options.type && !['opensource', 'freeware'].includes(options.type)) {
      console.error(`Invalid --type "${options.type}". Use "opensource" or "freeware".`);
      process.exit(1);
    }
    const failAbove = options.failAbove !== undefined ? Number(options.failAbove) : null;
    if (failAbove !== null && !Number.isFinite(failAbove)) {
      console.error('--fail-above must be a number between 0 and 100.');
      process.exit(1);
    }
    if (!options.json) printBanner();
    const log = options.json ? () => {} : console.log;

    const orchestrator = new AnalysisOrchestrator({
      githubToken: process.env.GITHUB_TOKEN,
      nvdApiKey: process.env.NVD_API_KEY,
      virusTotalApiKey: process.env.VIRUSTOTAL_API_KEY,
      hybridAnalysisApiKey: process.env.HYBRID_ANALYSIS_API_KEY,
      groqApiKey: process.env.GROQ_API_KEY,
    });

    const detectedType = options.type || orchestrator.detectType(input);
    log(
      `${c.dim}Target:${c.reset} ${c.bold}${input}${c.reset}`
    );
    log(
      `${c.dim}Type:${c.reset}   ${detectedType === 'opensource' ? '📦 Open Source' : detectedType === 'freeware' ? '💾 Freeware' : '🔄 Auto-detect'}`
    );
    log();

    const s = options.json || !process.stdout.isTTY
      ? { update() {}, succeed() {}, fail(m) { console.error(m); }, stop() {} }
      : spinner('Starting analysis...');

    try {
      const { jobId } = await orchestrator.startAnalysis(input, { type: options.type, skipReports: options.report === false });

      // Poll until complete
      let job;
      let lastStep = '';
      while (true) {
        await new Promise((r) => setTimeout(r, 1000));
        job = orchestrator.getJob(jobId);

        if (!job) {
          s.fail('Job not found');
          process.exit(1);
        }

        if (job.currentStep !== lastStep) {
          s.update(`[${job.progress}%] ${job.currentStep}`);
          lastStep = job.currentStep;
        }

        if (job.status === 'completed') {
          s.succeed('Analysis complete!');
          break;
        }
        if (job.status === 'failed') {
          s.fail(`Analysis failed: ${job.error}`);
          process.exit(1);
        }
      }

      const result = job.result;

      const exitCode = failAbove !== null && (result.riskScore?.overallRiskScore ?? 100) > failAbove ? 2 : 0;
      if (options.json) {
        console.log(JSON.stringify({
          target: result.target, type: result.type, riskScore: result.riskScore,
          aiAssessment: result.aiAssessment, reports: result.reports,
          vulnerabilitySummary: result.data?.vulnerabilitySummary, selfAdvisories: result.data?.selfAdvisories,
          virusTotal: result.data?.virusTotal,
        }, null, 2));
        process.exitCode = exitCode;
        return;
      }
      process.exitCode = exitCode;

      // ---- Print Results ----
      console.log();
      const score = result.riskScore?.overallRiskScore ?? 0;
      const level = result.riskScore?.riskLevel || 'UNKNOWN';
      const decision = result.riskScore?.decision || 'REVIEW_REQUIRED';

      // Risk Score Box
      console.log(`  ┌─────────────────────────────────────────┐`);
      console.log(`  │  ${c.bold}RISK SCORE:${c.reset}  ${riskStyle(level)}  ${c.bold}${score}/100${c.reset}`.padEnd(60) + `│`);
      console.log(`  │  ${c.bold}DECISION:${c.reset}    ${decision.replace(/_/g, ' ')}`.padEnd(52) + `│`);
      console.log(`  └─────────────────────────────────────────┘`);
      console.log();

      // Executive Summary
      const ai = result.aiAssessment || {};
      if (ai.executiveSummary) {
        console.log(`${c.bold}📋 Executive Summary${c.reset}`);
        console.log(`${c.dim}${'─'.repeat(50)}${c.reset}`);
        console.log(ai.executiveSummary);
        console.log();
      }

      // Risk Components
      const comps = result.riskScore?.components || {};
      if (Object.keys(comps).length > 0) {
        console.log(`${c.bold}📊 Risk Breakdown${c.reset}`);
        console.log(`${c.dim}${'─'.repeat(50)}${c.reset}`);
        const compRows = Object.entries(comps).map(([k, v]) => {
          if (v.available === false) return [v.label, 'no data', '░'.repeat(20), 'excluded'];
          const filled = Math.max(0, Math.min(20, Math.round(v.score / 5)));
          const bar = '█'.repeat(filled) + '░'.repeat(20 - filled);
          return [v.label, `${v.score}/100`, bar, `${Math.round((v.effectiveWeight ?? v.weight) * 100)}%`];
        });
        printTable(compRows, ['Component', 'Score', 'Bar', 'Weight']);
        console.log();
      }

      // Vulnerability Summary
      if (result.type === 'opensource') {
        const vs = result.data?.vulnerabilitySummary || {};
        console.log(`${c.bold}🔓 Vulnerabilities${c.reset}`);
        console.log(`${c.dim}${'─'.repeat(50)}${c.reset}`);
        console.log(`  Total: ${vs.total || 0}  |  Packages Scanned: ${vs.totalPackages || 0}`);
        console.log(
          `  ${c.red}Critical: ${vs.CRITICAL || 0}${c.reset}  ` +
          `${c.yellow}High: ${vs.HIGH || 0}${c.reset}  ` +
          `${c.yellow}Medium: ${vs.MEDIUM || 0}${c.reset}  ` +
          `${c.blue}Low: ${vs.LOW || 0}${c.reset}`
        );
        console.log();

        // Top vulns
        const topVulns = (result.data?.topVulnerabilities || []).slice(0, 5);
        if (topVulns.length > 0) {
          const vulnRows = topVulns.map((v) => [
            v.id,
            v.severity || '?',
            v.cvssScore || '—',
            v.epss?.score ? `${(v.epss.score * 100).toFixed(1)}%` : '—',
            v.affectedPackage || '—',
          ]);
          printTable(vulnRows, ['CVE/ID', 'Severity', 'CVSS', 'EPSS', 'Package']);
          console.log();
        }
      }

      // Recommendations
      const recs = [].concat(ai.recommendations || []).map((r) => (typeof r === 'string' ? { priority: 'MEDIUM', action: r } : r || {}));
      if (recs.length > 0) {
        console.log(`${c.bold}💡 Recommendations${c.reset}`);
        console.log(`${c.dim}${'─'.repeat(50)}${c.reset}`);
        for (const rec of recs) {
          const priorityColor =
            rec.priority === 'CRITICAL' ? c.red :
            rec.priority === 'HIGH' ? c.yellow :
            rec.priority === 'MEDIUM' ? c.blue : c.dim;
          console.log(`  ${priorityColor}[${rec.priority}]${c.reset} ${rec.action}`);
          if (rec.rationale) console.log(`    ${c.dim}↳ ${rec.rationale}${c.reset}`);
        }
        console.log();
      }

      const conf = result.riskScore?.confidenceLevel;
      console.log(`${c.dim}AI narrative: ${ai._meta?.source === 'llm' ? ai._meta.model : 'rule-based fallback'}${conf ? ` · data confidence ${conf.level} (${conf.score}%)` : ''}${c.reset}`);
      console.log();
      if (exitCode) console.log(`${c.red}${c.bold}CI gate: risk score ${score} is above --fail-above ${failAbove} (exit 2)${c.reset}\n`);

      // Report paths
      if (result.reports) {
        console.log(`${c.bold}📄 Reports Generated${c.reset}`);
        console.log(`${c.dim}${'─'.repeat(50)}${c.reset}`);
        if (result.reports.pdfPath) console.log(`  PDF:  ${c.cyan}${result.reports.pdfPath}${c.reset}`);
        if (result.reports.jsonPath) console.log(`  JSON: ${c.cyan}${result.reports.jsonPath}${c.reset}`);
        console.log();
      }
    } catch (err) {
      s.fail(`Error: ${err.message}`);
      process.exit(1);
    }
  });

program
  .command('test')
  .description('Run the live end-to-end test suite (paced for free-tier API limits)')
  .argument('[filter]', 'Case ids separated by |, e.g. "1|2|20"')
  .option('--suite <name>', 'core | extended | all', 'all')
  .action((filter, opts) => {
    const { spawnSync } = require('child_process');
    const args = [path.join(__dirname, '..', 'tests', 'e2e.js'), ...(filter ? [filter] : [])];
    const r = spawnSync(process.execPath, args, { stdio: 'inherit', env: { ...process.env, OSTE_SUITE: opts.suite } });
    process.exit(r.status ?? 1);
  });

program
  .command('config')
  .description('Check API key configuration status')
  .action(() => {
    printBanner();
    console.log(`${c.bold}⚙️  API Configuration Status${c.reset}`);
    console.log(`${c.dim}${'─'.repeat(50)}${c.reset}`);

    const keys = [
      { name: 'GitHub', env: 'GITHUB_TOKEN', required: 'Open Source flow' },
      { name: 'NVD', env: 'NVD_API_KEY', required: 'Enrichment (optional)' },
      { name: 'VirusTotal', env: 'VIRUSTOTAL_API_KEY', required: 'Freeware flow' },
      { name: 'Hybrid Analysis', env: 'HYBRID_ANALYSIS_API_KEY', required: 'Freeware flow' },
      { name: 'Groq', env: 'GROQ_API_KEY', required: 'AI Assessment' },
    ];

    for (const k of keys) {
      const configured = !!process.env[k.env];
      const icon = configured ? `${c.green}✅${c.reset}` : `${c.yellow}⚠️${c.reset} `;
      const status = configured ? `${c.green}Configured${c.reset}` : `${c.yellow}Not set${c.reset}`;
      console.log(`  ${icon} ${k.name.padEnd(18)} ${status.padEnd(30)} ${c.dim}(${k.required})${c.reset}`);
    }

    console.log();
    console.log(`${c.dim}Set keys in .env file or as environment variables.${c.reset}`);
    console.log(`${c.dim}See .env.example for details.${c.reset}`);
  });

program.parse();
