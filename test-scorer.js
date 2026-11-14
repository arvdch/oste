#!/usr/bin/env node

/**
 * OSTE Scorer Unit Test
 * Tests the scoring engine with mock data representing different risk profiles.
 * Run: node test-scorer.js
 */

const ScorerService = require('./server/services/scorer');
const scorer = new ScorerService();

const c = {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m',
  blue: '\x1b[34m', cyan: '\x1b[36m',
};

function riskColor(level) {
  const map = { CRITICAL: c.red, HIGH: c.red, MEDIUM: c.yellow, LOW: c.blue, MINIMAL: c.green };
  return map[level] || c.dim;
}

// ============ MOCK DATA PROFILES ============

const profiles = {
  // 1. Healthy, well-maintained project (like React)
  'facebook/react (healthy)': {
    repository: {
      name: 'facebook/react', stars: 252000, forks: 51000, watchers: 6700,
      openIssues: 1500, license: { key: 'mit', name: 'MIT License' },
      archived: false, disabled: false, createdAt: '2013-05-24T00:00:00Z',
      pushedAt: new Date(Date.now() - 1 * 86400000).toISOString(), // 1 day ago
    },
    contributors: { count: 30, top: [] },
    commits: { lastCommitDate: new Date(Date.now() - 1 * 86400000).toISOString() },
    releases: [
      { publishedAt: new Date(Date.now() - 30 * 86400000).toISOString() },
      { publishedAt: new Date(Date.now() - 90 * 86400000).toISOString() },
      { publishedAt: new Date(Date.now() - 180 * 86400000).toISOString() },
      { publishedAt: new Date(Date.now() - 270 * 86400000).toISOString() },
      { publishedAt: new Date(Date.now() - 360 * 86400000).toISOString() },
    ],
    community: {
      healthPercentage: 100, hasSecurityPolicy: true, hasContributing: true,
      hasReadme: true, hasCodeOfConduct: true,
    },
    issues: { avgCloseTimeHours: 48 },
    pullRequests: { avgMergeTimeHours: 24 },
    vulnerabilities: [],
    healthScore: { score: 95 },
  },

  // 2. Solid mid-tier project (like Express)
  'expressjs/express (solid)': {
    repository: {
      name: 'expressjs/express', stars: 65000, forks: 16000, watchers: 3200,
      openIssues: 260, license: { key: 'mit', name: 'MIT License' },
      archived: false, createdAt: '2009-06-26T00:00:00Z',
      pushedAt: new Date(Date.now() - 5 * 86400000).toISOString(),
    },
    contributors: { count: 30 },
    commits: { lastCommitDate: new Date(Date.now() - 5 * 86400000).toISOString() },
    releases: [
      { publishedAt: new Date(Date.now() - 60 * 86400000).toISOString() },
      { publishedAt: new Date(Date.now() - 120 * 86400000).toISOString() },
      { publishedAt: new Date(Date.now() - 200 * 86400000).toISOString() },
      { publishedAt: new Date(Date.now() - 300 * 86400000).toISOString() },
      { publishedAt: new Date(Date.now() - 400 * 86400000).toISOString() },
    ],
    community: {
      healthPercentage: 85, hasSecurityPolicy: true, hasContributing: true,
      hasReadme: true, hasCodeOfConduct: false,
    },
    issues: { avgCloseTimeHours: 72 },
    pullRequests: { avgMergeTimeHours: 48 },
    vulnerabilities: [
      { id: 'CVE-2024-1001', severity: 'MEDIUM', cvssScore: 5.3 },
      { id: 'CVE-2024-1002', severity: 'LOW', cvssScore: 3.1 },
    ],
    healthScore: { score: 82 },
  },

  // 3. Deprecated/unmaintained project (like Moment.js)
  'moment/moment (deprecated)': {
    repository: {
      name: 'moment/moment', stars: 48000, forks: 7200, watchers: 1500,
      openIssues: 250, license: { key: 'mit', name: 'MIT License' },
      archived: false, createdAt: '2011-03-01T00:00:00Z',
      pushedAt: new Date(Date.now() - 400 * 86400000).toISOString(), // last push 400 days ago
    },
    contributors: { count: 25 },
    commits: { lastCommitDate: new Date(Date.now() - 400 * 86400000).toISOString() },
    releases: [
      { publishedAt: new Date(Date.now() - 800 * 86400000).toISOString() }, // 2+ years ago
    ],
    community: {
      healthPercentage: 60, hasSecurityPolicy: false, hasContributing: true,
      hasReadme: true, hasCodeOfConduct: false,
    },
    issues: { avgCloseTimeHours: 720 }, // Takes a month to close issues
    pullRequests: { avgMergeTimeHours: 400 },
    vulnerabilities: [
      { id: 'CVE-2022-31129', severity: 'HIGH', cvssScore: 7.5, epss: { score: 0.15 } },
      { id: 'CVE-2022-24785', severity: 'HIGH', cvssScore: 7.5, epss: { score: 0.08 } },
      { id: 'GHSA-abc1', severity: 'MEDIUM', cvssScore: 5.3 },
    ],
    healthScore: { score: 55 },
  },

  // 4. Legacy project with many CVEs (like jQuery — historical)
  'jquery/jquery (legacy CVEs)': {
    repository: {
      name: 'jquery/jquery', stars: 59000, forks: 20500, watchers: 3100,
      openIssues: 96, license: { key: 'mit', name: 'MIT License' },
      archived: false, createdAt: '2009-04-03T00:00:00Z',
      pushedAt: new Date(Date.now() - 10 * 86400000).toISOString(),
    },
    contributors: { count: 30 },
    commits: { lastCommitDate: new Date(Date.now() - 10 * 86400000).toISOString() },
    releases: [
      { publishedAt: new Date(Date.now() - 200 * 86400000).toISOString() },
      { publishedAt: new Date(Date.now() - 400 * 86400000).toISOString() },
    ],
    community: {
      healthPercentage: 70, hasSecurityPolicy: true, hasContributing: true,
      hasReadme: true, hasCodeOfConduct: true,
    },
    issues: { avgCloseTimeHours: 168 },
    pullRequests: { avgMergeTimeHours: 120 },
    vulnerabilities: [
      { id: 'CVE-2020-11022', severity: 'MEDIUM', cvssScore: 6.1, epss: { score: 0.95 } },
      { id: 'CVE-2020-11023', severity: 'MEDIUM', cvssScore: 6.1, epss: { score: 0.92 } },
      { id: 'CVE-2019-11358', severity: 'MEDIUM', cvssScore: 6.1, epss: { score: 0.88 } },
      { id: 'CVE-2015-9251', severity: 'MEDIUM', cvssScore: 6.1, epss: { score: 0.72 } },
      { id: 'CVE-2012-6708', severity: 'MEDIUM', cvssScore: 6.1, epss: { score: 0.65 } },
    ],
    healthScore: { score: 68 },
  },

  // 5. Tiny abandoned single-maintainer project
  'Kkevsterrr/left-pad (abandoned)': {
    repository: {
      name: 'Kkevsterrr/left-pad', stars: 10, forks: 2, watchers: 1,
      openIssues: 5, license: null, // No license!
      archived: false, createdAt: '2016-03-23T00:00:00Z',
      pushedAt: new Date(Date.now() - 2500 * 86400000).toISOString(), // 7 years ago
    },
    contributors: { count: 1 },
    commits: { lastCommitDate: new Date(Date.now() - 2500 * 86400000).toISOString() },
    releases: [],
    community: {
      healthPercentage: 15, hasSecurityPolicy: false, hasContributing: false,
      hasReadme: true, hasCodeOfConduct: false,
    },
    issues: { avgCloseTimeHours: null },
    pullRequests: { avgMergeTimeHours: null },
    vulnerabilities: [],
    healthScore: { score: 12 },
  },

  // 6. Crypto mining tool (risky purpose)
  'nicehash/excavator (crypto miner)': {
    repository: {
      name: 'nicehash/excavator', stars: 500, forks: 120, watchers: 45,
      openIssues: 200, license: null,
      archived: false, createdAt: '2017-06-15T00:00:00Z',
      pushedAt: new Date(Date.now() - 300 * 86400000).toISOString(),
    },
    contributors: { count: 3 },
    commits: { lastCommitDate: new Date(Date.now() - 300 * 86400000).toISOString() },
    releases: [
      { publishedAt: new Date(Date.now() - 400 * 86400000).toISOString() },
    ],
    community: {
      healthPercentage: 25, hasSecurityPolicy: false, hasContributing: false,
      hasReadme: true, hasCodeOfConduct: false,
    },
    issues: { avgCloseTimeHours: 500 },
    pullRequests: { avgMergeTimeHours: null },
    vulnerabilities: [],
    healthScore: { score: 20 },
  },

  // 7. Security tool (wifiphisher) — hacking tool with vulns
  'wifiphisher/wifiphisher (hacking tool)': {
    repository: {
      name: 'wifiphisher/wifiphisher', stars: 13500, forks: 2600, watchers: 450,
      openIssues: 120, license: { key: 'gpl-3.0', name: 'GNU GPL v3' },
      archived: false, createdAt: '2015-01-15T00:00:00Z',
      pushedAt: new Date(Date.now() - 600 * 86400000).toISOString(),
    },
    contributors: { count: 15 },
    commits: { lastCommitDate: new Date(Date.now() - 600 * 86400000).toISOString() },
    releases: [
      { publishedAt: new Date(Date.now() - 900 * 86400000).toISOString() },
    ],
    community: {
      healthPercentage: 45, hasSecurityPolicy: false, hasContributing: true,
      hasReadme: true, hasCodeOfConduct: false,
    },
    issues: { avgCloseTimeHours: 360 },
    pullRequests: { avgMergeTimeHours: 200 },
    vulnerabilities: [
      { id: 'CVE-2023-5001', severity: 'CRITICAL', cvssScore: 9.8, epss: { score: 0.45 } },
      { id: 'CVE-2023-5002', severity: 'HIGH', cvssScore: 8.1, epss: { score: 0.22 } },
      { id: 'CVE-2023-5003', severity: 'HIGH', cvssScore: 7.5, epss: { score: 0.15 } },
      { id: 'CVE-2023-5004', severity: 'MEDIUM', cvssScore: 5.5 },
    ],
    healthScore: { score: 35 },
  },

  // 8. Known-malicious/vulnerable package
  'dangerous/insecure-pkg (critical vulns)': {
    repository: {
      name: 'dangerous/insecure-pkg', stars: 50, forks: 5, watchers: 2,
      openIssues: 30, license: null,
      archived: true, // Archived!
      createdAt: '2020-01-01T00:00:00Z',
      pushedAt: new Date(Date.now() - 1000 * 86400000).toISOString(),
    },
    contributors: { count: 1 },
    commits: { lastCommitDate: new Date(Date.now() - 1000 * 86400000).toISOString() },
    releases: [],
    community: {
      healthPercentage: 5, hasSecurityPolicy: false, hasContributing: false,
      hasReadme: false, hasCodeOfConduct: false,
    },
    issues: null,
    pullRequests: null,
    vulnerabilities: [
      { id: 'CVE-2024-9001', severity: 'CRITICAL', cvssScore: 10.0, epss: { score: 0.97 } },
      { id: 'CVE-2024-9002', severity: 'CRITICAL', cvssScore: 9.8, epss: { score: 0.85 } },
      { id: 'CVE-2024-9003', severity: 'HIGH', cvssScore: 8.5, epss: { score: 0.60 } },
      { id: 'CVE-2024-9004', severity: 'HIGH', cvssScore: 7.8, epss: { score: 0.30 } },
      { id: 'CVE-2024-9005', severity: 'MEDIUM', cvssScore: 6.5 },
      { id: 'CVE-2024-9006', severity: 'MEDIUM', cvssScore: 5.0 },
      { id: 'CVE-2024-9007', severity: 'LOW', cvssScore: 3.0 },
    ],
    healthScore: { score: 5 },
  },
};

// ============ RUN TESTS ============

console.log(`
${c.bold}${c.cyan}╔═══════════════════════════════════════════════════════════════════╗
║           OSTE Risk Scorer — Unit Test Results                  ║
╚═══════════════════════════════════════════════════════════════════╝${c.reset}
`);

// Header
console.log(`${c.bold}${'Repository'.padEnd(45)} ${'Score'.padStart(5)}  ${'Level'.padEnd(10)}  ${'Decision'.padEnd(24)}${c.reset}`);
console.log(`${'─'.repeat(90)}`);

const results = [];

for (const [name, data] of Object.entries(profiles)) {
  const result = scorer.scoreOpenSource(data);
  results.push({ name, ...result });
  
  const col = riskColor(result.riskLevel);
  console.log(
    `${name.padEnd(45)} ${col}${String(result.overallRiskScore).padStart(5)}${c.reset}  ${col}${result.riskLevel.padEnd(10)}${c.reset}  ${result.decision.padEnd(24)}`
  );
}

console.log(`${'─'.repeat(90)}`);
console.log();

// Detailed component breakdown for each
for (const r of results) {
  const data = profiles[r.name];
  const result = scorer.scoreOpenSource(data);
  
  console.log(`${c.bold}── ${r.name} ──${c.reset}`);
  for (const [key, comp] of Object.entries(result.components)) {
    const bar = '█'.repeat(Math.round(comp.score / 5)) + '░'.repeat(20 - Math.round(comp.score / 5));
    const col = comp.score >= 60 ? c.red : comp.score >= 40 ? c.yellow : comp.score >= 20 ? c.blue : c.green;
    console.log(`  ${comp.label.padEnd(30)} ${col}${String(comp.score).padStart(3)}${c.reset}/100  ${bar}  (${Math.round(comp.weight * 100)}%)`);
  }
  
  // Print recommendations
  if (result.recommendations?.length > 0) {
    console.log(`  ${c.dim}Recommendations:${c.reset}`);
    for (const rec of result.recommendations.slice(0, 3)) {
      const pCol = rec.priority === 'CRITICAL' ? c.red : rec.priority === 'HIGH' ? c.yellow : c.blue;
      console.log(`    ${pCol}[${rec.priority}]${c.reset} ${rec.action}`);
    }
  }
  console.log();
}

// ============ VALIDATION ============

console.log(`${c.bold}${c.cyan}═══════════════ VALIDATION ═══════════════${c.reset}`);
console.log();

const scores = results.map(r => ({ name: r.name, score: r.overallRiskScore, decision: r.decision }));

// Sort by score
scores.sort((a, b) => a.score - b.score);
console.log(`${c.bold}Ranking (safest → riskiest):${c.reset}`);
scores.forEach((s, i) => {
  const col = riskColor(results.find(r => r.name === s.name).riskLevel);
  console.log(`  ${i + 1}. ${col}${s.score}${c.reset} ${s.name} → ${s.decision}`);
});

console.log();

// Assertions
let passed = 0;
let failed = 0;

function assert(test, msg) {
  if (test) {
    console.log(`  ${c.green}✔${c.reset} ${msg}`);
    passed++;
  } else {
    console.log(`  ${c.red}✖ FAIL:${c.reset} ${msg}`);
    failed++;
  }
}

const s = (name) => results.find(r => r.name === name)?.overallRiskScore;
const d = (name) => results.find(r => r.name === name)?.decision;

console.log(`${c.bold}Assertions:${c.reset}`);
assert(s('facebook/react (healthy)') < 20, `React should be < 20 (got ${s('facebook/react (healthy)')})`);
assert(s('expressjs/express (solid)') < 30, `Express should be < 30 (got ${s('expressjs/express (solid)')})`);
assert(s('moment/moment (deprecated)') > s('expressjs/express (solid)'), `Moment should score higher (riskier) than Express`);
assert(s('Kkevsterrr/left-pad (abandoned)') > 45, `Left-pad should be > 45 (got ${s('Kkevsterrr/left-pad (abandoned)')})`);
assert(s('dangerous/insecure-pkg (critical vulns)') > 75, `Insecure-pkg should be > 75 (got ${s('dangerous/insecure-pkg (critical vulns)')})`);
assert(s('facebook/react (healthy)') < s('moment/moment (deprecated)'), `React should be less risky than Moment`);
assert(s('facebook/react (healthy)') < s('Kkevsterrr/left-pad (abandoned)'), `React should be less risky than Left-pad`);
assert(s('wifiphisher/wifiphisher (hacking tool)') > 40, `Wifiphisher should be > 40 (got ${s('wifiphisher/wifiphisher (hacking tool)')})`);
assert(d('facebook/react (healthy)') === 'APPROVE', `React should be APPROVE (got ${d('facebook/react (healthy)')})`);
assert(d('dangerous/insecure-pkg (critical vulns)') === 'REJECT' || d('dangerous/insecure-pkg (critical vulns)') === 'REVIEW_REQUIRED', 
  `Insecure-pkg should be REJECT or REVIEW_REQUIRED (got ${d('dangerous/insecure-pkg (critical vulns)')})`);

// Score spread
const allScores = results.map(r => r.overallRiskScore);
const spread = Math.max(...allScores) - Math.min(...allScores);
assert(spread >= 50, `Score spread should be >= 50 points (got ${spread}: ${Math.min(...allScores)} to ${Math.max(...allScores)})`);

// Unique scores (no identical scores for different profiles)
const uniqueScores = new Set(allScores);
assert(uniqueScores.size >= 5, `At least 5 unique scores expected (got ${uniqueScores.size}): [${allScores.join(', ')}]`);

// Freeware scoring assertions
const fwCleanSigned = scorer.scoreFreeware({
  virusTotal: { status: 'completed', malicious: 0, suspicious: 0, reputation: 50, signatureInfo: { verified: 'Signed', signers: '7-Zip' } },
  domainReputation: { status: 'completed', reputation: 20, malicious: 0, riskLevel: 'CLEAN' },
});
const fwMalwareHardGate = scorer.scoreFreeware({
  virusTotal: { status: 'completed', malicious: 58, suspicious: 0, reputation: 100, signatureInfo: { verified: 'Signed', signers: 'Forged' } },
});
const fwSingleFp = scorer.scoreFreeware({
  virusTotal: { status: 'completed', malicious: 1, suspicious: 0, reputation: 5 },
  domainReputation: { status: 'completed', reputation: 0, malicious: 1, riskLevel: 'MEDIUM' },
});
const fwUnknownHash = scorer.scoreFreeware({
  virusTotal: { status: 'not_found' },
  hybridAnalysis: { status: 'skipped' },
});

assert(fwCleanSigned.overallRiskScore <= 20 && fwCleanSigned.decision === 'APPROVE',
  `Clean signed freeware should be APPROVE <= 20 (got ${fwCleanSigned.overallRiskScore}, ${fwCleanSigned.decision})`);
assert(fwMalwareHardGate.overallRiskScore >= 85 && fwMalwareHardGate.decision === 'REJECT' && !!fwMalwareHardGate.hardGate,
  `Malware (>=10 engines) must trigger hardGate REJECT >= 85 (got ${fwMalwareHardGate.overallRiskScore}, ${fwMalwareHardGate.decision})`);
assert(fwSingleFp.overallRiskScore <= 35 && fwSingleFp.decision !== 'REJECT',
  `Single-engine false positive should not be REJECT/HIGH (got ${fwSingleFp.overallRiskScore}, ${fwSingleFp.decision})`);
assert(fwUnknownHash.decision === 'REVIEW_REQUIRED' && fwUnknownHash.insufficientData === true,
  `Unknown hash with no data must be REVIEW_REQUIRED with insufficientData=true (got ${fwUnknownHash.decision})`);

console.log();
console.log(`${c.bold}Results: ${c.green}${passed} passed${c.reset}, ${failed > 0 ? c.red : c.dim}${failed} failed${c.reset}`);
if (failed > 0) process.exit(1);

