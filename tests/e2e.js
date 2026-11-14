/**
 * OSTE end-to-end test suite (real APIs). Paced for free-tier limits:
 *   GitHub anon 60 req/h, NVD 5 req/30s, VirusTotal 4 req/min, Groq 8k tokens/min.
 * Usage: node tests/e2e.js [filter]      (results -> reports/e2e-results.json)
 */
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const fs = require('fs');
const path = require('path');
const Orchestrator = require('../server/services/orchestrator');

const CASES = [
  // ---- open source: healthy / mature ----
  { id: 1, name: 'Healthy mature framework', input: 'expressjs/express', expect: { status: 'completed', max: 34 } },
  { id: 2, name: 'Popular lib w/ historical CVEs (lodash)', input: 'lodash/lodash', expect: { status: 'completed', min: 5, max: 59 } },
  { id: 3, name: 'Maintenance-mode lib (moment)', input: 'moment/moment', expect: { status: 'completed', min: 5, max: 69 } },
  { id: 4, name: 'Legacy lib w/ many advisories (jquery, URL input)', input: 'https://github.com/jquery/jquery', expect: { status: 'completed', min: 5, max: 59 } },
  { id: 5, name: 'Python project, PyPI ecosystem (flask)', input: 'pallets/flask', expect: { status: 'completed', max: 39 } },
  { id: 6, name: 'Go module project (gin)', input: 'gin-gonic/gin', expect: { status: 'completed', max: 39 } },
  { id: 7, name: 'Rust project w/ Cargo.lock (ripgrep)', input: 'BurntSushi/ripgrep', expect: { status: 'completed', max: 39 } },
  { id: 8, name: 'Deliberately vulnerable app (OWASP NodeGoat)', input: 'OWASP/NodeGoat', expect: { status: 'completed', min: 40 } },
  { id: 9, name: 'Offensive security tool (wifiphisher)', input: 'wifiphisher/wifiphisher', expect: { status: 'completed', min: 20 } },
  // ---- freeware: hashes ----
  { id: 10, name: 'EICAR test file SHA-256 (must be flagged)', input: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', expect: { status: 'completed', min: 60 } },
  { id: 11, name: 'WannaCry ransomware SHA-256 (must be flagged)', input: '24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c', expect: { status: 'completed', min: 60 } },
  { id: 12, name: 'Empty file SHA-256 (benign)', input: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', expect: { status: 'completed', max: 34 } },
  { id: 13, name: 'EICAR MD5 (hash type detection)', input: '44d88612fea8a8f36de82e1278abb02f', expect: { status: 'completed', min: 60 } },
  { id: 14, name: 'Unknown hash (not in VirusTotal)', input: 'a3f5c8d1e9b2740615fa8c3d7e1b9042c6d8f1a3e5b79c0d2f4a6b8c1e3d5f70', expect: { status: 'completed', lowConfidence: true } },
  // ---- freeware: URLs ----
  { id: 15, name: 'Legit installer URL (7-Zip)', input: 'https://www.7-zip.org/a/7z2408-x64.exe', type: 'freeware', expect: { status: 'completed', max: 49 } },
  { id: 16, name: 'Known-malicious test URL (WICAR)', input: 'http://malware.wicar.org/data/ms14_064_ole_not_xp.html', type: 'freeware', expect: { status: 'completed', min: 35 } },
  // ---- search flow + error handling ----
  { id: 17, name: 'Name search flow (resolves via GitHub search)', input: 'prettier', expect: { status: 'completed', max: 49 } },
  { id: 18, name: 'Nonexistent repo -> clean 404 error', input: 'this-owner-does-not-exist-zz9/nope-repo-xx', type: 'opensource', expect: { status: 'failed', error: /not found/i } },
  { id: 19, name: 'Garbage name -> clear error, no crash', input: 'zzqqxx_nonexistent_tool_998877', type: 'freeware', expect: { status: 'failed', error: /No GitHub repository found|provide a download URL/i } },
  // ---- extended open source cases ----
  { id: 20, name: 'Monorepo w/ registry self-package lookup (react)', input: 'facebook/react', expect: { status: 'completed', max: 34 } },
  { id: 21, name: 'Officially archived/deprecated npm package (request)', input: 'request/request', expect: { status: 'completed', min: 35 } },
  { id: 22, name: 'Abandoned archived package (left-pad/left-pad)', input: 'left-pad/left-pad', expect: { status: 'completed', min: 35 } },
  { id: 23, name: 'GPL-licensed offensive security tool (sqlmap)', input: 'sqlmapproject/sqlmap', expect: { status: 'completed', min: 10, max: 65 } },
  // ---- extended freeware hashes & release binary URL ----
  { id: 24, name: 'NotPetya wiper SHA-256 (forged MS signature)', input: '027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745', expect: { status: 'completed', min: 80 } },
  { id: 25, name: 'WannaCry dropper SHA-256 (empty signatureInfo)', input: 'ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa', expect: { status: 'completed', min: 80 } },
  { id: 26, name: 'EICAR test file SHA-1 (40-char hash + hardGate)', input: '3395856ce81f2b7382dee72602f798b642f14140', expect: { status: 'completed', min: 80 } },
  { id: 27, name: 'EICAR ZIP archive SHA-256 (compressed payload)', input: '2546dcffc5ad854d4ddc64fbf056871cd5a00f2471cb7a5bfd4ac23b6e9eedad', expect: { status: 'completed', min: 80 } },
  { id: 28, name: 'Legitimate PuTTY x64 binary SHA-256 (clean)', input: 'd01fdb5aae8f112526040a39b0bfb9e27d813003178645e65f8d1cfdb2a26c87', expect: { status: 'completed', max: 34 } },
  { id: 29, name: 'Legitimate 7-Zip installer SHA-256 (clean, high rep)', input: '67cb9d3452c9dd974b04f4a5fd842dbcba8184f2344ff72e3662d7cdb68b099b', expect: { status: 'completed', max: 25 } },
  { id: 30, name: 'GitHub release binary URL routed to freeware flow', input: 'https://github.com/BurntSushi/ripgrep/releases/download/14.1.1/ripgrep-14.1.1-x86_64-unknown-linux-musl.tar.gz', expect: { status: 'completed', resolvedType: 'freeware', max: 49 } },
];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function run(o, c) {
  const t0 = Date.now();
  const { jobId } = await o.startAnalysis(c.input, { type: c.type });
  let job;
  for (;;) {
    job = o.getJob(jobId);
    if (job.status !== 'running') break;
    if (Date.now() - t0 > 600000) { job.status = 'timeout'; break; }
    await sleep(500);
  }
  const secs = Math.round((Date.now() - t0) / 1000);
  const res = { id: c.id, name: c.name, input: c.input, status: job.status, seconds: secs, error: job.error || null, steps: job.steps.map((s) => `${s.name}:${s.status}`) };
  const ok = [];
  const fail = [];
  const e = c.expect;
  if (job.status === e.status) ok.push(`status=${job.status}`); else fail.push(`status ${job.status} != ${e.status}`);
  if (e.error) (e.error.test(job.error || '') ? ok : fail).push(`error~${e.error} (${job.error})`);
  if (job.result) {
    const r = job.result;
    const rs = r.riskScore;
    res.score = rs.overallRiskScore; res.level = rs.riskLevel; res.decision = rs.decision; res.confidence = rs.confidenceLevel;
    res.components = Object.fromEntries(Object.entries(rs.components).map(([k, v]) => [k, v.available === false ? 'n/a' : v.score]));
    res.resolvedType = r.type;
    res.vulns = r.data.vulnerabilitySummary ? { total: r.data.vulnerabilitySummary.total, C: r.data.vulnerabilitySummary.CRITICAL, H: r.data.vulnerabilitySummary.HIGH, M: r.data.vulnerabilitySummary.MEDIUM, L: r.data.vulnerabilitySummary.LOW, pkgs: r.data.vulnerabilitySummary.totalPackages } : undefined;
    res.selfAdvisories = r.data.selfAdvisories ? { pkg: r.data.selfAdvisories.package, current: r.data.selfAdvisories.current?.length, historical: r.data.selfAdvisories.historicalCount } : undefined;
    res.vt = r.data.virusTotal ? { status: r.data.virusTotal.status, malicious: r.data.virusTotal.malicious, suspicious: r.data.virusTotal.suspicious, source: r.data.virusTotal.source } : undefined;
    res.ai = { source: r.aiAssessment._meta?.source, model: r.aiAssessment._meta?.model, tokens: r.aiAssessment._meta?.usage?.total_tokens, reason: r.aiAssessment._meta?.reason };
    res.summary = r.aiAssessment.executiveSummary;
    res.reports = r.reports;
    if (e.min !== undefined) (rs.overallRiskScore >= e.min ? ok : fail).push(`score ${rs.overallRiskScore} >= ${e.min}`);
    if (e.max !== undefined) (rs.overallRiskScore <= e.max ? ok : fail).push(`score ${rs.overallRiskScore} <= ${e.max}`);
    if (e.resolvedType) (r.type === e.resolvedType ? ok : fail).push(`resolvedType ${r.type} == ${e.resolvedType}`);
    if (e.lowConfidence) (rs.confidenceLevel.level !== 'HIGH' ? ok : fail).push(`confidence ${rs.confidenceLevel.level} is not HIGH`);
    (r.aiAssessment._meta?.source === 'llm' ? ok : fail).push(`AI source=${r.aiAssessment._meta?.source}`);
    for (const f of [r.reports?.jsonPath, r.reports?.pdfPath]) {
      (f && fs.existsSync(f) && fs.statSync(f).size > 500 ? ok : fail).push(`report file ${f ? path.basename(f) : 'missing'}`);
    }
  }
  res.pass = fail.length === 0;
  res.ok = ok; res.fail = fail;
  return res;
}

(async () => {
  const filter = process.argv[2];
  const o = new Orchestrator({
    githubToken: process.env.GITHUB_TOKEN, nvdApiKey: process.env.NVD_API_KEY,
    virusTotalApiKey: process.env.VIRUSTOTAL_API_KEY, hybridAnalysisApiKey: process.env.HYBRID_ANALYSIS_API_KEY,
    groqApiKey: process.env.GROQ_API_KEY,
  });
  const out = path.join(__dirname, '..', 'reports', 'e2e-results.json');
  let results = [];
  try { results = JSON.parse(fs.readFileSync(out, 'utf8')); } catch { /* fresh */ }
  for (const c of CASES) {
    if (filter && !String(c.id).match(new RegExp(`^(${filter})$`))) continue;
    process.stdout.write(`#${c.id} ${c.name} [${c.input.slice(0, 50)}] ... `);
    let r;
    try { r = await run(o, c); } catch (err) { r = { id: c.id, name: c.name, pass: false, fail: ['harness exception: ' + err.stack] }; }
    console.log(`${r.pass ? 'PASS' : 'FAIL'} ${r.seconds}s score=${r.score ?? '-'} ${r.decision ?? ''} ${r.error ? '| ' + r.error.slice(0, 100) : ''}`);
    if (!r.pass) console.log('    ' + r.fail.join('\n    '));
    results = results.filter((x) => x.id !== c.id).concat(r).sort((a, b) => a.id - b.id);
    fs.writeFileSync(out, JSON.stringify(results, null, 2));
  }
  const passed = results.filter((r) => r.pass).length;
  console.log(`\n${passed}/${results.length} passed`);
})();
