# 🛡️ OSTE — Open Source Tool Evaluation (v1.1)

**Automated Security Risk Assessment Platform for Open Source Software & Freeware**

OSTE evaluates third-party open-source packages, GitHub repositories, downloadable binaries/installers, and file hashes (`MD5`, `SHA-1`, `SHA-256`) to produce a **deterministic security risk score (0–100)**, an **adoption decision**, an **AI-generated executive security narrative**, and **PDF + JSON reports** suitable for executive review or CI/CD gating.

---

## 🏗️ System Architecture & Analysis Flows

OSTE automatically classifies each input (`detectType` in `server/services/orchestrator.js`) and routes it to one of three flows:

| Input Pattern | Detected Flow | Examples |
|---|---|---|
| `owner/repo` or `https://github.com/owner/repo` | **Open Source Flow** | `facebook/react`, `https://github.com/pallets/flask` |
| Direct download URL (including GitHub Release assets `.../releases/download/...` and `raw.githubusercontent.com/...`) | **Freeware Flow (URL)** | `https://www.7-zip.org/a/7z2408-x64.exe`, `https://github.com/.../releases/download/.../tool.tar.gz` |
| 32-char (`MD5`), 40-char (`SHA-1`), or 64-char (`SHA-256`) hex string | **Freeware Flow (Hash)** | `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f` |
| Plain tool name | **Search Flow** | `prettier` (queries GitHub Search API for top-starred match; falls back to error if no repo/URL/hash is provided) |

### 1. Open Source Analysis Pipeline
```text
Input (Repo / URL)
  ├─► 1. GitHub Service (server/services/github.js)
  │     • Repo metadata, stars, forks, archive/fork status, license, releases, commits, contributors
  │     • Community health profile (README, SECURITY.md, CONTRIBUTING.md, Code of Conduct)
  │     • Raw manifest & lockfile fetching via raw.githubusercontent.com (zero REST quota cost)
  │     • Monorepo self-package lookup via npm registry when root package.json is private
  ├─► 2. OSV Vulnerability Scanner (server/services/osv.js)
  │     • Parses runtime dependencies (excludes devDependencies/test scopes)
  │     • Resolves unpinned npm & PyPI version ranges against registry.npmjs.org / pypi.org
  │     • Batch queries OSV.dev (/v1/querybatch) + hydrates full advisory records (/v1/vulns/:id)
  │     • Computes exact CVSS v3.0/v3.1 base scores from vector strings
  │     • Queries current & all-time historical advisories for the project's own published package
  ├─► 3. NVD Enrichment (server/services/nvd.js)
  │     • Enriches top CVEs via NIST NVD 2.0 API (official CVSS v3.1/v2 metrics, CWEs, exploitability)
  ├─► 4. EPSS Exploit Prediction (server/services/epss.js)
  │     • Queries FIRST.org EPSS API in chunked batches for 30-day exploitation probability
  ├─► 5. Deterministic Risk Scorer (server/services/scorer.js)
  │     • Computes weighted 0–100 risk score, confidence level, and adoption decision
  ├─► 6. Groq AI Security Analyst (server/services/groq.js)
  │     • Produces structured executive summary, posture analysis, and prioritized recommendations
  └─► 7. Report Generator (server/services/report.js)
        • Outputs PDF and JSON reports to reports/
```

#### Supported Dependency Manifests & Ecosystems
| Ecosystem | Supported Manifests / Lockfiles | Version Handling |
|---|---|---|
| **npm** | `package-lock.json` (v2/v3 & v1), `package.json` | Lockfile exact versions preferred; `package.json` semver ranges resolved against `registry.npmjs.org` |
| **PyPI** | `poetry.lock`, `Pipfile.lock`, `requirements.txt`, `pyproject.toml` | Lockfile exact versions preferred; `>=`/`~=` specs resolved against `pypi.org` |
| **Go** | `go.mod` | Module directives + own module path extraction |
| **Rust (crates.io)** | `Cargo.lock`, `Cargo.toml` | Exact `[[package]]` lock versions + crate name extraction |
| **RubyGems** | `Gemfile.lock` | Locked gem versions |
| **Packagist (PHP)** | `composer.lock` | Runtime `packages` (excludes `packages-dev`) |
| **Maven (Java)** | `pom.xml` | `<dependency>` coordinates (excludes `<scope>test</scope>`) |

---

### 2. Freeware / Binary Analysis Pipeline
```text
Input (Download URL / MD5 / SHA-1 / SHA-256)
  ├─► 1. VirusTotal Service (server/services/virustotal.js)
  │     • File hash lookup (/api/v3/files/:hash) — multi-engine detections, Authenticode signature verification, community reputation, sandbox tags
  │     • URL analysis (/api/v3/urls) — reuses recent (<7d) analysis reports before submitting a new scan
  │     • Domain reputation (/api/v3/domains/:domain) — WHOIS creation date, registrar, engine verdicts
  ├─► 2. Hybrid Analysis Service (server/services/hybrid.js)
  │     • CrowdStrike Falcon Sandbox behavioral lookup (/api/v2/search/hash & /search/terms)
  │     • Extracts threat score, MITRE ATT&CK tactics, dropped files, and network indicators
  ├─► 3. Deterministic Risk Scorer (server/services/scorer.js)
  │     • Computes weighted 0–100 risk score with missing-source weight renormalization & malware hard gates
  ├─► 4. Groq AI Security Analyst (server/services/groq.js)
  └─► 5. Report Generator (server/services/report.js)
```

---

## 🧮 Deterministic Risk Scoring Engine (`server/services/scorer.js`)

Higher scores indicate **higher risk** (`0` = safest, `100` = highest risk).
- **Authoritative Deterministic Score:** The deterministic scorer is always authoritative for `overallRiskScore`, `riskLevel`, and `decision` so results are reproducible and CI/CD-safe. The LLM's raw score is preserved under `aiAssessment.aiOriginal` for transparency.
- **Dynamic Weight Renormalization:** If a data source is unavailable (for example, Hybrid Analysis when `HYBRID_ANALYSIS_API_KEY` is not set, or vulnerability exposure on a repo with no dependency manifests and no published package), that component is marked `available: false`, excluded from the weighted average, and the remaining active components are renormalized (`effectiveWeight`).
- **Insufficient Data Safeguard:** If *all* components lack data (e.g., an unknown SHA-256 hash not present in VirusTotal or Hybrid Analysis), `insufficientData: true` is set, confidence drops to `0% (LOW)`, and the decision is forced to `REVIEW_REQUIRED`.

### Open Source Component Weights
| Component | Base Weight | Signals Evaluated |
|---|---|---|
| **Vulnerability Exposure** | **30%** | Diminishing-returns curve `100 × (1 - exp(-points / 60))` over runtime CVEs (`CRITICAL×30 + HIGH×18 + MEDIUM×8 + LOW×2`) plus historical advisory track record of the project's own package |
| **Exploit Likelihood (EPSS)** | **20%** | Maximum EPSS (35%), average EPSS (25%), count of CVEs with EPSS ≥ 10% (+8 pts each) and EPSS ≥ 50% (+15 pts each) |
| **Project Health** | **20%** | Stars, contributor count (bus factor), forks, `SECURITY.md`, `CONTRIBUTING.md`, `README`, community health %, open-issues-to-stars ratio, archived/disabled status (archived = 95/100; archived/disabled repos are also floored at overall score ≥ 45 `APPROVE_WITH_CONDITIONS`) |
| **Maintenance Activity** | **15%** | Days since last commit, days since latest release, release count, issue close time & PR merge time (when `GITHUB_TOKEN` is set) |
| **License Compliance** | **15%** | Permissive (`MIT`, `Apache-2.0`, `BSD`, `ISC` → 5), weak copyleft (`MPL-2.0`, `EPL-2.0` → 25), strong copyleft (`GPL`, `AGPL`, `LGPL` → 45), unknown/custom (`other`/`noassertion` → 55), no license (→ 70) |

### Freeware Component Weights & Hard Gates
| Component | Base Weight | Signals Evaluated |
|---|---|---|
| **Malware Detection** | **40%** | VirusTotal malicious engine count (`≥10` → 100, `5–9` → 85, `3–4` → 65, `2` → 35, `1` → 20 to tolerate single-engine false positives, `0` → 5) |
| **Behavioral Analysis** | **30%** | Hybrid Analysis Falcon Sandbox `threatScore` (0–100); automatically excluded & renormalized when unconfigured or not found |
| **Publisher Reputation** | **20%** | Verified Authenticode signature (`verified === "Signed"` and `<3` malicious flags → -20 risk; forged/unverified signature → +5 risk), VirusTotal community reputation score, and hosting domain reputation |
| **Distribution Safety** | **10%** | Hosting domain VirusTotal risk level (`CLEAN` → 5, `LOW` → 25, `MEDIUM` → 50, `HIGH` → 80, `CRITICAL` → 100) |
| **Malware Hard Gate** | **Override** | Any sample flagged as malicious by **≥ 10 antivirus engines** has its overall risk score floored at **≥ 85 (`CRITICAL` / `REJECT`)**, regardless of forged digital signatures or positive community votes |

### Decision Matrix
| Score Range | Risk Level | Decision | Meaning |
|---|---|---|---|
| **0 – 19** | `MINIMAL` | `APPROVE` | Safe for adoption with standard practices |
| **20 – 34** | `LOW` | `APPROVE` | Low risk; routine monitoring recommended |
| **35 – 59** | `MEDIUM` | `APPROVE_WITH_CONDITIONS` | Adopt only after addressing noted vulnerabilities, license terms, or maintenance gaps |
| **60 – 79** | `HIGH` | `REVIEW_REQUIRED` | Manual security review required before any use |
| **80 – 100** | `CRITICAL` | `REJECT` | Severe vulnerability exposure or confirmed malware — do not adopt |

---

## ⏱️ Free-Tier Rate Limiting & Caching (`server/services/util.js`)

OSTE is engineered to run reliably on **free-tier API keys** (and even without `GITHUB_TOKEN` or `NVD_API_KEY`):

| Service | Free-Tier Limit | OSTE Rate-Limit & Caching Strategy |
|---|---|---|
| **GitHub REST API** | 60 req/hr (unauth) / 5,000 req/hr (token) | Uses only ~6 REST calls per repo in unauthenticated mode; reads all dependency manifests via `raw.githubusercontent.com` (0 API quota); caches responses in `.cache/` for 6h; tracks core rate-limit headers separately from search headers |
| **OSV.dev API** | Public / unauthenticated | Batch queries `/v1/querybatch`, hydrates up to 300 advisories with 8x concurrency, caches advisory records for 24h |
| **NIST NVD 2.0 API** | 5 req / 30s (no key) / 50 req / 30s (key) | Serial `RateLimiter` enforces a **6.5s gap** (no key) or **0.7s gap** (with key), retries on 403/429/503, caches CVEs for 24h |
| **FIRST.org EPSS** | Public / unauthenticated | Chunks CVE lists into batches of 40 to prevent URL length errors; caches for 12h |
| **VirusTotal API v3** | 4 req/min, 500 req/day (free key) | Serial `RateLimiter` enforces a **15.5s gap** between requests; checks `/urls/:id` to reuse existing reports (<7 days old) before submitting new URL scans; caches for 24h |
| **Groq Cloud LLM** | 8,000 tokens/min, 1,000 req/day (free tier) | Compacts prompts to ~1k–1.5k tokens; sliding-window token budget (`7,000 TPM`) pauses before hitting 429; automatic model failover (`openai/gpt-oss-120b` → `openai/gpt-oss-20b` → `qwen/qwen3.8-27b`); deterministic rule-based fallback if all models fail |

- Set `OSTE_NO_CACHE=1` to bypass the `.cache/` disk cache at any time.
- Expired cache files (>7 days old) are automatically pruned on server startup.

---

## 🚀 Quick Start & Usage

### 1. Install Dependencies
```bash
npm install
```

### 2. Configure `.env`
```bash
cp .env.example .env
```

| Environment Variable | Required? | Purpose |
|---|---|---|
| `GROQ_API_KEY` | Recommended | AI executive narrative & recommendations (falls back to rule-based summary if omitted) |
| `VIRUSTOTAL_API_KEY` | Required for Freeware | File hash, URL, and domain reputation scanning |
| `GITHUB_TOKEN` | Optional | Raises GitHub limit from 60/hr to 5,000/hr and enables issue/PR turnaround metrics |
| `NVD_API_KEY` | Optional | Raises NVD limit from 5 req/30s to 50 req/30s |
| `HYBRID_ANALYSIS_API_KEY` | Optional | Enables Falcon Sandbox behavioral scoring for freeware |
| `GROQ_MODEL` | Optional | Override primary Groq model (default: `openai/gpt-oss-120b`) |
| `PORT` | Optional | Web server port (default: `3000`) |

### 3. Run the Web UI & Server
```bash
npm run dev
# Open http://localhost:3000
```

### 4. Command-Line Interface (`cli/oste.js`)
```bash
# Analyze an open-source repository (shorthand or full GitHub URL)
node cli/oste.js analyze expressjs/express
node cli/oste.js analyze https://github.com/pallets/flask

# Analyze a file hash (MD5, SHA-1, or SHA-256)
node cli/oste.js analyze 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f

# Analyze a download URL
node cli/oste.js analyze https://www.7-zip.org/a/7z2408-x64.exe --type freeware

# CI/CD Gate: output raw JSON, skip PDF generation, and exit with code 2 if score > 35
node cli/oste.js analyze OWASP/NodeGoat --no-report --fail-above 35 --json

# Check configured API keys
node cli/oste.js config

# Run the live end-to-end test suite (or filter by test IDs)
node cli/oste.js test
node cli/oste.js test "1|10|20|24"
```

---

## 📡 REST API Reference

| Method & Endpoint | Description |
|---|---|
| `POST /api/analyze` | Start an analysis job. Body: `{ "input": "<repo|url|hash|name>", "type": "opensource" \| "freeware" }` (omit `type` for auto-detection). Enforces input validation and a concurrency cap (`OSTE_MAX_CONCURRENT`, default `3`). |
| `GET /api/jobs/:jobId` | Poll job progress (`status`, `progress`, `currentStep`, `steps`) and final `result`. |
| `GET /api/jobs/:jobId/report/pdf` | Download the generated executive PDF report. |
| `GET /api/jobs/:jobId/report/json` | Download the full machine-readable JSON report. |
| `GET /api/jobs` | List the 50 most recent jobs (in-memory store bounded to 200 jobs / 24h TTL). |
| `GET /api/config/status` | Check boolean configuration status of all 5 external API integrations. |

---

## 🧪 Testing & Benchmark Results (30 Live E2E Cases + 16 Unit Tests)

- **Unit Tests (`npm test` / `node test-scorer.js`):** 16/16 assertions verifying open-source and freeware scoring math, relative risk ordering, single-engine false-positive tolerance, unknown-hash `REVIEW_REQUIRED` handling, and malware hard gates.
- **Live End-to-End Suite (`npm run test:e2e` / `node tests/e2e.js`):** 30/30 real-world test cases across npm, PyPI, Go, Rust, monorepos, archived/abandoned packages, offensive security tools, ransomware/wiper hashes (WannaCry, NotPetya), EICAR payloads (`SHA-256`, `SHA-1`, `MD5`, `.zip`), clean signed/unsigned Windows binaries (PuTTY, 7-Zip), GitHub release tarballs, malicious URLs (WICAR), search resolution, and error handling. Full output is saved in `reports/e2e-results.json`.

| # | Category | Target | Score | Level | Decision |
|---|---|---|---|---|---|
| 1 | Open Source (npm) | `expressjs/express` | 4 | `MINIMAL` | `APPROVE` |
| 2 | Open Source (npm) | `lodash/lodash` | 18 | `MINIMAL` | `APPROVE` |
| 3 | Open Source (npm) | `moment/moment` | 7 | `MINIMAL` | `APPROVE` |
| 4 | Open Source (URL) | `https://github.com/jquery/jquery` | 6 | `MINIMAL` | `APPROVE` |
| 5 | Open Source (PyPI) | `pallets/flask` | 7 | `MINIMAL` | `APPROVE` |
| 6 | Open Source (Go) | `gin-gonic/gin` | 35 | `MEDIUM` | `APPROVE_WITH_CONDITIONS` |
| 7 | Open Source (Rust) | `BurntSushi/ripgrep` | 5 | `MINIMAL` | `APPROVE` |
| 8 | Vulnerable App | `OWASP/NodeGoat` | 63 | `HIGH` | `REVIEW_REQUIRED` |
| 9 | Offensive Security | `wifiphisher/wifiphisher` | 40 | `MEDIUM` | `APPROVE_WITH_CONDITIONS` |
| 10 | Malware Hash (SHA-256) | EICAR (`275a021b...`) | 83 | `CRITICAL` | `REJECT` |
| 11 | Malware Hash (SHA-256) | WannaCry (`24d004a1...`) | 92 | `CRITICAL` | `REJECT` |
| 12 | Benign Hash (SHA-256) | Empty File (`e3b0c442...`) | 20 | `LOW` | `APPROVE` |
| 13 | Malware Hash (MD5) | EICAR MD5 (`44d88612...`) | 83 | `CRITICAL` | `REJECT` |
| 14 | Unknown Hash | Unseen SHA-256 (`a3f5c8d1...`) | 50 | `MEDIUM` | `REVIEW_REQUIRED` (Low Confidence) |
| 15 | Legitimate Installer URL | `https://www.7-zip.org/a/7z2408-x64.exe` | 34 | `LOW` | `APPROVE` |
| 16 | Malicious Exploit URL | `http://malware.wicar.org/...` | 100 | `CRITICAL` | `REJECT` |
| 17 | Tool Name Search | `prettier` → `prettier/prettier` | 13 | `MINIMAL` | `APPROVE` |
| 18 | Invalid Repo (404) | `this-owner-does-not-exist-zz9/nope-repo-xx` | — | Error | Clean 404 Error |
| 19 | Invalid Freeware Name | `zzqqxx_nonexistent_tool_998877` | — | Error | Clean Input Error |
| 20 | Monorepo Self-Lookup | `facebook/react` | 5 | `MINIMAL` | `APPROVE` |
| 21 | Archived Package | `request/request` | 39 | `MEDIUM` | `APPROVE_WITH_CONDITIONS` |
| 22 | Archived Tiny Package | `left-pad/left-pad` | 45 | `MEDIUM` | `APPROVE_WITH_CONDITIONS` |
| 23 | GPL Security Tool | `sqlmapproject/sqlmap` | 24 | `LOW` | `APPROVE` |
| 24 | Forged Signature Wiper | NotPetya (`027cc450...`) | 92 | `CRITICAL` | `REJECT` |
| 25 | Ransomware Dropper | WannaCry Dropper (`ed01ebfb...`) | 92 | `CRITICAL` | `REJECT` |
| 26 | Malware Hash (SHA-1) | EICAR SHA-1 (`3395856c...`) | 85 | `CRITICAL` | `REJECT` |
| 27 | Malware Archive Hash | EICAR ZIP (`2546dcff...`) | 85 | `CRITICAL` | `REJECT` |
| 28 | Clean Binary Hash | Official PuTTY x64 (`d01fdb5a...`) | 20 | `LOW` | `APPROVE` |
| 29 | Clean Installer Hash | Official 7-Zip x64 (`67cb9d34...`) | 18 | `MINIMAL` | `APPROVE` |
| 30 | Release Binary URL | `github.com/BurntSushi/ripgrep/releases/download/...` | 14 | `MINIMAL` | `APPROVE` (`freeware` flow) |

---

## 📁 Project Structure

```text
oste-project/
├── server/
│   ├── index.js                 # Express HTTP server, REST API routes, validation & error middleware
│   └── services/
│       ├── orchestrator.js      # Pipeline router, job store with TTL eviction, AI/scorer reconciliation
│       ├── github.js            # GitHub API client, raw manifest fetcher, lockfile parsers, health score
│       ├── osv.js               # OSV.dev batch scanner, advisory hydration, CVSS v3 math, range resolver
│       ├── nvd.js               # NIST NVD 2.0 CVE enrichment with rate limiting & disk cache
│       ├── epss.js              # FIRST.org EPSS exploit probability client (chunked + cached)
│       ├── virustotal.js        # VirusTotal v3 URL, domain & file hash scanner with report reuse
│       ├── hybrid.js            # Hybrid Analysis Falcon Sandbox v2 client
│       ├── groq.js              # Groq LLM client with 8k-TPM budget, model failover & rule fallback
│       ├── scorer.js            # Deterministic risk scoring engine (v2) with weight renormalization
│       ├── report.js            # PDFKit PDF & JSON report generator
│       └── util.js              # Shared SHA-1 disk cache (.cache/), RateLimiter, and withRetry helpers
├── public/
│   ├── index.html               # Web dashboard UI
│   ├── css/style.css            # Styling & responsive layout
│   └── js/app.js                # Frontend state, polling, gauge & breakdown rendering
├── cli/
│   └── oste.js                  # Commander.js CLI (analyze, test, config) with --fail-above CI gate
├── tests/
│   └── e2e.js                   # 30-case live end-to-end test suite
├── test-scorer.js               # 16-assertion deterministic scorer unit test suite
├── test-repos.sh                # Sequential multi-repository shell test script
├── reports/                     # Generated PDF/JSON reports and e2e-results.json
├── .env.example                 # Environment variable template
└── package.json
```

---

## 📜 License

MIT
