# OSTE (Open Source Tool Evaluation) — Agent Context & Project Rules

This file is automatically loaded by Antigravity (and other coding agents) to provide complete architectural context, invariants, rate-limit constraints, and testing workflows for **OSTE v1.1**.

## 1. Project Overview

**OSTE** (`Oste-project`, `/home/spirit/Desktop/oste-project`) is a Node.js/Express application, CLI (`cli/oste.js`), and web UI (`public/`) that performs automated security risk assessments on open-source repositories and freeware (download URLs or file hashes `MD5` / `SHA-1` / `SHA-256`).

### Directory Layout
- `server/index.js` — Express HTTP server, REST API endpoints (`/api/analyze`, `/api/jobs/:jobId`, `/api/jobs/:jobId/report/:format`, `/api/jobs`, `/api/config/status`), input validation, concurrency cap (`MAX_CONCURRENT_JOBS = 3`), JSON error middleware, and startup cache pruning.
- `server/services/orchestrator.js` — `AnalysisOrchestrator`: input classification (`detectType`), job store (`MAX_JOBS = 200`, `24h` TTL eviction), pipeline orchestration (`_runOpenSourceFlow`, `_runFreewareFlow`, `_runSearchFlow`), and deterministic-vs-AI score reconciliation (`_reconcileAI`).
- `server/services/github.js` — `GitHubService`: repository metadata, contributors, releases, commits, community health profile (`/community/profile`), raw manifest fetching via `raw.githubusercontent.com` (zero REST API quota cost), lockfile/manifest parsers (`package-lock.json`, `package.json`, `poetry.lock`, `Pipfile.lock`, `requirements.txt`, `go.mod`, `Cargo.lock`, `Gemfile.lock`, `composer.lock`, `pom.xml`, `pyproject.toml`, `Cargo.toml`), and monorepo self-package lookup (`_npmPackageForRepo`).
- `server/services/osv.js` — `OSVService`: batch dependency scanning (`/v1/querybatch`), full vulnerability hydration (`/v1/vulns/:id`, up to 300 advisories with 8x concurrency), exact CVSS v3.0/v3.1 base-score calculation (`_parseCVSSScore`), npm & PyPI version range resolution (`_resolveNpmRange`, `_resolvePypiSpec`), and self-package advisory lookup (`analyzeSelf`).
- `server/services/nvd.js` — `NVDService`: NIST NVD 2.0 CVE enrichment (`/rest/json/cves/2.0`), serial rate limiter (`6.5s` gap without key, `0.7s` with key), 24h disk cache.
- `server/services/epss.js` — `EPSSService`: FIRST.org EPSS exploit probability batch lookup (chunked in groups of 40 CVEs), 12h disk cache.
- `server/services/virustotal.js` — `VirusTotalService`: VirusTotal API v3 hash lookup (`/files/:hash`), URL analysis (`/urls` with `<7d` existing report reuse via `/urls/:id`), and domain reputation (`/domains/:domain`), paced at `15.5s` between calls (`4 req/min` free tier) with 24h disk cache.
- `server/services/hybrid.js` — `HybridAnalysisService`: CrowdStrike Falcon Sandbox API v2 (`GET /search/hash` with `POST` fallback, `/search/terms`).
- `server/services/scorer.js` — `ScorerService`: deterministic risk scoring engine (0–100, higher = riskier) for both open-source and freeware flows, dynamic weight renormalization over available components, archived-repo floor, and malware hard gate.
- `server/services/groq.js` — `GroqService`: Groq LLM client with compacted prompts (~1k–1.5k tokens), sliding-window token budget (`7,000 TPM` to stay under the `8,000 TPM` free-tier cap), automatic model failover (`openai/gpt-oss-120b` → `openai/gpt-oss-20b` → `qwen/qwen3.8-27b`), and rule-based fallback (`_fallbackAssessment`).
- `server/services/report.js` — `ReportGenerator`: generates executive PDF (`pdfkit`) and machine-readable JSON reports in `reports/`.
- `server/services/util.js` — Shared SHA-1 persistent disk cache (`.cache/`), `pruneCache()`, serial `RateLimiter`, and exponential backoff `withRetry()`.
- `public/` — Vanilla HTML/CSS/JS single-page dashboard (`index.html`, `css/style.css`, `js/app.js`).
- `cli/oste.js` — Commander.js CLI (`analyze`, `test`, `config`) with `--type`, `--json`, `--no-report`, and `--fail-above <score>` CI gate (exits with code `2` when risk score exceeds threshold).
- `test-scorer.js` — Fast offline unit test suite for `ScorerService` (16 assertions, `npm test`).
- `tests/e2e.js` — 30-case live end-to-end test suite (`npm run test:e2e`, writes `reports/e2e-results.json`).
- `test-repos.sh` — Sequential multi-repository shell test script against `http://localhost:3000`.

---

## 2. Critical Architectural Invariants (Do Not Break)

1. **Deterministic Score Authority (`_reconcileAI` in `orchestrator.js`):**
   - `ScorerService` is always authoritative for `overallRiskScore`, `riskLevel`, and `decision`.
   - `GroqService` provides the executive narrative and qualitative recommendations; its raw score is stored under `aiAssessment.aiOriginal`. Never let non-deterministic LLM numbers override `riskScore`.
2. **Missing-Source Weight Renormalization (`_aggregate` in `scorer.js`):**
   - Components without data (`available: false`, such as Hybrid Analysis when `HYBRID_ANALYSIS_API_KEY` is unset, or vulnerability exposure on a repo with no manifests and no published package) must be excluded from the weighted mean and the remaining weights renormalized (`effectiveWeight`).
   - Never revert to scoring missing data as a flat `50/100`.
   - When *all* freeware components are unavailable (`insufficientData: true`, e.g., an unknown file hash not in VirusTotal), the decision must be forced to `REVIEW_REQUIRED` with `LOW` confidence.
3. **Hard Gates & Safety Floors (`scorer.js`):**
   - **Malware Hard Gate (`scoreFreeware`):** Any sample with `virusTotal.malicious >= 10` is floored at `overallRiskScore >= 85` (`CRITICAL` / `REJECT`), regardless of forged digital signatures or positive VirusTotal community votes.
   - **Digital Signature Verification (`_scoreReputation`):** Only a verified signature (`/^signed$/i.test(sig.verified)`) on a file with `< 3` malicious flags reduces risk (`-20`). Unverified/forged signatures (`+5`) or empty `signatureInfo: {}` objects must never reduce risk.
   - **Single-Engine False Positive Tolerance (`_scoreMalware`):** `1` malicious engine flag scores `20` (and `1–2` domain flags add `+5`), preventing legitimate installers (like 7-Zip) from being rejected due to a single noisy scanner.
   - **Archived Repository Floor (`scoreOpenSource`):** Repositories with `archived: true` or `disabled: true` are floored at `overallRiskScore >= 45` (`MEDIUM` / `APPROVE_WITH_CONDITIONS`).
4. **Input Classification (`detectType` in `orchestrator.js`):**
   - Direct binary download URLs on GitHub (`github.com/.../releases/download/...`, `objects.githubusercontent.com/...`, `raw.githubusercontent.com/...`, or GitHub URLs ending in binary extensions like `.exe`, `.tar.gz`, `.zip`) must route to `freeware`, **not** `opensource`.
   - Hashes must match exact hex lengths: `32` (`MD5`), `40` (`SHA-1`), or `64` (`SHA-256`).
5. **Decision Thresholds (`scorer.js`, `report.js`, `public/js/app.js`):**
   - `0–19`: `MINIMAL` (`APPROVE`)
   - `20–34`: `LOW` (`APPROVE`)
   - `35–59`: `MEDIUM` (`APPROVE_WITH_CONDITIONS`)
   - `60–79`: `HIGH` (`REVIEW_REQUIRED`)
   - `80–100`: `CRITICAL` (`REJECT`)

---

## 3. API Keys & Free-Tier Rate-Limit Rules

- **Never read or print the contents of `.env` in plain text** (use `node cli/oste.js config` or check key presence without printing secret values).
- **Currently configured keys in `.env`:** `GROQ_API_KEY` and `VIRUSTOTAL_API_KEY` are set; `GITHUB_TOKEN`, `NVD_API_KEY`, and `HYBRID_ANALYSIS_API_KEY` are empty (operating in free/unauthenticated mode).
- **Rate Limits to Respect When Testing:**
  - **GitHub (unauthenticated):** `60 requests/hour` per IP (~6 calls per uncached repo). Manifests are fetched via `raw.githubusercontent.com` (free). Separate `x-ratelimit-resource: search` from `core` in `github.js`.
  - **NIST NVD (no key):** `5 requests / 30 seconds` (`RateLimiter(6500)` in `nvd.js`). Only top 8 CVEs per repo are enriched with NVD.
  - **VirusTotal (free key):** `4 requests / minute`, `500 / day` (`RateLimiter(15500)` in `virustotal.js`).
  - **Groq (free tier):** `8,000 tokens / minute` per model (`TPM_BUDGET = 7000` sliding window in `groq.js`). Note that `llama-3.1-70b-versatile` is decommissioned on Groq — always use `openai/gpt-oss-120b` → `openai/gpt-oss-20b` → `qwen/qwen3.8-27b` (or `process.env.GROQ_MODEL`).
- **Disk Cache (`.cache/`):** All external API responses are cached in `.cache/`. Do not delete `.cache/` before running large E2E batches unless explicitly testing uncached behavior (`OSTE_NO_CACHE=1`).

---

## 4. Common Commands & Verification Workflow

Run all commands from `/home/spirit/Desktop/oste-project`:

```bash
# 1. Fast offline unit tests (16 assertions, 0 API calls)
npm test

# 2. Run specific live E2E test cases by ID (uses .cache/ when available)
node tests/e2e.js "1|10|20|24"

# 3. Run the full 30-case live E2E suite (writes reports/e2e-results.json)
npm run test:e2e

# 4. CLI usage & CI gate check
node cli/oste.js config
node cli/oste.js analyze expressjs/express --no-report
node cli/oste.js analyze left-pad/left-pad --no-report --fail-above 35 --json

# 5. Start the Express web server + UI on http://localhost:3000
npm run dev
```
