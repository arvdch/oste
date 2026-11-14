/**
 * OSTE - Open Source Tool Evaluation
 * OSV (Open Source Vulnerabilities) Service
 * 
 * Queries the OSV.dev API for known vulnerabilities
 * affecting the project's dependencies.
 */

const axios = require('axios');
const semver = require('semver');
const { cache, withRetry } = require('./util');

class OSVService {
  constructor() {
    this.api = axios.create({
      baseURL: 'https://api.osv.dev/v1',
      timeout: 30000,
      headers: { 'Content-Type': 'application/json' },
    });
  }

  /** Convert a manifest version spec into a concrete version string OSV understands. */
  _cleanVersion(version, ecosystem) {
    if (!version || version === '*' || version === 'latest') return null;
    let v = String(version).trim();
    if (/^(git|github|file|link|workspace|npm:|http)/i.test(v)) return null;
    if (ecosystem === 'npm') {
      try {
        const min = semver.minVersion(v);
        return min ? min.version : null;
      } catch { return null; }
    }
    v = v.replace(/^[\^~>=<!\s]+/, '').split(/[\s,]/)[0];
    return /^\d/.test(v) ? v : null;
  }

  /**
   * Resolve an npm semver range to the version a fresh install would pick (highest satisfying,
   * non-prerelease). Falls back to the range minimum when the registry is unreachable.
   */
  async _resolveNpmRange(name, range) {
    const key = 'npmvers:' + name;
    let versions = cache.get(key, 12 * 3600 * 1000);
    if (versions === undefined) {
      try {
        const r = await withRetry(() => axios.get(`https://registry.npmjs.org/${name.replace('/', '%2F')}`, {
          timeout: 20000, headers: { Accept: 'application/vnd.npm.install-v1+json' },
        }), { retries: 2 });
        versions = Object.keys(r.data.versions || {});
        cache.set(key, versions);
      } catch { versions = null; }
    }
    if (versions) {
      try {
        const v = semver.maxSatisfying(versions, range);
        if (v) return v;
      } catch { /* fall through */ }
    }
    return this._cleanVersion(range, 'npm');
  }

  /**
   * Resolve a PyPI requirement spec. Lower-bound-only specs (>=, >, ~=) resolve to the latest
   * release (what pip installs); specs with an upper bound keep the conservative minimum.
   */
  async _resolvePypiSpec(name, spec, fallback) {
    if (!spec || /[<]/.test(spec) || /==/.test(spec)) return fallback;
    const key = 'pypi:' + name.toLowerCase();
    let latest = cache.get(key, 12 * 3600 * 1000);
    if (latest === undefined) {
      try {
        const r = await withRetry(() => axios.get(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`, { timeout: 15000 }), { retries: 1 });
        latest = r.data.info?.version || null;
      } catch { latest = null; }
      cache.set(key, latest);
    }
    if (!latest) return fallback;
    if (/~=/.test(spec)) {
      // ~=1.4.2 means >=1.4.2,==1.4.* : only accept latest when the prefix matches
      const base = fallback.split('.');
      const prefix = base.slice(0, Math.max(1, base.length - 1)).join('.');
      return latest.startsWith(prefix + '.') || latest === prefix ? latest : fallback;
    }
    return latest;
  }

  async _post(path, body) {
    return withRetry(() => this.api.post(path, body), { retries: 3, label: 'osv' });
  }

  /** Batch query -> array (per input package) of vuln id lists. */
  async _batchIds(packages) {
    const out = new Array(packages.length).fill(null).map(() => []);
    const CHUNK = 500;
    for (let i = 0; i < packages.length; i += CHUNK) {
      const chunk = packages.slice(i, i + CHUNK);
      const queries = chunk.map((pkg) => ({
        package: { name: pkg.name, ecosystem: pkg.ecosystem },
        ...(pkg.cleanVersion ? { version: pkg.cleanVersion } : {}),
      }));
      try {
        const resp = await this._post('/querybatch', { queries });
        (resp.data.results || []).forEach((r, idx) => { out[i + idx] = (r.vulns || []).map((v) => v.id); });
      } catch (err) {
        console.error(`OSV batch query failed: ${err.message}`);
      }
    }
    return out;
  }

  /** Fetch full vulnerability records (querybatch only returns ids). */
  async _hydrate(ids, limit = 150) {
    const unique = [...new Set(ids)].slice(0, limit);
    const records = new Map();
    let i = 0;
    const worker = async () => {
      while (i < unique.length) {
        const id = unique[i++];
        const key = 'osv:' + id;
        let rec = cache.get(key, 24 * 3600 * 1000);
        if (rec === undefined) {
          try {
            rec = (await withRetry(() => this.api.get(`/vulns/${encodeURIComponent(id)}`), { retries: 3 })).data;
            cache.set(key, rec);
          } catch (err) {
            console.error(`OSV vuln fetch failed for ${id}: ${err.message}`);
            continue;
          }
        }
        if (!rec.withdrawn) records.set(id, rec);
      }
    };
    await Promise.all(Array.from({ length: 8 }, worker));
    return records;
  }

  /**
   * Analyze dependency files from GitHub service output.
   * Only runtime packages with a resolvable version are scanned (dev-only packages and
   * unversioned entries would create false positives).
   */
  async analyzeDependencies(dependencyFiles) {
    const seen = new Map();
    let devSkipped = 0;
    let unversioned = 0;
    for (const depFile of dependencyFiles) {
      for (const pkg of depFile.packages) {
        if (pkg.type === 'dev') { devSkipped++; continue; }
        const cleanVersion = this._cleanVersion(pkg.version, depFile.ecosystem);
        if (!cleanVersion) { unversioned++; continue; }
        const key = `${depFile.ecosystem}:${pkg.name}@${cleanVersion}`;
        if (!seen.has(key)) {
          seen.set(key, { name: pkg.name, version: pkg.version, spec: pkg.spec, cleanVersion, ecosystem: depFile.ecosystem, type: pkg.type, exact: !!pkg.exact });
        }
      }
    }
    const allPackages = [...seen.values()];
    // Resolve manifest ranges (no lockfile) to the version an install would actually get
    const toResolve = allPackages.filter((p) => (p.ecosystem === 'npm' || p.ecosystem === 'PyPI') && !p.exact);
    let ri = 0;
    await Promise.all(Array.from({ length: 8 }, async () => {
      while (ri < toResolve.length) {
        const p = toResolve[ri++];
        p.cleanVersion = p.ecosystem === 'npm'
          ? (await this._resolveNpmRange(p.name, p.version)) || p.cleanVersion
          : await this._resolvePypiSpec(p.name, p.spec, p.cleanVersion);
        p.resolvedFromRange = true;
      }
    }));
    const meta = { devSkipped, unversioned, scanned: allPackages.length, resolvedFromRanges: toResolve.length };

    if (allPackages.length === 0) {
      return { totalPackages: 0, vulnerabilities: [], summary: this._createSummary([]), meta };
    }

    const idLists = await this._batchIds(allPackages);
    const idToPkgs = new Map();
    idLists.forEach((ids, idx) => ids.forEach((id) => {
      if (!idToPkgs.has(id)) idToPkgs.set(id, []);
      idToPkgs.get(id).push(allPackages[idx]);
    }));

    const HYDRATE_LIMIT = 300;
    const records = await this._hydrate([...idToPkgs.keys()], HYDRATE_LIMIT);
    const vulns = [];
    for (const [id, rec] of records) {
      const pkgs = idToPkgs.get(id) || [];
      const first = pkgs[0] || {};
      vulns.push({
        ...this._normalize(rec),
        affectedPackage: first.name,
        affectedEcosystem: first.ecosystem,
        affectedVersion: first.cleanVersion,
        affectedPackages: pkgs.slice(0, 5).map((p) => `${p.name}@${p.cleanVersion}`),
        versionExact: !!first.exact,
      });
    }
    meta.vulnerabilityIdsFound = idToPkgs.size;
    meta.hydrated = records.size;
    meta.notHydrated = Math.max(0, idToPkgs.size - records.size);

    const uniqueVulns = this._deduplicateVulns(vulns);
    return {
      totalPackages: allPackages.length,
      vulnerabilities: uniqueVulns,
      summary: this._createSummary(uniqueVulns),
      meta,
    };
  }

  /**
   * Advisories for the project's own published package:
   *  - current: advisories affecting the latest version
   *  - historical: all advisories ever published (count + top sample), a signal of security track record
   */
  async analyzeSelf(selfPackage, latestVersion) {
    if (!selfPackage) return null;
    const version = this._cleanVersion(latestVersion || selfPackage.version, selfPackage.ecosystem);
    const pkgBase = { name: selfPackage.name, ecosystem: selfPackage.ecosystem };
    const queries = [{ ...pkgBase }];
    if (version) queries.push({ ...pkgBase, cleanVersion: version });
    const [histIds, curIds] = await this._batchIds(queries);
    if (!histIds.length && !(curIds || []).length) {
      return { package: selfPackage.name, ecosystem: selfPackage.ecosystem, version, historicalCount: 0, current: [], historicalSeverity: {}, found: false };
    }
    const records = await this._hydrate([...(curIds || []), ...histIds], 40);
    const norm = (id) => (records.has(id) ? this._normalize(records.get(id)) : null);
    const current = (curIds || []).map(norm).filter(Boolean);
    const histSample = histIds.map(norm).filter(Boolean);
    const sev = this._createSummary(histSample);
    return {
      package: selfPackage.name,
      ecosystem: selfPackage.ecosystem,
      version,
      found: true,
      historicalCount: histIds.length,
      historicalSampled: histSample.length,
      historicalSeverity: { CRITICAL: sev.CRITICAL, HIGH: sev.HIGH, MEDIUM: sev.MEDIUM, LOW: sev.LOW },
      current: current.map((v) => ({ ...v, affectedPackage: selfPackage.name, affectedEcosystem: selfPackage.ecosystem, affectedVersion: version, isSelf: true })),
    };
  }

  /**
   * Normalize an OSV vulnerability record.
   */
  _normalize(vuln) {
    const severity = this._extractSeverity(vuln);
    return {
      id: vuln.id,
      aliases: vuln.aliases || [],
      summary: vuln.summary || '',
      details: (vuln.details || '').slice(0, 400),
      severity: severity.level,
      cvssScore: severity.score,
      cvssVector: severity.vector,
      published: vuln.published,
      modified: vuln.modified,
      withdrawn: vuln.withdrawn || null,
      references: (vuln.references || []).map(r => ({
        type: r.type,
        url: r.url,
      })),
      affected: (vuln.affected || []).map(a => ({
        package: a.package,
        ranges: a.ranges,
        versions: a.versions,
        ecosystemSpecific: a.ecosystem_specific,
        databaseSpecific: a.database_specific,
      })),
      cveIds: (vuln.aliases || []).filter(a => a.startsWith('CVE-')),
    };
  }

  _extractSeverity(vuln) {
    const scoreMap = { CRITICAL: 9.5, HIGH: 7.5, MODERATE: 5.5, MEDIUM: 5.5, LOW: 3.0 };
    const dbLevel = (vuln.database_specific?.severity || '').toUpperCase();
    // CVSS v3 vector (exact computation)
    for (const s of vuln.severity || []) {
      if (s.type === 'CVSS_V3') {
        const score = this._parseCVSSScore(s.score);
        if (score !== null) return { score, level: this._scoreToLevel(score), vector: s.score };
      }
    }
    if (scoreMap[dbLevel]) {
      return { score: scoreMap[dbLevel], level: dbLevel === 'MODERATE' ? 'MEDIUM' : dbLevel, vector: null };
    }
    return { score: null, level: 'UNKNOWN', vector: null };
  }

  _parseCVSSScore(vector) {
    const m = vector?.match(/^CVSS:3\.[01]\/(.+)$/);
    if (!m) return null;
    const v = Object.fromEntries(m[1].split('/').map((p) => p.split(':')));
    const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[v.AV];
    const AC = { L: 0.77, H: 0.44 }[v.AC];
    const UI = { N: 0.85, R: 0.62 }[v.UI];
    const changed = v.S === 'C';
    const PR = (changed ? { N: 0.85, L: 0.68, H: 0.5 } : { N: 0.85, L: 0.62, H: 0.27 })[v.PR];
    const cia = { H: 0.56, L: 0.22, N: 0 };
    if ([AV, AC, UI, PR].some((x) => x === undefined) || [v.C, v.I, v.A].some((x) => cia[x] === undefined)) return null;
    const iss = 1 - (1 - cia[v.C]) * (1 - cia[v.I]) * (1 - cia[v.A]);
    const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
    const expl = 8.22 * AV * AC * PR * UI;
    if (impact <= 0) return 0;
    const raw = changed ? Math.min(1.08 * (impact + expl), 10) : Math.min(impact + expl, 10);
    return Math.ceil(raw * 10 - 1e-9) / 10; // CVSS roundup
  }

  _scoreToLevel(score) {
    if (score === null) return 'UNKNOWN';
    if (score >= 9.0) return 'CRITICAL';
    if (score >= 7.0) return 'HIGH';
    if (score >= 4.0) return 'MEDIUM';
    if (score > 0) return 'LOW';
    return 'NONE';
  }

  _deduplicateVulns(vulns) {
    const seen = new Map();
    for (const v of vulns) {
      if (!seen.has(v.id)) {
        seen.set(v.id, v);
      }
    }
    return Array.from(seen.values());
  }

  _createSummary(vulns) {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
    for (const v of vulns) {
      const sev = v.severity || 'UNKNOWN';
      counts[sev] = (counts[sev] || 0) + 1;
    }
    // Treat UNKNOWN severity as MEDIUM (conservative approach)
    counts.MEDIUM += counts.UNKNOWN;
    return {
      total: vulns.length,
      CRITICAL: counts.CRITICAL,
      HIGH: counts.HIGH,
      MEDIUM: counts.MEDIUM,
      LOW: counts.LOW,
      hasCritical: counts.CRITICAL > 0,
      hasHigh: counts.HIGH > 0,
      unknownReclassified: counts.UNKNOWN,
    };
  }
}

module.exports = OSVService;
