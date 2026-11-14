/**
 * OSTE - Open Source Tool Evaluation
 * NVD (National Vulnerability Database) Service
 * 
 * Enriches vulnerability findings with NVD data including
 * official CVSS scores, CWE mappings, and references.
 */

const axios = require('axios');
const { cache, RateLimiter, withRetry } = require('./util');

class NVDService {
  constructor(apiKey) {
    this.apiKey = apiKey;
    this.api = axios.create({
      baseURL: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
      timeout: 30000,
      headers: {
        ...(apiKey ? { apiKey } : {}),
      },
    });
    // Public limit: 5 req / 30s without key (6.5s gap is safe), 50 req / 30s with key.
    this.limiter = new RateLimiter(apiKey ? 700 : 6500);
  }

  /** Rate-limited, retrying request. */
  async _throttledRequest(params) {
    return this.limiter.schedule(() =>
      withRetry(() => this.api.get('', { params }), {
        retries: 3,
        baseMs: 8000,
        isRetryable: (e) => [403, 429, 503, 502, 504].includes(e.response?.status) || !e.response,
      }));
  }

  /**
   * Look up a CVE by ID.
   */
  async getCVE(cveId) {
    const key = 'nvd:' + cveId;
    const hit = cache.get(key, 24 * 3600 * 1000);
    if (hit !== undefined) return hit;
    try {
      const resp = await this._throttledRequest({ cveId });
      const vulns = resp.data.vulnerabilities || [];
      if (vulns.length === 0) return null;

      const norm = this._normalize(vulns[0].cve);
      cache.set(key, norm);
      return norm;
    } catch (err) {
      console.error(`NVD lookup failed for ${cveId}: ${err.message}`);
      return null;
    }
  }

  /**
   * Search NVD by keyword (e.g., package name).
   */
  async searchByKeyword(keyword, resultsPerPage = 20) {
    try {
      const resp = await this._throttledRequest({
        keywordSearch: keyword,
        resultsPerPage,
      });

      return (resp.data.vulnerabilities || []).map(v => this._normalize(v.cve));
    } catch (err) {
      console.error(`NVD keyword search failed for "${keyword}": ${err.message}`);
      return [];
    }
  }

  /**
   * Enrich OSV vulnerability findings with NVD data.
   */
  async enrichVulnerabilities(osvVulns) {
    const enriched = [];

    for (const vuln of osvVulns) {
      const cveIds = vuln.cveIds || vuln.aliases?.filter(a => a.startsWith('CVE-')) || [];

      if (cveIds.length === 0) {
        enriched.push({ ...vuln, nvdEnriched: false });
        continue;
      }

      // Look up the first CVE ID (primary)
      const nvdData = await this.getCVE(cveIds[0]);

      if (nvdData) {
        enriched.push({
          ...vuln,
          nvdEnriched: true,
          nvd: {
            cveId: nvdData.id,
            description: nvdData.description,
            cvssV3: nvdData.cvssV3,
            cvssV2: nvdData.cvssV2,
            cwes: nvdData.cwes,
            references: nvdData.references,
            published: nvdData.published,
            lastModified: nvdData.lastModified,
            exploitabilityScore: nvdData.exploitabilityScore,
            impactScore: nvdData.impactScore,
          },
          // Override severity with NVD data if available
          severity: nvdData.cvssV3?.baseSeverity || vuln.severity,
          cvssScore: nvdData.cvssV3?.baseScore || vuln.cvssScore,
        });
      } else {
        enriched.push({ ...vuln, nvdEnriched: false });
      }
    }

    return enriched;
  }

  /**
   * Normalize NVD CVE data.
   */
  _normalize(cve) {
    const desc = cve.descriptions?.find(d => d.lang === 'en')?.value || '';

    // Extract CVSS v3
    let cvssV3 = null;
    const metrics = cve.metrics;
    if (metrics?.cvssMetricV31?.length) {
      const m = metrics.cvssMetricV31[0];
      cvssV3 = {
        baseScore: m.cvssData.baseScore,
        baseSeverity: m.cvssData.baseSeverity,
        vectorString: m.cvssData.vectorString,
        attackVector: m.cvssData.attackVector,
        attackComplexity: m.cvssData.attackComplexity,
        privilegesRequired: m.cvssData.privilegesRequired,
        userInteraction: m.cvssData.userInteraction,
        scope: m.cvssData.scope,
        confidentialityImpact: m.cvssData.confidentialityImpact,
        integrityImpact: m.cvssData.integrityImpact,
        availabilityImpact: m.cvssData.availabilityImpact,
      };
    } else if (metrics?.cvssMetricV30?.length) {
      const m = metrics.cvssMetricV30[0];
      cvssV3 = {
        baseScore: m.cvssData.baseScore,
        baseSeverity: m.cvssData.baseSeverity,
        vectorString: m.cvssData.vectorString,
      };
    }

    // Extract CVSS v2
    let cvssV2 = null;
    if (metrics?.cvssMetricV2?.length) {
      const m = metrics.cvssMetricV2[0];
      cvssV2 = {
        baseScore: m.cvssData.baseScore,
        severity: m.baseSeverity,
        vectorString: m.cvssData.vectorString,
      };
    }

    // Extract CWEs
    const cwes = [];
    for (const weakness of cve.weaknesses || []) {
      for (const desc of weakness.description || []) {
        if (desc.value && desc.value !== 'NVD-CWE-noinfo') {
          cwes.push(desc.value);
        }
      }
    }

    // Exploitability and impact scores
    let exploitabilityScore = null;
    let impactScore = null;
    if (metrics?.cvssMetricV31?.[0]) {
      exploitabilityScore = metrics.cvssMetricV31[0].exploitabilityScore;
      impactScore = metrics.cvssMetricV31[0].impactScore;
    }

    return {
      id: cve.id,
      description: desc.slice(0, 500),
      cvssV3,
      cvssV2,
      cwes,
      references: (cve.references || []).slice(0, 5).map(r => ({
        url: r.url,
        source: r.source,
        tags: r.tags || [],
      })),
      published: cve.published,
      lastModified: cve.lastModified,
      exploitabilityScore,
      impactScore,
    };
  }
}

module.exports = NVDService;
