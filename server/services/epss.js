/**
 * OSTE - Open Source Tool Evaluation
 * EPSS (Exploit Prediction Scoring System) Service
 * 
 * Queries FIRST.org's EPSS API to get exploit probability
 * scores for known CVEs. EPSS predicts the likelihood
 * that a vulnerability will be exploited in the wild.
 */

const axios = require('axios');
const { cache, withRetry } = require('./util');

class EPSSService {
  constructor() {
    this.api = axios.create({
      baseURL: 'https://api.first.org/data/v1',
      timeout: 15000,
    });
  }

  /**
   * Get EPSS data for a single CVE.
   */
  async getScore(cveId) {
    try {
      const resp = await this.api.get('/epss', {
        params: { cve: cveId },
      });

      const data = resp.data?.data?.[0];
      if (!data) return null;

      return {
        cve: data.cve,
        epss: parseFloat(data.epss),
        percentile: parseFloat(data.percentile),
        date: data.date,
        riskLevel: this._epssToRiskLevel(parseFloat(data.epss)),
      };
    } catch (err) {
      console.error(`EPSS lookup failed for ${cveId}: ${err.message}`);
      return null;
    }
  }

  /**
   * Get EPSS data for multiple CVEs in batch.
   */
  async getScoresBatch(cveIds) {
    if (!cveIds.length) return [];
    const results = [];
    const CHUNK = 40; // keep URL length well under limits
    for (let i = 0; i < cveIds.length; i += CHUNK) {
      const chunk = cveIds.slice(i, i + CHUNK);
      const key = 'epss:' + chunk.join(',');
      let data = cache.get(key, 12 * 3600 * 1000);
      if (data === undefined) {
        try {
          const resp = await withRetry(() => this.api.get('/epss', { params: { cve: chunk.join(',') } }), { retries: 3 });
          data = resp.data?.data || [];
          cache.set(key, data);
        } catch (err) {
          console.error(`EPSS batch lookup failed: ${err.message}`);
          continue;
        }
      }
      results.push(...data.map((d) => ({
        cve: d.cve,
        epss: parseFloat(d.epss),
        percentile: parseFloat(d.percentile),
        date: d.date,
        riskLevel: this._epssToRiskLevel(parseFloat(d.epss)),
      })));
    }
    return results;
  }

  /**
   * Enrich vulnerability findings with EPSS data.
   */
  async enrichVulnerabilities(vulns) {
    // Collect all CVE IDs
    const cveIds = [];
    for (const v of vulns) {
      const ids = v.cveIds || v.aliases?.filter(a => a.startsWith('CVE-')) || [];
      cveIds.push(...ids);
    }

    const uniqueCveIds = [...new Set(cveIds)];
    if (uniqueCveIds.length === 0) return vulns;

    // Batch fetch EPSS scores
    const epssScores = await this.getScoresBatch(uniqueCveIds);
    const epssMap = new Map(epssScores.map(s => [s.cve, s]));

    // Enrich each vulnerability
    return vulns.map(v => {
      const ids = v.cveIds || v.aliases?.filter(a => a.startsWith('CVE-')) || [];
      const epssData = ids.map(id => epssMap.get(id)).filter(Boolean);

      // Use the highest EPSS score among all CVE aliases
      const maxEpss = epssData.length > 0
        ? epssData.reduce((max, d) => d.epss > max.epss ? d : max)
        : null;

      return {
        ...v,
        epss: maxEpss ? {
          score: maxEpss.epss,
          percentile: maxEpss.percentile,
          riskLevel: maxEpss.riskLevel,
          date: maxEpss.date,
          cve: maxEpss.cve,
        } : null,
        exploitLikelihood: maxEpss ? this._interpretEPSS(maxEpss.epss) : 'Unknown',
      };
    });
  }

  /**
   * Convert EPSS score to risk level.
   */
  _epssToRiskLevel(epss) {
    if (epss >= 0.9) return 'CRITICAL';
    if (epss >= 0.5) return 'HIGH';
    if (epss >= 0.1) return 'MEDIUM';
    if (epss >= 0.01) return 'LOW';
    return 'MINIMAL';
  }

  /**
   * Human-readable EPSS interpretation.
   */
  _interpretEPSS(epss) {
    const pct = (epss * 100).toFixed(2);
    if (epss >= 0.9) return `Very High (${pct}%) - Almost certain to be exploited`;
    if (epss >= 0.5) return `High (${pct}%) - Likely to be exploited`;
    if (epss >= 0.1) return `Moderate (${pct}%) - Notable exploitation probability`;
    if (epss >= 0.01) return `Low (${pct}%) - Limited exploitation activity`;
    return `Minimal (${pct}%) - Very unlikely to be exploited`;
  }
}

module.exports = EPSSService;
