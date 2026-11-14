/**
 * OSTE - Open Source Tool Evaluation
 * VirusTotal Service
 * 
 * Analyzes files, URLs and domains through the VirusTotal API
 * for malware detection and publisher reputation assessment.
 */

const axios = require('axios');
const { cache, RateLimiter, withRetry } = require('./util');

class VirusTotalService {
  constructor(apiKey) {
    this.apiKey = apiKey;
    this.api = axios.create({
      baseURL: 'https://www.virustotal.com/api/v3',
      timeout: 60000,
      headers: {
        'x-apikey': apiKey || '',
      },
    });
    // Free public API: 4 requests/minute, 500/day -> one request every ~15.5s
    this.limiter = new RateLimiter(15500);
  }

  _get(path) {
    return this.limiter.schedule(() => withRetry(() => this.api.get(path), { retries: 2, baseMs: 20000 }));
  }

  _post(path, body, opts) {
    return this.limiter.schedule(() => withRetry(() => this.api.post(path, body, opts), { retries: 2, baseMs: 20000 }));
  }

  /**
   * Analyze a URL (e.g., download link for freeware).
   */
  async analyzeURL(url) {
    if (!this.apiKey) {
      return this._mockResult('url', url, 'No VirusTotal API key configured');
    }

    const ckey = 'vt:url:' + url;
    const cached = cache.get(ckey, 24 * 3600 * 1000);
    if (cached) return cached;

    try {
      // Reuse an existing recent report when there is one (saves quota + time)
      const urlId = Buffer.from(url).toString('base64url');
      try {
        const existing = await this._get(`/urls/${urlId}`);
        const a = existing.data.data.attributes;
        const total = Object.values(a.last_analysis_stats || {}).reduce((x, y) => x + y, 0);
        if (total > 0 && a.last_analysis_date && Date.now() / 1000 - a.last_analysis_date < 7 * 86400) {
          const st = a.last_analysis_stats;
          const result = {
            type: 'url', target: url, status: 'completed', source: 'existing-report',
            stats: st, malicious: st.malicious || 0, suspicious: st.suspicious || 0,
            harmless: st.harmless || 0, undetected: st.undetected || 0,
            reputation: a.reputation, categories: a.categories, finalUrl: a.last_final_url,
            riskLevel: this._assessRisk(st),
            detectionNames: this._extractDetections(a.last_analysis_results),
          };
          cache.set(ckey, result);
          return result;
        }
      } catch (e) {
        if (e.response?.status !== 404) throw e;
      }

      // Submit URL for scanning
      const submitResp = await this._post('/urls', `url=${encodeURIComponent(url)}`, {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      });

      const analysisId = submitResp.data.data.id;

      // Poll for results
      const polled = await this._pollAnalysis(analysisId, url, 'url');
      if (polled.status === 'completed') cache.set(ckey, polled);
      return polled;
    } catch (err) {
      console.error(`VirusTotal URL analysis failed: ${err.message}`);
      return this._errorResult('url', url, err.message);
    }
  }

  /**
   * Search for a domain's reputation.
   */
  async analyzeDomain(domain) {
    if (!this.apiKey) {
      return this._mockResult('domain', domain, 'No VirusTotal API key configured');
    }

    try {
      const dkey = 'vt:dom:' + domain;
      const dc = cache.get(dkey, 24 * 3600 * 1000);
      if (dc) return dc;
      const resp = await this._get(`/domains/${domain}`);
      const data = resp.data.data;

      const dresult = {
        type: 'domain',
        target: domain,
        status: 'completed',
        reputation: data.attributes.reputation,
        lastAnalysisStats: data.attributes.last_analysis_stats,
        categories: data.attributes.categories,
        registrar: data.attributes.registrar,
        creationDate: data.attributes.creation_date,
        lastModificationDate: data.attributes.last_modification_date,
        malicious: data.attributes.last_analysis_stats?.malicious || 0,
        suspicious: data.attributes.last_analysis_stats?.suspicious || 0,
        harmless: data.attributes.last_analysis_stats?.harmless || 0,
        undetected: data.attributes.last_analysis_stats?.undetected || 0,
        riskLevel: this._assessRisk(data.attributes.last_analysis_stats),
      };
      cache.set(dkey, dresult);
      return dresult;
    } catch (err) {
      console.error(`VirusTotal domain analysis failed: ${err.message}`);
      return this._errorResult('domain', domain, err.message);
    }
  }

  /**
   * Look up a file hash.
   */
  async analyzeFileHash(hash) {
    if (!this.apiKey) {
      return this._mockResult('file', hash, 'No VirusTotal API key configured');
    }

    try {
      const fkey = 'vt:file:' + hash;
      const fc = cache.get(fkey, 24 * 3600 * 1000);
      if (fc) return fc;
      const resp = await this._get(`/files/${hash}`);
      const data = resp.data.data;
      const attrs = data.attributes;

      const fresult = {
        type: 'file',
        target: hash,
        status: 'completed',
        name: attrs.meaningful_name || attrs.names?.[0],
        size: attrs.size,
        sha256: attrs.sha256,
        md5: attrs.md5,
        sha1: attrs.sha1,
        fileType: attrs.type_description,
        magic: attrs.magic,
        lastAnalysisStats: attrs.last_analysis_stats,
        malicious: attrs.last_analysis_stats?.malicious || 0,
        suspicious: attrs.last_analysis_stats?.suspicious || 0,
        harmless: attrs.last_analysis_stats?.harmless || 0,
        undetected: attrs.last_analysis_stats?.undetected || 0,
        reputation: attrs.reputation,
        totalVotes: attrs.total_votes,
        tags: attrs.tags || [],
        signatureInfo: attrs.signature_info || null,
        sandbox: attrs.sandbox_verdicts || null,
        riskLevel: this._assessRisk(attrs.last_analysis_stats),
        detectionNames: this._extractDetections(attrs.last_analysis_results),
      };
      cache.set(fkey, fresult);
      return fresult;
    } catch (err) {
      if (err.response?.status === 404) {
        return { type: 'file', target: hash, status: 'not_found', riskLevel: 'UNKNOWN' };
      }
      console.error(`VirusTotal file analysis failed: ${err.message}`);
      return this._errorResult('file', hash, err.message);
    }
  }

  /**
   * Poll for analysis completion.
   */
  async _pollAnalysis(analysisId, target, type, maxAttempts = 10) {
    for (let i = 0; i < maxAttempts; i++) {
      try {
        const resp = await this._get(`/analyses/${analysisId}`);
        const data = resp.data.data;

        if (data.attributes.status === 'completed') {
          return {
            type,
            target,
            status: 'completed',
            stats: data.attributes.stats,
            malicious: data.attributes.stats?.malicious || 0,
            suspicious: data.attributes.stats?.suspicious || 0,
            harmless: data.attributes.stats?.harmless || 0,
            undetected: data.attributes.stats?.undetected || 0,
            detectionNames: this._extractDetections(data.attributes.results),
            riskLevel: this._assessRisk(data.attributes.stats),
          };
        }
      } catch (err) {
        console.error(`Poll attempt ${i + 1} failed: ${err.message}`);
      }
    }

    return {
      type,
      target,
      status: 'timeout',
      riskLevel: 'UNKNOWN',
      message: 'Analysis timed out after maximum attempts',
    };
  }

  _assessRisk(stats) {
    if (!stats) return 'UNKNOWN';
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const total = Object.values(stats).reduce((a, b) => a + b, 0);

    if (malicious >= 10) return 'CRITICAL';
    if (malicious >= 5) return 'HIGH';
    if (malicious >= 1 || suspicious >= 3) return 'MEDIUM';
    if (suspicious >= 1) return 'LOW';
    return 'CLEAN';
  }

  _extractDetections(results) {
    if (!results) return [];
    return Object.entries(results)
      .filter(([, r]) => r.category === 'malicious' || r.category === 'suspicious')
      .map(([engine, r]) => ({
        engine,
        category: r.category,
        result: r.result,
      }))
      .slice(0, 20);
  }

  _mockResult(type, target, reason) {
    return {
      type,
      target,
      status: 'skipped',
      riskLevel: 'UNKNOWN',
      message: reason,
      malicious: 0,
      suspicious: 0,
    };
  }

  _errorResult(type, target, error) {
    return {
      type,
      target,
      status: 'error',
      riskLevel: 'UNKNOWN',
      error,
    };
  }
}

module.exports = VirusTotalService;
