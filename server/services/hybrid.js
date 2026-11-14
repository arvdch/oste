/**
 * OSTE - Open Source Tool Evaluation
 * Hybrid Analysis Service
 * 
 * Submits samples to Hybrid Analysis (Falcon Sandbox)
 * for dynamic behavioral analysis.
 */

const axios = require('axios');

class HybridAnalysisService {
  constructor(apiKey) {
    this.apiKey = apiKey;
    this.api = axios.create({
      baseURL: 'https://www.hybrid-analysis.com/api/v2',
      timeout: 60000,
      headers: {
        'api-key': apiKey || '',
        'User-Agent': 'OSTE Security Scanner',
        Accept: 'application/json',
      },
    });
  }

  /**
   * Search for an existing analysis by hash.
   */
  async searchByHash(hash) {
    if (!this.apiKey) {
      return this._mockResult(hash, 'No Hybrid Analysis API key configured');
    }

    try {
      // v2 API: GET /search/hash (newer) with POST fallback (older deployments)
      let resp;
      try {
        resp = await this.api.get('/search/hash', { params: { hash } });
      } catch (e) {
        if (![404, 405].includes(e.response?.status)) throw e;
        resp = await this.api.post('/search/hash', `hash=${encodeURIComponent(hash)}`, {
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        });
      }
      const list = Array.isArray(resp.data) ? resp.data : (resp.data?.reports || resp.data?.result || []);
      if (!list.length) {
        return { status: 'not_found', hash, riskLevel: 'UNKNOWN' };
      }
      return this._normalizeResults(list, hash);
    } catch (err) {
      console.error(`Hybrid Analysis hash search failed: ${err.message}`);
      return this._errorResult(hash, err.message);
    }
  }

  /**
   * Search for existing analyses by term.
   */
  async searchByTerm(term) {
    if (!this.apiKey) {
      return this._mockResult(term, 'No Hybrid Analysis API key configured');
    }

    try {
      const resp = await this.api.post('/search/terms', `filename=${encodeURIComponent(term)}`, {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      });

      if (!resp.data?.result || resp.data.result.length === 0) {
        return { status: 'not_found', term, riskLevel: 'UNKNOWN' };
      }

      return this._normalizeResults(resp.data.result, term);
    } catch (err) {
      console.error(`Hybrid Analysis term search failed: ${err.message}`);
      return this._errorResult(term, err.message);
    }
  }

  /**
   * Get a detailed report for a specific analysis.
   */
  async getReport(id) {
    if (!this.apiKey) {
      return this._mockResult(id, 'No Hybrid Analysis API key configured');
    }

    try {
      const resp = await this.api.get(`/report/${id}/summary`);
      return this._normalizeReport(resp.data);
    } catch (err) {
      console.error(`Hybrid Analysis report failed: ${err.message}`);
      return this._errorResult(id, err.message);
    }
  }

  /**
   * Normalize search results.
   */
  _normalizeResults(results, identifier) {
    const analyses = results.filter(Boolean).map(r => this._normalizeReport(r));
    if (!analyses.length) return { status: 'not_found', identifier, riskLevel: 'UNKNOWN' };

    // Find the most relevant (highest threat score)
    const primary = analyses.reduce((max, a) =>
      (a.threatScore || 0) > (max.threatScore || 0) ? a : max
    );

    return {
      status: 'found',
      identifier,
      totalAnalyses: analyses.length,
      primary,
      analyses: analyses.slice(0, 5),
      riskLevel: primary.riskLevel || 'UNKNOWN',
    };
  }

  /**
   * Normalize a single report.
   */
  _normalizeReport(report) {
    const threatScore = report.threat_score || report.av_detect || 0;

    return {
      jobId: report.job_id,
      sha256: report.sha256,
      md5: report.md5,
      sha1: report.sha1,
      fileName: report.submit_name || report.file_name,
      fileType: report.type || report.type_short,
      fileSize: report.size,
      environment: report.environment_description,
      threatScore,
      threatLevel: report.threat_level,
      verdict: report.verdict,
      avDetect: report.av_detect,
      vxFamily: report.vx_family,
      tags: report.tags || [],
      mitreTactics: (report.mitre_attcks || []).map(m => ({
        tactic: m.tactic,
        technique: m.technique,
        attckId: m.attck_id,
        description: m.attck_id_wiki,
      })),
      processes: (report.processes || []).map(p => ({
        uid: p.uid,
        name: p.name,
        commandLine: p.command_line,
        parentuid: p.parentuid,
      })),
      networkTraffic: {
        domains: report.domains || [],
        hosts: report.hosts || [],
        totalNetworkConnections: report.total_network_connections || 0,
        totalProcesses: report.total_processes || 0,
        totalSignatures: report.total_signatures || 0,
      },
      signatures: (report.extracted_files || []).slice(0, 10).map(f => ({
        name: f.name,
        filePath: f.file_path,
        runtimeProcess: f.runtime_process,
        threatLevel: f.threat_level_readable,
        avMatched: f.av_matched || 0,
      })),
      submissionDate: report.analysis_start_time,
      riskLevel: this._threatScoreToRisk(threatScore),
      behaviorSummary: {
        droppedFiles: report.total_dropped_files || 0,
        networkConnections: report.total_network_connections || 0,
        processes: report.total_processes || 0,
        registryKeys: report.registry_keys_set || 0,
      },
    };
  }

  _threatScoreToRisk(score) {
    if (score >= 80) return 'CRITICAL';
    if (score >= 50) return 'HIGH';
    if (score >= 25) return 'MEDIUM';
    if (score >= 5) return 'LOW';
    return 'CLEAN';
  }

  _mockResult(identifier, reason) {
    return {
      status: 'skipped',
      identifier,
      riskLevel: 'UNKNOWN',
      message: reason,
    };
  }

  _errorResult(identifier, error) {
    return {
      status: 'error',
      identifier,
      riskLevel: 'UNKNOWN',
      error,
    };
  }
}

module.exports = HybridAnalysisService;
