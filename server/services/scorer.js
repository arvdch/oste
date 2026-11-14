/**
 * OSTE - Open Source Tool Evaluation
 * Risk Scoring Engine (v2)
 * 
 * Normalizes and scores findings from all services into
 * a unified risk score with detailed breakdown.
 * 
 * HIGHER score = HIGHER risk (0 = safest, 100 = riskiest)
 */

class ScorerService {
  /**
   * Calculate overall risk score for open source tools.
   */
  scoreOpenSource(data) {
    const components = {};

    // 1. Repository Health (weight: 20%) — inverted: poor health = high risk
    components.health = {
      weight: 0.20,
      score: this._scoreProjectHealth(data),
      label: 'Project Health',
      available: !data.repository?._partial,
    };

    // 2. Vulnerability Exposure (weight: 30%)
    components.vulnerabilities = {
      weight: 0.30,
      score: this._scoreVulnerabilities(data.vulnerabilities, data.vulnerabilitySummary, data.selfAdvisories),
      label: 'Vulnerability Exposure',
      available: this._vulnDataAvailable(data),
    };

    // 3. Exploit Likelihood (weight: 20%)
    components.exploitability = {
      weight: 0.20,
      score: this._scoreExploitability(data.vulnerabilities),
      label: 'Exploit Likelihood (EPSS)',
      available: this._vulnDataAvailable(data),
    };

    // 4. Maintenance & Activity (weight: 15%)
    components.maintenance = {
      weight: 0.15,
      score: this._scoreMaintenance(data),
      label: 'Maintenance Activity',
      available: !data.repository?._partial,
    };

    // 5. License & Compliance (weight: 15%)
    components.license = {
      weight: 0.15,
      score: this._scoreLicense(data.repository?.license),
      label: 'License Compliance',
      available: !data.repository?._partial,
    };

    // Weighted risk score (0 = safest, 100 = riskiest); unavailable components are excluded and weights renormalized
    let riskScore = this._aggregate(components);

    // Archived or disabled repositories receive no security updates and cannot be unconditionally approved
    if (data.repository?.archived || data.repository?.disabled) {
      riskScore = Math.max(riskScore, 45);
    }

    // Generate auto-recommendations based on component scores
    const recommendations = this._generateRecommendations(components, data);

    return {
      overallRiskScore: riskScore,
      riskLevel: this._riskScoreToLevel(riskScore),
      decision: this._riskScoreToDecision(riskScore),
      components,
      recommendations,
      confidenceLevel: this._componentConfidence(components, this._calculateConfidence(data)),
    };
  }

  /**
   * Calculate overall risk score for freeware.
   */
  scoreFreeware(data) {
    const components = {};

    // 1. Malware Detection (weight: 40%)
    components.malware = {
      weight: 0.40,
      score: this._scoreMalware(data.virusTotal),
      label: 'Malware Detection',
      available: this._vtUsable(data.virusTotal),
    };

    // 2. Behavioral Analysis (weight: 30%)
    components.behavior = {
      weight: 0.30,
      score: this._scoreBehavior(data.hybridAnalysis),
      label: 'Behavioral Analysis',
      available: !!data.hybridAnalysis && data.hybridAnalysis.status === 'found' && !!data.hybridAnalysis.primary,
    };

    // 3. Publisher Reputation (weight: 20%)
    components.reputation = {
      weight: 0.20,
      score: this._scoreReputation(data.virusTotal, data.domainReputation),
      label: 'Publisher Reputation',
      available: !!((data.virusTotal?.signatureInfo && Object.keys(data.virusTotal.signatureInfo).length) || typeof data.virusTotal?.reputation === 'number' || data.domainReputation?.status === 'completed'),
    };

    // 4. Distribution Safety (weight: 10%)
    components.distribution = {
      weight: 0.10,
      score: this._scoreDistribution(data.domainReputation),
      label: 'Distribution Safety',
      available: data.domainReputation?.status === 'completed',
    };

    // Weighted risk score (0 = safest, 100 = riskiest); unavailable components are excluded and weights renormalized
    let riskScore = this._aggregate(components);

    const insufficient = !Object.values(components).some((c) => c.available !== false);
    // Hard gate: broad multi-engine malware detection is a rejection regardless of other signals
    const hardGate = this._vtUsable(data.virusTotal) && (data.virusTotal.malicious || 0) >= 10;
    if (hardGate) riskScore = Math.max(riskScore, 85);
    return {
      overallRiskScore: riskScore,
      hardGate: hardGate ? 'malware: >=10 antivirus engines flag this sample' : undefined,
      riskLevel: this._riskScoreToLevel(riskScore),
      decision: insufficient ? 'REVIEW_REQUIRED' : this._riskScoreToDecision(riskScore),
      insufficientData: insufficient,
      components,
      confidenceLevel: this._componentConfidence(components, this._calculateFreewareConfidence(data)),
    };
  }

  /** Weighted mean over components that actually have data. */
  _aggregate(components) {
    const avail = Object.values(components).filter((c) => c.available !== false);
    const totalW = avail.reduce((a, c) => a + c.weight, 0);
    if (!totalW) return 50;
    const sum = avail.reduce((a, c) => a + c.score * c.weight, 0);
    for (const c of avail) c.effectiveWeight = +(c.weight / totalW).toFixed(3);
    return Math.round(sum / totalW);
  }

  /** Vulnerability data counts as available when we scanned packages or looked up the project's own package. */
  _vulnDataAvailable(data) {
    return (data.vulnerabilitySummary?.totalPackages || 0) > 0 || !!data.selfAdvisories;
  }

  _vtUsable(vt) {
    return !!vt && vt.status === 'completed';
  }

  // ---- Open Source Scoring Functions ----

  /**
   * Project Health Risk (0–100)
   * Considers: stars, contributors, forks, community profile, archived status.
   * Low health = high risk score.
   */
  _scoreProjectHealth(data) {
    const repo = data.repository;
    if (!repo) return 70; // No repo data = high risk

    // Partial data (rate limited) = moderate risk with penalty
    if (repo._partial) return 55;

    let risk = 50; // Start at moderate

    // Archived repos are dead projects
    if (repo.archived) return 95;
    if (repo.disabled) return 90;

    // Star count — popularity as a proxy for trust
    const stars = repo.stars || 0;
    if (stars >= 10000) risk -= 25;
    else if (stars >= 1000) risk -= 15;
    else if (stars >= 100) risk -= 8;
    else if (stars >= 10) risk -= 2;
    else risk += 15; // very few stars = higher risk

    // Contributors — bus factor
    const contribCount = data.contributors?.count || 0;
    if (contribCount >= 30) risk -= 12;
    else if (contribCount >= 10) risk -= 8;
    else if (contribCount >= 3) risk -= 3;
    else if (contribCount <= 1) risk += 12; // single maintainer = risk

    // Forks — adoption signal
    const forks = repo.forks || 0;
    if (forks >= 1000) risk -= 5;
    else if (forks >= 100) risk -= 3;
    else if (forks < 5) risk += 5;

    // Community health signals
    const community = data.community;
    if (community) {
      if (!community.hasSecurityPolicy) risk += 8;
      if (!community.hasContributing) risk += 3;
      if (!community.hasReadme) risk += 5;
      if (community.healthPercentage) {
        risk -= Math.round(community.healthPercentage / 10); // up to -10
      }
    } else {
      risk += 5; // No community data = slight risk
    }

    // Open issues ratio (high open issues vs stars = bad sign)
    if (repo.openIssues && stars > 0) {
      const issueRatio = repo.openIssues / stars;
      if (issueRatio > 0.1) risk += 8;
      else if (issueRatio > 0.05) risk += 4;
    }

    return Math.max(0, Math.min(100, risk));
  }

  /**
   * Vulnerability Exposure (0–100)
   * Severity-weighted scoring with severity classification from OSV.
   */
  _scoreVulnerabilities(vulns, summary, selfAdv) {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    for (const v of vulns || []) counts[this._classifyVulnSeverity(v)]++;
    // Advisories found but not fetched in detail (very large dependency trees) count as MEDIUM
    counts.MEDIUM += summary?.notHydrated || 0;

    // Severity-weighted points, with diminishing returns so the scale stays meaningful
    const points = counts.CRITICAL * 30 + counts.HIGH * 18 + counts.MEDIUM * 8 + counts.LOW * 2;
    let score = 100 * (1 - Math.exp(-points / 60));

    // Security track record of the project's own package (all-time advisories)
    if (selfAdv?.historicalCount) {
      const h = selfAdv.historicalCount;
      const sev = selfAdv.historicalSeverity || {};
      let hist = 0;
      if (h > 50) hist += 10; else if (h > 20) hist += 6; else if (h > 5) hist += 3; else hist += 1;
      hist += Math.min(8, (sev.CRITICAL || 0) * 2 + (sev.HIGH || 0) * 0.5);
      score += hist;
    }
    return Math.min(100, Math.round(score));
  }

  /**
   * Classify vulnerability severity from various data points.
   */
  _classifyVulnSeverity(vuln) {
    // Use explicit severity if present
    if (vuln.severity && ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(vuln.severity)) {
      return vuln.severity;
    }

    // Use CVSS score to derive severity
    const cvss = vuln.cvssScore || vuln.cvss;
    if (cvss != null) {
      if (cvss >= 9.0) return 'CRITICAL';
      if (cvss >= 7.0) return 'HIGH';
      if (cvss >= 4.0) return 'MEDIUM';
      return 'LOW';
    }

    // Check database_specific severity
    if (vuln.database_specific?.severity) {
      const s = vuln.database_specific.severity.toUpperCase();
      if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(s)) return s;
    }

    // Default: treat unknown severity as MEDIUM (conservative)
    return 'MEDIUM';
  }

  /**
   * Exploit Likelihood (0–100)
   * Based on EPSS scores — probability of exploitation in the wild.
   */
  _scoreExploitability(vulns) {
    if (!vulns || !vulns.length) return 0; // No vulns = no exploit risk

    const epssScores = vulns
      .filter(v => v.epss?.score)
      .map(v => v.epss.score);

    if (!epssScores.length) {
      // Vulns exist but no EPSS data — moderate risk based on vuln count
      if (vulns.length > 10) return 40;
      if (vulns.length > 5) return 30;
      return 20;
    }

    const maxEpss = Math.max(...epssScores);
    const avgEpss = epssScores.reduce((a, b) => a + b, 0) / epssScores.length;
    const highEpssCount = epssScores.filter(s => s >= 0.1).length; // >10% exploit probability
    const criticalEpssCount = epssScores.filter(s => s >= 0.5).length; // >50% exploit probability

    // Combine signals
    let score = 0;
    score += Math.round(maxEpss * 100 * 0.35);       // Max EPSS contributes 35%
    score += Math.round(avgEpss * 100 * 0.25);        // Avg EPSS contributes 25%
    score += highEpssCount * 8;                        // Each high-EPSS vuln adds 8 points
    score += criticalEpssCount * 15;                   // Each critical-EPSS vuln adds 15 points

    return Math.min(100, score);
  }

  /**
   * Maintenance Activity Risk (0–100)
   * Considers: commit recency, release cadence, issue response time, PR merge time.
   * Unmaintained = high risk.
   */
  _scoreMaintenance(data) {
    const repo = data.repository;
    if (!repo) return 60;

    // Partial data (rate limited) = moderate risk with penalty
    if (repo._partial) return 50;

    // Archived repos
    if (repo.archived) return 95;

    let risk = 40; // Start moderate

    // --- Commit recency ---
    const lastCommit = data.commits?.lastCommitDate;
    if (lastCommit) {
      const daysSinceCommit = (Date.now() - new Date(lastCommit)) / 86400000;
      if (daysSinceCommit > 730) risk += 35;       // 2+ years = very risky
      else if (daysSinceCommit > 365) risk += 25;   // 1+ year = risky
      else if (daysSinceCommit > 180) risk += 15;   // 6+ months = concerning
      else if (daysSinceCommit > 90) risk += 8;     // 3+ months = slight concern
      else if (daysSinceCommit < 7) risk -= 20;      // Active this week = great
      else if (daysSinceCommit < 30) risk -= 15;     // Active this month = good
      else if (daysSinceCommit < 60) risk -= 8;      // Active last 2 months
    } else {
      risk += 15; // No commit data available
    }

    // --- Release cadence ---
    const releases = data.releases;
    if (releases?.length > 0) {
      const latestRelease = new Date(releases[0].publishedAt);
      const daysSinceRelease = (Date.now() - latestRelease) / 86400000;
      if (daysSinceRelease > 730) risk += 20;
      else if (daysSinceRelease > 365) risk += 12;
      else if (daysSinceRelease < 90) risk -= 12;
      else if (daysSinceRelease < 180) risk -= 5;

      // Multiple releases = active project
      if (releases.length >= 5) risk -= 5;
    } else {
      risk += 10; // No releases at all
    }

    // --- Issue response time ---
    if (data.issues?.avgCloseTimeHours != null) {
      if (data.issues.avgCloseTimeHours < 24) risk -= 8;
      else if (data.issues.avgCloseTimeHours < 168) risk -= 4;
      else if (data.issues.avgCloseTimeHours > 720) risk += 8;
    }

    // --- PR merge time ---
    if (data.pullRequests?.avgMergeTimeHours != null) {
      if (data.pullRequests.avgMergeTimeHours < 24) risk -= 5;
      else if (data.pullRequests.avgMergeTimeHours < 168) risk -= 2;
      else if (data.pullRequests.avgMergeTimeHours > 720) risk += 5;
    }

    return Math.max(0, Math.min(100, risk));
  }

  /**
   * License Compliance Risk (0–100)
   */
  _scoreLicense(license) {
    if (!license) return 70; // No license = high risk (code is technically all-rights-reserved)

    const permissive = ['mit', 'apache-2.0', 'bsd-2-clause', 'bsd-3-clause', 'isc', 'unlicense', '0bsd'];
    const copyleft = ['gpl-2.0', 'gpl-3.0', 'agpl-3.0', 'lgpl-2.1', 'lgpl-3.0'];
    const weak = ['mpl-2.0', 'epl-2.0', 'cddl-1.0'];

    const key = license.key?.toLowerCase();
    if (!key) return 60; // License exists but can't identify it

    if (permissive.includes(key)) return 5;      // Very safe
    if (weak.includes(key)) return 25;            // Moderate
    if (copyleft.includes(key)) return 45;        // Copyleft restrictions
    if (key === 'other' || key === 'noassertion') return 55; // Custom/unknown license
    return 40; // Unrecognized license
  }

  // ---- Freeware Scoring Functions ----

  _scoreMalware(vtResult) {
    if (!vtResult || vtResult.status === 'skipped') return 50;
    if (vtResult.status === 'error') return 60;

    const malicious = vtResult.malicious || 0;
    if (malicious >= 10) return 100;
    if (malicious >= 5) return 85;
    if (malicious >= 3) return 65;
    if (malicious === 2) return 35;
    if (malicious === 1) return 20; // single-engine detections are usually false positives
    if ((vtResult.suspicious || 0) >= 3) return 40;
    if ((vtResult.suspicious || 0) >= 1) return 25;
    return 5;
  }

  _scoreBehavior(haResult) {
    if (!haResult || haResult.status === 'skipped') return 50;
    if (haResult.status === 'not_found') return 40;

    const primary = haResult.primary;
    if (!primary) return 50;

    const score = primary.threatScore || 0;
    return Math.min(100, score);
  }

  _scoreReputation(vtResult, domainRep) {
    let score = 50;

    // Only a *valid* Authenticode signature lowers risk (malware often carries fake/invalid ones)
    const sig = vtResult?.signatureInfo;
    if (sig && Object.keys(sig).length > 0) {
      const verified = /^signed$/i.test(String(sig.verified || '').trim());
      if (verified && (vtResult.malicious || 0) < 3) score -= 20;
      else if (!verified) score += 5;
    }

    // Community reputation of the file/URL itself (VirusTotal votes)
    if (typeof vtResult?.reputation === 'number') {
      if (vtResult.reputation <= -10) score += 20;
      else if (vtResult.reputation < 0) score += 8;
      else if (vtResult.reputation > 10 && (vtResult.malicious || 0) < 3) score -= 10;
    }

    if (domainRep?.reputation !== undefined) {
      if (domainRep.reputation > 0) score -= 15;
      else if (domainRep.reputation < -5) score += 20;
    }

    if (domainRep?.malicious >= 3) score += 30;
    else if (domainRep?.malicious > 0) score += 5;

    return Math.max(0, Math.min(100, score));
  }

  _scoreDistribution(domainRep) {
    if (!domainRep || domainRep.status === 'skipped') return 50;

    if (domainRep.riskLevel === 'CRITICAL') return 100;
    if (domainRep.riskLevel === 'HIGH') return 80;
    if (domainRep.riskLevel === 'MEDIUM') return 50;
    if (domainRep.riskLevel === 'LOW') return 25;
    if (domainRep.riskLevel === 'CLEAN') return 5;
    return 50;
  }

  // ---- Auto Recommendations ----

  _generateRecommendations(components, data) {
    const recs = [];

    // Vulnerability recommendations
    if (components.vulnerabilities?.score >= 60) {
      recs.push({
        priority: 'CRITICAL',
        action: 'Remediate critical and high severity vulnerabilities before adoption',
        rationale: `High vulnerability exposure score (${components.vulnerabilities.score}/100). Review and patch known CVEs.`,
      });
    } else if (components.vulnerabilities?.score >= 30) {
      recs.push({
        priority: 'HIGH',
        action: 'Review and remediate known vulnerabilities in dependencies',
        rationale: `Moderate vulnerability exposure detected (${components.vulnerabilities.score}/100).`,
      });
    }

    // Exploit risk
    if (components.exploitability?.score >= 50) {
      recs.push({
        priority: 'CRITICAL',
        action: 'Prioritize patching vulnerabilities with high EPSS scores',
        rationale: 'Some vulnerabilities have high probability of active exploitation.',
      });
    }

    // Maintenance risk
    if (components.maintenance?.score >= 70) {
      recs.push({
        priority: 'HIGH',
        action: 'Evaluate maintenance status — project may be abandoned',
        rationale: `High maintenance risk (${components.maintenance.score}/100). Consider active alternatives.`,
      });
    } else if (components.maintenance?.score >= 45) {
      recs.push({
        priority: 'MEDIUM',
        action: 'Monitor project activity for signs of declining maintenance',
        rationale: 'Moderate maintenance concerns. Set up alerts for project inactivity.',
      });
    }

    // Health risk
    if (components.health?.score >= 60) {
      recs.push({
        priority: 'HIGH',
        action: 'Assess project health — limited community or governance signals',
        rationale: `Health risk score is ${components.health.score}/100. Low stars, contributors, or missing governance files.`,
      });
    }

    // License risk
    if (components.license?.score >= 55) {
      recs.push({
        priority: 'HIGH',
        action: 'License review required — missing, unknown or custom license',
        rationale: 'Non-standard or absent license. Legal team should review before adoption.',
      });
    } else if (components.license?.score >= 45) {
      recs.push({
        priority: 'MEDIUM',
        action: 'Review license compatibility with your organization\'s policies',
        rationale: 'Copyleft or restrictive license detected. Ensure compliance before integration.',
      });
    }

    // Archived
    if (data.repository?.archived) {
      recs.push({
        priority: 'CRITICAL',
        action: 'Project is archived — no future security patches will be released',
        rationale: 'Archived repositories receive no updates. Migrate to an actively maintained fork.',
      });
    }

    // Single maintainer
    if (data.contributors?.count === 1) {
      recs.push({
        priority: 'MEDIUM',
        action: 'Single maintainer detected — evaluate bus factor risk',
        rationale: 'If the sole maintainer becomes unavailable, the project has no backup.',
      });
    }

    // No security policy
    if (data.community && !data.community.hasSecurityPolicy) {
      recs.push({
        priority: 'LOW',
        action: 'No security policy found — vulnerability reporting process is unclear',
        rationale: 'Projects without SECURITY.md may have slower vulnerability response.',
      });
    }

    return recs;
  }

  // ---- Shared Utility Functions ----

  _riskScoreToLevel(score) {
    if (score >= 80) return 'CRITICAL';
    if (score >= 60) return 'HIGH';
    if (score >= 35) return 'MEDIUM';
    if (score >= 20) return 'LOW';
    return 'MINIMAL';
  }

  _riskScoreToDecision(score) {
    if (score >= 80) return 'REJECT';
    if (score >= 60) return 'REVIEW_REQUIRED';
    if (score >= 35) return 'APPROVE_WITH_CONDITIONS';
    return 'APPROVE';
  }

  /** Confidence = share of total weight that had real data, capped by the legacy signal. */
  _componentConfidence(components, legacy) {
    const all = Object.values(components);
    const total = all.reduce((a, c) => a + c.weight, 0);
    const have = all.filter((c) => c.available !== false).reduce((a, c) => a + c.weight, 0);
    const score = Math.min(Math.round((have / total) * 100), legacy.score);
    return { score, level: score >= 80 ? 'HIGH' : score >= 50 ? 'MEDIUM' : 'LOW' };
  }

  _calculateConfidence(data) {
    let factors = 0;
    let available = 0;

    factors++; if (data.repository) available++;
    factors++; if (data.healthScore) available++;
    factors++; if (data.vulnerabilities?.length !== undefined) available++;
    factors++; if (data.commits) available++;
    factors++; if (data.releases) available++;
    factors++; if (data.community) available++;
    factors++; if (data.contributors) available++;

    const confidence = Math.round((available / factors) * 100);
    return {
      score: confidence,
      level: confidence >= 80 ? 'HIGH' : confidence >= 50 ? 'MEDIUM' : 'LOW',
    };
  }

  _calculateFreewareConfidence(data) {
    let factors = 0;
    let available = 0;

    factors++;
    if (data.virusTotal && data.virusTotal.status === 'completed') available++;
    factors++;
    if (data.hybridAnalysis && data.hybridAnalysis.status === 'found') available++;
    factors++;
    if (data.domainReputation && data.domainReputation.status === 'completed') available++;

    const confidence = Math.round((available / factors) * 100);
    return {
      score: confidence,
      level: confidence >= 66 ? 'HIGH' : confidence >= 33 ? 'MEDIUM' : 'LOW',
    };
  }
}

module.exports = ScorerService;
