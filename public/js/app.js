/**
 * OSTE - Open Source Tool Evaluation
 * Frontend Application
 */

(function () {
  'use strict';

  // ---- State ----
  const state = {
    selectedType: 'auto',
    currentJobId: null,
    pollTimer: null,
  };

  // ---- DOM Refs ----
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => document.querySelectorAll(sel);

  const els = {
    searchInput: $('#searchInput'),
    searchBtn: $('#searchBtn'),
    btnText: $('#btnText'),
    btnSpinner: $('#btnSpinner'),
    heroSection: $('#heroSection'),
    progressSection: $('#progressSection'),
    progressTitle: $('#progressTitle'),
    progressPct: $('#progressPct'),
    progressBar: $('#progressBar'),
    progressStepText: $('#progressStepText'),
    progressSteps: $('#progressSteps'),
    errorCard: $('#errorCard'),
    errorMessage: $('#errorMessage'),
    retryBtn: $('#retryBtn'),
    resultsSection: $('#resultsSection'),
    gaugeFill: $('#gaugeFill'),
    scoreNumber: $('#scoreNumber'),
    scoreLabel: $('#scoreLabel'),
    riskTitle: $('#riskTitle'),
    riskTarget: $('#riskTarget'),
    decisionBadge: $('#decisionBadge'),
    executiveSummary: $('#executiveSummary'),
    downloadPdf: $('#downloadPdf'),
    downloadJson: $('#downloadJson'),
    newAnalysisBtn: $('#newAnalysisBtn'),
    componentScores: $('#componentScores'),
    vulnStats: $('#vulnStats'),
    vulnList: $('#vulnList'),
    vulnBadge: $('#vulnBadge'),
    infoTitle: $('#infoTitle'),
    infoGrid: $('#infoGrid'),
    cardLanguages: $('#cardLanguages'),
    langBar: $('#langBar'),
    langLegend: $('#langLegend'),
    cardHealth: $('#cardHealth'),
    healthBadge: $('#healthBadge'),
    healthList: $('#healthList'),
    recommendationsList: $('#recommendationsList'),
    apiStatus: $('#apiStatus'),
    recentSection: $('#recentSection'),
    recentList: $('#recentList'),
    dashboardGrid: $('#dashboardGrid'),
    btnHistory: $('#btnHistory'),
  };

  // ---- Language Colors ----
  const langColors = {
    JavaScript: '#f1e05a', TypeScript: '#3178c6', Python: '#3572A5',
    Java: '#b07219', Go: '#00ADD8', Rust: '#dea584', Ruby: '#701516',
    PHP: '#4F5D95', 'C++': '#f34b7d', C: '#555555', 'C#': '#178600',
    Swift: '#F05138', Kotlin: '#A97BFF', Dart: '#00B4AB', Shell: '#89e051',
    HTML: '#e34c26', CSS: '#563d7c', Scala: '#c22d40', R: '#198CE7',
    Lua: '#000080', Perl: '#0298c3', Haskell: '#5e5086', Elixir: '#6e4a7e',
    Vue: '#41b883', SCSS: '#c6538c', Dockerfile: '#384d54',
  };

  // ---- Init ----
  async function init() {
    loadApiStatus();
    loadRecentJobs();
    bindEvents();
  }

  function bindEvents() {
    // Search
    els.searchBtn.addEventListener('click', startAnalysis);
    els.searchInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') startAnalysis();
    });

    // Type selector
    $$('.type-btn').forEach((btn) => {
      btn.addEventListener('click', () => {
        $$('.type-btn').forEach((b) => b.classList.remove('active'));
        btn.classList.add('active');
        state.selectedType = btn.dataset.type;
      });
    });

    // Hint chips
    $$('.hint-chip').forEach((chip) => {
      chip.addEventListener('click', () => {
        els.searchInput.value = chip.dataset.value;
        els.searchInput.focus();
      });
    });

    // Retry
    els.retryBtn.addEventListener('click', () => {
      hideError();
      showHero();
    });

    // New analysis
    els.newAnalysisBtn.addEventListener('click', () => {
      els.searchInput.value = '';
      showHero();
    });

    // History toggle
    els.btnHistory.addEventListener('click', () => {
      loadRecentJobs();
      els.recentSection.style.display =
        els.recentSection.style.display === 'none' ? 'block' : 'none';
    });
  }

  // ---- API Status ----
  async function loadApiStatus() {
    try {
      const resp = await fetch('/api/config/status');
      const data = await resp.json();

      const services = [
        { key: 'github', label: 'GitHub' },
        { key: 'nvd', label: 'NVD' },
        { key: 'virusTotal', label: 'VirusTotal' },
        { key: 'hybridAnalysis', label: 'Hybrid Analysis' },
        { key: 'groq', label: 'Groq AI' },
      ];

      els.apiStatus.innerHTML = services
        .map(
          (s) =>
            `<div class="status-pill ${data[s.key] ? 'active' : ''}">
              <span class="dot"></span>${s.label}
            </div>`
        )
        .join('');
    } catch {
      els.apiStatus.innerHTML = '';
    }
  }

  // ---- Recent Jobs ----
  async function loadRecentJobs() {
    try {
      const resp = await fetch('/api/jobs');
      const data = await resp.json();

      if (!data.jobs || data.jobs.length === 0) {
        els.recentSection.style.display = 'none';
        return;
      }

      els.recentList.innerHTML = data.jobs
        .map(
          (j) => `
        <div class="recent-item" data-job-id="${j.id}" onclick="window.__loadJob('${j.id}')">
          <span class="ri-type">${escHtml(j.type || 'auto')}</span>
          <span class="ri-input">${escHtml(j.input)}</span>
          ${
            j.riskScore !== undefined
              ? `<span class="ri-score" style="color:${riskColor(
                  j.riskLevel
                )}">${j.riskScore}</span>`
              : ''
          }
          <span class="ri-status">${escHtml(j.status)}</span>
        </div>`
        )
        .join('');
    } catch {
      // silent
    }
  }

  // Expose for inline onclick
  window.__loadJob = async function (jobId) {
    state.currentJobId = jobId;
    showProgress();
    pollJob();
  };

  // ---- Start Analysis ----
  async function startAnalysis() {
    const input = els.searchInput.value.trim();
    if (!input) {
      els.searchInput.focus();
      return;
    }

    // Disable button
    els.searchBtn.disabled = true;
    els.btnText.textContent = 'Starting…';
    els.btnSpinner.style.display = 'block';
    hideError();

    try {
      const body = { input };
      if (state.selectedType !== 'auto') body.type = state.selectedType;

      const resp = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

      const data = await resp.json();

      if (!resp.ok || !data.success) {
        throw new Error(data.error || 'Failed to start analysis');
      }

      state.currentJobId = data.jobId;
      showProgress();
      pollJob();
    } catch (err) {
      showError(err.message);
    } finally {
      els.searchBtn.disabled = false;
      els.btnText.textContent = 'Analyze';
      els.btnSpinner.style.display = 'none';
    }
  }

  // ---- Poll Job ----
  function pollJob() {
    if (state.pollTimer) clearInterval(state.pollTimer);
    state.pollTimer = setInterval(async () => {
      try {
        const resp = await fetch(`/api/jobs/${state.currentJobId}`);
        if (resp.status === 404) {
          clearInterval(state.pollTimer);
          showError('Job not found (the server may have restarted).');
          return;
        }
        const job = await resp.json();

        updateProgress(job);

        if (job.status === 'completed') {
          clearInterval(state.pollTimer);
          renderResults(job);
        } else if (job.status === 'failed') {
          clearInterval(state.pollTimer);
          showError(job.error || 'Analysis failed.');
        }
      } catch (err) {
        console.error('Poll error:', err);
      }
    }, 1500);
  }

  // ---- Progress Updates ----
  function updateProgress(job) {
    els.progressPct.textContent = `${job.progress}%`;
    els.progressBar.style.width = `${job.progress}%`;
    els.progressStepText.textContent = job.currentStep || 'Processing…';
    els.progressTitle.textContent = `Analyzing ${job.resolvedInput ? `${job.input} → ${job.resolvedInput}` : job.input}`;

    // Completed steps
    els.progressSteps.innerHTML = (job.steps || [])
      .map((s) => {
        const ok = ['completed', 'found'].includes(s.status);
        const warn = ['fallback', 'skipped', 'not_found', 'rate_limited', 'timeout'].includes(s.status);
        const icon = ok ? '✓' : warn ? '!' : '✕';
        const extra = s.count !== undefined ? ` (${s.count})` : s.match ? ` → ${s.match}` : !ok && s.status ? ` — ${s.status}` : '';
        return `<div class="step-item completed" title="${escHtml(s.error || '')}">
            <span class="check" style="${ok ? '' : `color:${warn ? '#eab308' : '#ef4444'}`}">${icon}</span>
            <span>${escHtml(s.name)}${escHtml(extra)}</span>
          </div>`;
      })
      .join('');
  }

  // ---- Render Results ----
  function renderResults(job) {
    const result = job.result;
    if (!result) {
      showError('No results returned.');
      return;
    }

    const score = result.riskScore?.overallRiskScore ?? 0;
    const level = result.riskScore?.riskLevel || 'UNKNOWN';
    const decision = result.riskScore?.decision || 'REVIEW_REQUIRED';
    const ai = result.aiAssessment || {};

    // ---- Risk Gauge ----
    const circumference = 2 * Math.PI * 52; // ~326.73
    const offset = circumference - (score / 100) * circumference;
    els.gaugeFill.style.strokeDashoffset = offset;
    els.gaugeFill.style.stroke = riskColor(level);

    els.scoreNumber.textContent = score;
    els.scoreNumber.style.color = riskColor(level);
    els.scoreLabel.textContent = level;
    els.scoreLabel.style.color = riskColor(level);

    // Title & target
    els.riskTitle.textContent =
      result.type === 'opensource' ? 'Open Source Assessment' : 'Freeware Assessment';
    els.riskTarget.textContent = result.target;

    // Decision badge
    const decisionMap = {
      APPROVE: { cls: 'approve', icon: '✅', text: 'Approved' },
      APPROVE_WITH_CONDITIONS: { cls: 'conditions', icon: '⚠️', text: 'Approved with Conditions' },
      REVIEW_REQUIRED: { cls: 'review', icon: '🔍', text: 'Review Required' },
      REJECT: { cls: 'reject', icon: '❌', text: 'Rejected' },
    };
    const dec = decisionMap[decision] || decisionMap.REVIEW_REQUIRED;
    els.decisionBadge.className = `decision-badge ${dec.cls}`;
    els.decisionBadge.textContent = `${dec.icon} ${dec.text}`;

    // Executive summary
    const conf = result.riskScore?.confidenceLevel;
    const aiNote = ai._meta?.source === 'llm'
      ? `AI narrative: ${ai._meta.model}`
      : 'Rule-based narrative (AI unavailable)';
    els.executiveSummary.textContent =
      (ai.executiveSummary || 'AI assessment unavailable. Configure GROQ_API_KEY for detailed analysis.') +
      `\n\n${aiNote}${conf ? ` · Data confidence: ${conf.level} (${conf.score}%)` : ''}`;
    els.executiveSummary.style.whiteSpace = 'pre-line';

    // Download links
    els.downloadPdf.href = `/api/jobs/${state.currentJobId}/report/pdf`;
    els.downloadJson.href = `/api/jobs/${state.currentJobId}/report/json`;

    // ---- Component Scores ----
    const components = result.riskScore?.components || {};
    els.componentScores.innerHTML = Object.entries(components)
      .map(([key, comp]) => {
        if (comp.available === false) {
          return `
        <div class="component-row" style="opacity:0.55">
          <div class="component-label">
            <span>${escHtml(comp.label)}</span>
            <span class="score">no data <small>(excluded)</small></span>
          </div>
          <div class="component-bar"><div class="component-bar-fill" style="width:0%"></div></div>
        </div>`;
        }
        const compLevel = scoreToLevel(comp.score);
        return `
        <div class="component-row">
          <div class="component-label">
            <span>${escHtml(comp.label)}</span>
            <span class="score" style="color:${riskColor(compLevel)}">${comp.score}/100 <small>(${Math.round((comp.effectiveWeight ?? comp.weight) * 100)}%)</small></span>
          </div>
          <div class="component-bar">
            <div class="component-bar-fill" style="width:${comp.score}%;background:${riskColor(compLevel)}"></div>
          </div>
        </div>`;
      })
      .join('');

    // ---- Vulnerability Stats ----
    const data = result.data || {};
    els.vulnBadge.style.display = 'none';
    if (result.type === 'opensource') {
      const vs = data.vulnerabilitySummary || {};
      els.vulnStats.innerHTML = `
        <div class="vuln-stat critical"><div class="count">${vs.CRITICAL || 0}</div><div class="label">Critical</div></div>
        <div class="vuln-stat high"><div class="count">${vs.HIGH || 0}</div><div class="label">High</div></div>
        <div class="vuln-stat medium"><div class="count">${vs.MEDIUM || 0}</div><div class="label">Medium</div></div>
        <div class="vuln-stat low"><div class="count">${vs.LOW || 0}</div><div class="label">Low</div></div>
      `;

      const totalVulns = vs.total || 0;
      const sa = data.selfAdvisories;
      if (totalVulns > 0) {
        els.vulnBadge.style.display = 'inline';
        els.vulnBadge.textContent = totalVulns;
        els.vulnBadge.style.background = riskBg(level);
        els.vulnBadge.style.color = riskColor(level);
      }

      // Vuln list
      const topVulns = data.topVulnerabilities || [];
      els.vulnList.innerHTML = topVulns.length
        ? topVulns
            .map(
              (v) => `
          <div class="vuln-item">
            <span class="vuln-severity ${(v.severity || 'unknown').toLowerCase()}">${v.severity || '?'}</span>
            <div class="vuln-details">
              <div class="vuln-id">${escHtml(v.id)}</div>
              <div class="vuln-desc">${escHtml(v.summary || v.details || 'No description')}</div>
              <div class="vuln-meta">
                ${v.cvssScore ? `<span>CVSS: ${v.cvssScore}</span>` : ''}
                ${v.epss?.score ? `<span class="epss-badge">EPSS: ${(v.epss.score * 100).toFixed(1)}%</span>` : ''}
                ${v.affectedPackage ? `<span>📦 ${escHtml(v.affectedPackage)}</span>` : ''}
              </div>
            </div>
          </div>`
            )
            .join('')
        : `<div style="color:var(--text-muted);font-size:0.82rem;padding:12px;">${
            (vs.totalPackages || 0) > 0 || sa
              ? 'No known vulnerabilities in scanned dependencies.'
              : 'No supported dependency manifest found — vulnerability exposure could not be assessed.'
          }</div>`;
      if (sa && sa.found) {
        els.vulnList.innerHTML += `<div style="color:var(--text-muted);font-size:0.78rem;padding:8px 12px;">
          Package <b>${escHtml(sa.package)}</b>${sa.version ? '@' + escHtml(sa.version) : ''} (${escHtml(sa.ecosystem)}):
          ${sa.current?.length || 0} advisories affect this version · ${sa.historicalCount} all-time advisories.</div>`;
      }
    } else {
      // Freeware vuln stats
      const vt = data.virusTotal || {};
      els.vulnStats.innerHTML = `
        <div class="vuln-stat critical"><div class="count">${vt.malicious || 0}</div><div class="label">Malicious</div></div>
        <div class="vuln-stat high"><div class="count">${vt.suspicious || 0}</div><div class="label">Suspicious</div></div>
        <div class="vuln-stat medium"><div class="count">${vt.harmless || 0}</div><div class="label">Harmless</div></div>
        <div class="vuln-stat low"><div class="count">${vt.undetected || 0}</div><div class="label">Undetected</div></div>
      `;

      // Detection names
      const detections = vt.detectionNames || [];
      els.vulnList.innerHTML = detections.length
        ? detections
            .map(
              (d) => `
          <div class="vuln-item">
            <span class="vuln-severity ${d.category === 'malicious' ? 'critical' : 'medium'}">${d.category}</span>
            <div class="vuln-details">
              <div class="vuln-id">${escHtml(d.engine)}</div>
              <div class="vuln-desc">${escHtml(d.result || 'Detected')}</div>
            </div>
          </div>`
            )
            .join('')
        : '<div style="color:var(--text-muted);font-size:0.82rem;padding:12px;">No detections.</div>';
    }

    // ---- Project/Tool Info ----
    if (result.type === 'opensource') {
      const repo = data.repository || {};
      els.infoTitle.textContent = 'Project Info';
      els.infoGrid.innerHTML = `
        <div class="info-item"><div class="label">Stars</div><div class="value">${formatNum(repo.stars)}</div></div>
        <div class="info-item"><div class="label">Forks</div><div class="value">${formatNum(repo.forks)}</div></div>
        <div class="info-item"><div class="label">Watchers</div><div class="value">${formatNum(repo.watchers)}</div></div>
        <div class="info-item"><div class="label">Open Issues</div><div class="value">${formatNum(repo.openIssues)}</div></div>
        <div class="info-item"><div class="label">License</div><div class="value">${escHtml(repo.license?.name || 'None')}</div></div>
        <div class="info-item"><div class="label">Language</div><div class="value">${escHtml(repo.language || '—')}</div></div>
        <div class="info-item"><div class="label">Created</div><div class="value">${formatDate(repo.createdAt)}</div></div>
        <div class="info-item"><div class="label">Last Push</div><div class="value">${formatDate(repo.pushedAt)}</div></div>
      `;

      // Languages
      if (data.languages?.length) {
        els.cardLanguages.style.display = 'block';
        els.langBar.innerHTML = data.languages
          .map(
            (l) =>
              `<div class="lang-segment" style="width:${l.percentage}%;background:${langColors[l.name] || '#6b7280'}" title="${escHtml(l.name)}: ${l.percentage}%"></div>`
          )
          .join('');
        els.langLegend.innerHTML = data.languages
          .map(
            (l) =>
              `<div class="lang-legend-item"><span class="lang-dot" style="background:${langColors[l.name] || '#6b7280'}"></span>${escHtml(l.name)} ${l.percentage}%</div>`
          )
          .join('');
      } else {
        els.cardLanguages.style.display = 'none';
      }

      // Health checks
      if (data.healthScore?.details) {
        els.cardHealth.style.display = 'block';
        els.healthBadge.textContent = `${data.healthScore.score}/100`;
        els.healthBadge.style.background = riskBg(scoreToLevel(100 - data.healthScore.score));
        els.healthBadge.style.color = riskColor(scoreToLevel(100 - data.healthScore.score));
        els.healthList.innerHTML = data.healthScore.details
          .filter((d) => d.passed !== null)
          .map(
            (d) =>
              `<div class="health-item ${d.passed ? 'pass' : 'fail'}">
                <span class="icon">${d.passed ? '✅' : '❌'}</span>
                <span>${escHtml(d.label)}</span>
              </div>`
          )
          .join('');
      } else {
        els.cardHealth.style.display = 'none';
      }
    } else {
      // Freeware info
      const vt = data.virusTotal || {};
      const ha = data.hybridAnalysis?.primary || {};
      els.infoTitle.textContent = 'Tool Info';
      els.infoGrid.innerHTML = `
        <div class="info-item"><div class="label">File</div><div class="value">${escHtml(vt.name || ha.fileName || '—')}</div></div>
        <div class="info-item"><div class="label">Type</div><div class="value">${escHtml(vt.fileType || ha.fileType || '—')}</div></div>
        <div class="info-item"><div class="label">Size</div><div class="value">${vt.size ? formatBytes(vt.size) : '—'}</div></div>
        <div class="info-item"><div class="label">VT Status</div><div class="value">${escHtml(vt.riskLevel || vt.status || '—')}</div></div>
        <div class="info-item"><div class="label">HA Verdict</div><div class="value">${escHtml(ha.verdict || '—')}</div></div>
        <div class="info-item"><div class="label">Threat Score</div><div class="value">${ha.threatScore ?? '—'}</div></div>
      `;
      els.cardLanguages.style.display = 'none';
      els.cardHealth.style.display = 'none';
    }

    // ---- Recommendations ----
    const recs = [].concat(ai.recommendations || result.riskScore?.recommendations || [])
      .map((r) => (typeof r === 'string' ? { priority: 'MEDIUM', action: r } : r || {}));
    els.recommendationsList.innerHTML = recs.length
      ? recs
          .map(
            (r) => `
        <div class="rec-item ${String(r.priority || 'medium').toLowerCase().replace(/[^a-z]/g, '')}">
          <div class="rec-action">[${escHtml(r.priority || 'INFO')}] ${escHtml(r.action || '')}</div>
          <div class="rec-rationale">${escHtml(r.rationale || '')}</div>
        </div>`
          )
          .join('')
      : '<div style="color:var(--text-muted);font-size:0.82rem;">No recommendations available.</div>';

    // Show results
    showResults();
    loadRecentJobs();
  }

  // ---- View State Helpers ----
  function showHero() {
    els.heroSection.style.display = 'block';
    els.progressSection.classList.remove('visible');
    els.resultsSection.classList.remove('visible');
    els.errorCard.classList.remove('visible');
    if (state.pollTimer) clearInterval(state.pollTimer);
  }

  function showProgress() {
    els.heroSection.style.display = 'none';
    els.progressSection.classList.add('visible');
    els.resultsSection.classList.remove('visible');
    els.errorCard.classList.remove('visible');
    // Reset progress
    els.progressPct.textContent = '0%';
    els.progressBar.style.width = '0%';
    els.progressSteps.innerHTML = '';
  }

  function showResults() {
    els.heroSection.style.display = 'none';
    els.progressSection.classList.remove('visible');
    els.resultsSection.classList.add('visible');
    els.errorCard.classList.remove('visible');
  }

  function showError(msg) {
    els.heroSection.style.display = 'none';
    els.progressSection.classList.remove('visible');
    els.resultsSection.classList.remove('visible');
    els.errorCard.classList.add('visible');
    els.errorMessage.textContent = msg;
    if (state.pollTimer) clearInterval(state.pollTimer);
  }

  function hideError() {
    els.errorCard.classList.remove('visible');
  }

  // ---- Utility ----
  function riskColor(level) {
    const map = {
      CRITICAL: '#ef4444',
      HIGH: '#f97316',
      MEDIUM: '#eab308',
      LOW: '#3b82f6',
      MINIMAL: '#10b981',
      CLEAN: '#10b981',
    };
    return map[level] || '#6b7280';
  }

  function riskBg(level) {
    const map = {
      CRITICAL: 'rgba(239,68,68,0.12)',
      HIGH: 'rgba(249,115,22,0.12)',
      MEDIUM: 'rgba(234,179,8,0.12)',
      LOW: 'rgba(59,130,246,0.12)',
      MINIMAL: 'rgba(16,185,129,0.12)',
    };
    return map[level] || 'rgba(107,114,128,0.12)';
  }

  function scoreToLevel(score) {
    if (score >= 80) return 'CRITICAL';
    if (score >= 60) return 'HIGH';
    if (score >= 35) return 'MEDIUM';
    if (score >= 20) return 'LOW';
    return 'MINIMAL';
  }

  function escHtml(str) {
    if (str === undefined || str === null) return '';
    str = String(str);
    const el = document.createElement('span');
    el.textContent = str;
    return el.innerHTML;
  }

  function formatNum(n) {
    if (n === undefined || n === null) return '—';
    return n.toLocaleString();
  }

  function formatDate(dateStr) {
    if (!dateStr) return '—';
    return new Date(dateStr).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  }

  function formatBytes(bytes) {
    if (!bytes) return '—';
    const units = ['B', 'KB', 'MB', 'GB'];
    let i = 0;
    let b = bytes;
    while (b >= 1024 && i < units.length - 1) {
      b /= 1024;
      i++;
    }
    return `${b.toFixed(1)} ${units[i]}`;
  }

  // ---- Boot ----
  document.addEventListener('DOMContentLoaded', init);
})();
