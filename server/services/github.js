/**
 * OSTE - Open Source Tool Evaluation
 * GitHub API Service
 * 
 * Collects repository metadata, health signals, license info,
 * dependency manifests, and contributor data from GitHub.
 */

const axios = require('axios');
const { cache, withRetry } = require('./util');

class GitHubService {
  constructor(token) {
    this.token = token;
    this.rateRemaining = null;
    this.rateReset = 0;
    this.api = axios.create({
      baseURL: 'https://api.github.com',
      headers: {
        Accept: 'application/vnd.github.v3+json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      timeout: 30000,
    });
  }

  /**
   * Parse owner/repo from a GitHub URL or shorthand.
   */
  parseRepo(input) {
    // Handle full URLs
    const urlMatch = input.match(/github\.com\/([^/]+)\/([^/\s#?]+)/);
    if (urlMatch) {
      return { owner: urlMatch[1], repo: urlMatch[2].replace(/\.git$/, '') };
    }
    // Handle owner/repo format
    const parts = input.split('/');
    if (parts.length === 2) {
      return { owner: parts[0], repo: parts[1] };
    }
    return null;
  }

  /** GET from GitHub API with disk cache + rate-limit awareness. */
  async _get(url, { ttl = 6 * 3600 * 1000, optional = false } = {}) {
    const key = 'gh:' + url;
    const hit = cache.get(key, ttl);
    if (hit !== undefined) return hit;
    if (this.rateRemaining !== null && this.rateRemaining <= 1 && Date.now() < this.rateReset) {
      const e = new Error(`GitHub API rate limit exhausted (resets ${new Date(this.rateReset).toISOString()}). Set GITHUB_TOKEN for 5000 req/hr.`);
      e.response = { status: 403 };
      throw e;
    }
    try {
      const resp = await withRetry(() => this.api.get(url), {
        retries: 2,
        isRetryable: (e) => !e.response && true,
      });
      this._trackLimit(resp.headers);
      cache.set(key, resp.data);
      return resp.data;
    } catch (err) {
      if (err.response) this._trackLimit(err.response.headers);
      if (err.response?.status === 403 && this.rateRemaining === 0) {
        err.message = `GitHub API rate limit exhausted (resets ${new Date(this.rateReset).toISOString()}). Set GITHUB_TOKEN for 5000 req/hr.`;
      }
      if (optional && err.response?.status === 404) return null;
      throw err;
    }
  }

  _trackLimit(h = {}) {
    // Search has its own (smaller) bucket; only track the core REST bucket here
    if (h['x-ratelimit-resource'] && h['x-ratelimit-resource'] !== 'core') return;
    if (h['x-ratelimit-remaining'] !== undefined) {
      this.rateRemaining = parseInt(h['x-ratelimit-remaining'], 10);
      this.rateReset = parseInt(h['x-ratelimit-reset'], 10) * 1000;
    }
  }

  /** Fetch a raw file (not counted against API rate limits). Returns null when absent. */
  async _raw(owner, repo, branch, filePath, { maxBytes = 6e6 } = {}) {
    const url = `https://raw.githubusercontent.com/${owner}/${repo}/${encodeURIComponent(branch)}/${filePath}`;
    const key = 'raw:' + url;
    const hit = cache.get(key, 6 * 3600 * 1000);
    if (hit !== undefined) return hit;
    try {
      const r = await withRetry(() => axios.get(url, { timeout: 20000, responseType: 'text', transformResponse: (x) => x, maxContentLength: maxBytes }), { retries: 1 });
      cache.set(key, r.data);
      return r.data;
    } catch (err) {
      if (err.response?.status === 404) { cache.set(key, null); return null; }
      return null;
    }
  }

  /**
   * Fetch comprehensive repository data.
   * Uses 6 API calls (repo, languages, contributors, releases, commits, community) in lite mode
   * (no token) and adds issues + PRs when a token is configured. Dependency manifests
   * are read through raw.githubusercontent.com (not counted against API limits).
   */
  async analyzeRepository(input) {
    const parsed = this.parseRepo(input);
    if (!parsed) {
      throw new Error(`Cannot parse GitHub repository from input: "${input}"`);
    }

    const { owner, repo } = parsed;
    const results = {};
    const base = `/repos/${owner}/${repo}`;

    // Repo metadata first: a 404/403 here means no point in continuing.
    const r = await this._get(base);
    results.repository = {
      name: r.full_name,
      description: r.description,
      url: r.html_url,
      homepage: r.homepage,
      stars: r.stargazers_count,
      forks: r.forks_count,
      watchers: r.subscribers_count,
      openIssues: r.open_issues_count,
      size: r.size,
      language: r.language,
      license: r.license ? { key: r.license.key, name: r.license.name, spdxId: r.license.spdx_id } : null,
      defaultBranch: r.default_branch,
      archived: r.archived,
      disabled: r.disabled,
      isTemplate: r.is_template,
      isFork: r.fork,
      visibility: r.visibility,
      createdAt: r.created_at,
      updatedAt: r.updated_at,
      pushedAt: r.pushed_at,
      topics: r.topics || [],
      hasWiki: r.has_wiki,
      hasPages: r.has_pages,
      hasDiscussions: r.has_discussions,
    };
    results.liteMode = !this.token;
    const branch = r.default_branch || 'main';

    const calls = [
      this._get(`${base}/languages`),
      this._get(`${base}/contributors?per_page=30`),
      this._get(`${base}/releases?per_page=10`),
      this._get(`${base}/commits?per_page=10`),
      this._get(`${base}/community/profile`),
    ];
    if (this.token) {
      calls.push(this._get(`${base}/issues?state=closed&per_page=50`));
      calls.push(this._get(`${base}/pulls?state=closed&per_page=30`));
    }
    const [languages, contributors, releases, commits, community, issues, pullRequests] = await Promise.allSettled(calls);
    results.apiErrors = [languages, contributors, releases, commits, community]
      .map((x, i) => (x.status === 'rejected' ? ['languages', 'contributors', 'releases', 'commits', 'community'][i] + ': ' + x.reason.message : null))
      .filter(Boolean);

    if (languages.status === 'fulfilled') {
      const totalBytes = Object.values(languages.value).reduce((a, b) => a + b, 0) || 1;
      results.languages = Object.entries(languages.value).map(([lang, bytes]) => ({
        name: lang,
        bytes,
        percentage: ((bytes / totalBytes) * 100).toFixed(1),
      }));
    }

    if (contributors.status === 'fulfilled' && Array.isArray(contributors.value)) {
      results.contributors = {
        count: contributors.value.length,
        capped: contributors.value.length >= 30,
        top: contributors.value.slice(0, 10).map((c) => ({ login: c.login, contributions: c.contributions, type: c.type })),
      };
    }

    if (releases.status === 'fulfilled' && Array.isArray(releases.value)) {
      results.releases = releases.value.map((x) => ({
        name: x.name || x.tag_name,
        tag: x.tag_name,
        prerelease: x.prerelease,
        draft: x.draft,
        publishedAt: x.published_at,
        author: x.author?.login,
      }));
    }

    if (commits.status === 'fulfilled' && Array.isArray(commits.value)) {
      results.commits = {
        recent: commits.value.slice(0, 10).map((c) => ({
          sha: c.sha.substring(0, 7),
          message: c.commit.message.split('\n')[0].slice(0, 120),
          author: c.commit.author?.name,
          date: c.commit.author?.date,
        })),
        lastCommitDate: commits.value[0]?.commit?.author?.date,
      };
    }

    if (issues?.status === 'fulfilled') {
      const closed = issues.value.filter((i) => !i.pull_request && i.closed_at);
      results.issues = { totalSampled: closed.length, closed: closed.length, avgCloseTimeHours: this._avgCloseTime(closed) };
    }
    if (pullRequests?.status === 'fulfilled') {
      const merged = pullRequests.value.filter((p) => p.merged_at);
      results.pullRequests = { totalSampled: pullRequests.value.length, merged: merged.length, avgMergeTimeHours: this._avgMergeTime(merged) };
    }

    // Community profile (GitHub also counts org-level default health files)
    if (community.status === 'fulfilled' && community.value) {
      const c = community.value;
      results.community = {
        healthPercentage: c.health_percentage,
        hasCodeOfConduct: !!(c.files?.code_of_conduct || c.files?.code_of_conduct_file),
        hasContributing: !!c.files?.contributing,
        hasIssueTemplate: !!c.files?.issue_template,
        hasPullRequestTemplate: !!c.files?.pull_request_template,
        hasReadme: !!c.files?.readme,
        hasLicense: !!c.files?.license,
        hasSecurityPolicy: !!(c.files?.security || c.files?.security_policy),
        source: 'github-community-profile',
      };
    } else {
      results.community = null; // unknown: do not claim files are missing
    }

    // Dependency manifests via raw (no API quota)
    const dep = await this._fetchDependencyFiles(owner, repo, branch, results);
    results.dependencies = dep.files;
    results.selfPackage = dep.selfPackage;
    results.dependencyStats = dep.stats;

    results.healthScore = this._calculateHealthScore(results);
    return results;
  }

  /**
   * Fetch + parse dependency manifests (root of repo), preferring lockfiles for exact versions.
   * Dev-only packages are tagged type:'dev' and excluded from the vulnerability scan by OSV service.
   */
  async _fetchDependencyFiles(owner, repo, branch, results) {
    const manifests = [
      'package-lock.json', 'package.json', 'requirements.txt', 'poetry.lock', 'Pipfile.lock',
      'go.mod', 'Cargo.lock', 'Gemfile.lock', 'composer.lock', 'pom.xml', 'pyproject.toml', 'Cargo.toml',
    ];
    const contents = {};
    await Promise.all(manifests.map(async (m) => { contents[m] = await this._raw(owner, repo, branch, m); }));

    const files = [];
    const add = (file, ecosystem, packages) => { if (packages.length) files.push({ file, ecosystem, packages }); };

    let npmLocked = false;
    if (contents['package-lock.json']) {
      const pk = this._parseDependencies(contents['package-lock.json'], 'npm', 'package-lock.json');
      if (pk.length) { npmLocked = true; add('package-lock.json', 'npm', pk); }
    }
    if (contents['package.json'] && !npmLocked) add('package.json', 'npm', this._parseDependencies(contents['package.json'], 'npm', 'package.json'));
    if (contents['poetry.lock']) add('poetry.lock', 'PyPI', this._parseDependencies(contents['poetry.lock'], 'PyPI', 'poetry.lock'));
    else if (contents['Pipfile.lock']) add('Pipfile.lock', 'PyPI', this._parseDependencies(contents['Pipfile.lock'], 'PyPI', 'Pipfile.lock'));
    if (contents['requirements.txt']) add('requirements.txt', 'PyPI', this._parseDependencies(contents['requirements.txt'], 'PyPI', 'requirements.txt'));
    if (contents['go.mod']) add('go.mod', 'Go', this._parseDependencies(contents['go.mod'], 'Go', 'go.mod'));
    if (contents['Cargo.lock']) add('Cargo.lock', 'crates.io', this._parseDependencies(contents['Cargo.lock'], 'crates.io', 'Cargo.lock'));
    if (contents['Gemfile.lock']) add('Gemfile.lock', 'RubyGems', this._parseDependencies(contents['Gemfile.lock'], 'RubyGems', 'Gemfile.lock'));
    if (contents['composer.lock']) add('composer.lock', 'Packagist', this._parseDependencies(contents['composer.lock'], 'Packagist', 'composer.lock'));
    if (contents['pom.xml']) add('pom.xml', 'Maven', this._parseDependencies(contents['pom.xml'], 'Maven', 'pom.xml'));

    // Identify the project's own published package (to look up advisories for the tool itself)
    let selfPackage = null;
    try {
      if (contents['package.json']) {
        const pkg = JSON.parse(contents['package.json']);
        if (pkg.name && !pkg.private) selfPackage = { name: pkg.name, ecosystem: 'npm', version: pkg.version || null };
        else if (pkg.private || pkg.workspaces) selfPackage = await this._npmPackageForRepo(owner, repo);
      }
      if (!selfPackage && contents['go.mod']) {
        const m = contents['go.mod'].match(/^module\s+(\S+)/m);
        if (m) selfPackage = { name: m[1], ecosystem: 'Go', version: null };
      }
      if (!selfPackage && contents['Cargo.toml']) {
        const m = contents['Cargo.toml'].match(/\[package\][\s\S]*?\bname\s*=\s*"([^"]+)"/);
        if (m) selfPackage = { name: m[1], ecosystem: 'crates.io', version: null };
      }
      if (!selfPackage && contents['pyproject.toml']) {
        const m = contents['pyproject.toml'].match(/\[(?:project|tool\.poetry)\][\s\S]*?\bname\s*=\s*"([^"]+)"/);
        if (m) selfPackage = { name: m[1], ecosystem: 'PyPI', version: null };
      }
    } catch { /* ignore */ }

    const all = files.flatMap((f) => f.packages);
    const stats = {
      manifestsFound: files.map((f) => f.file),
      runtimePackages: all.filter((p) => p.type !== 'dev').length,
      devPackages: all.filter((p) => p.type === 'dev').length,
      exactVersions: all.filter((p) => p.exact).length,
    };
    return { files, selfPackage, stats };
  }

  /**
   * Monorepos usually have a private root package.json. Look for an npm package named like the
   * repo whose registry metadata points back at this GitHub repository (e.g. facebook/react -> react).
   */
  async _npmPackageForRepo(owner, repo) {
    const candidates = [...new Set([repo.toLowerCase(), repo.toLowerCase().replace(/\.js$/, '')])];
    for (const name of candidates) {
      const key = 'npmmeta:' + name;
      let meta = cache.get(key, 12 * 3600 * 1000);
      if (meta === undefined) {
        try {
          const r = await axios.get(`https://registry.npmjs.org/${encodeURIComponent(name)}/latest`, { timeout: 15000 });
          meta = { version: r.data.version, repo: (r.data.repository?.url || r.data.repository || '').toString() };
        } catch { meta = null; }
        cache.set(key, meta);
      }
      if (meta && meta.repo.toLowerCase().includes(`${owner}/${repo}`.toLowerCase())) {
        return { name, ecosystem: 'npm', version: meta.version, viaRegistry: true };
      }
    }
    return null;
  }

  /**
   * Parse dependencies from manifest content.
   * Every package: { name, version, type: 'runtime'|'dev', exact: boolean }
   */
  _parseDependencies(content, ecosystem, filename) {
    try {
      const out = [];
      if (filename === 'package-lock.json') {
        const lock = JSON.parse(content);
        if (lock.packages) {
          for (const [p, info] of Object.entries(lock.packages)) {
            if (!p || !info.version) continue;
            const name = info.name || p.split('node_modules/').pop();
            if (info.link || /^(file|git|http)/.test(info.resolved || '') && !/registry\.npmjs/.test(info.resolved || '')) continue;
            out.push({ name, version: info.version, type: info.dev || info.devOptional ? 'dev' : 'runtime', exact: true });
          }
        } else if (lock.dependencies) {
          const walk = (deps) => {
            for (const [name, info] of Object.entries(deps || {})) {
              if (info.version && /^\d/.test(info.version)) out.push({ name, version: info.version, type: info.dev ? 'dev' : 'runtime', exact: true });
              walk(info.dependencies);
            }
          };
          walk(lock.dependencies);
        }
        return this._uniq(out);
      }
      if (filename === 'package.json') {
        const pkg = JSON.parse(content);
        for (const [name, version] of Object.entries(pkg.dependencies || {})) out.push({ name, version, type: 'runtime', exact: false });
        for (const [name, version] of Object.entries(pkg.optionalDependencies || {})) out.push({ name, version, type: 'runtime', exact: false });
        for (const [name, version] of Object.entries(pkg.devDependencies || {})) out.push({ name, version, type: 'dev', exact: false });
        return out;
      }
      if (filename === 'requirements.txt') {
        for (const raw of content.split('\n')) {
          const line = raw.split('#')[0].trim();
          if (!line || line.startsWith('-')) continue;
          const m = line.match(/^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?\s*(==|>=|~=|<=|>|<|!=)?\s*([0-9][A-Za-z0-9.!+*_-]*)?/);
          if (m && m[3]) out.push({ name: m[1], version: m[3].replace(/\.\*$/, ''), spec: line.slice(m[1].length).trim(), type: 'runtime', exact: m[2] === '==' && !/\*/.test(m[3]) });
        }
        return out;
      }
      if (filename === 'poetry.lock' || filename === 'Cargo.lock') {
        const re = /\[\[package\]\]([\s\S]*?)(?=\n\[\[package\]\]|$)/g;
        let m;
        while ((m = re.exec(content))) {
          const name = m[1].match(/\bname\s*=\s*"([^"]+)"/)?.[1];
          const version = m[1].match(/\bversion\s*=\s*"([^"]+)"/)?.[1];
          const isDev = /category\s*=\s*"dev"/.test(m[1]) || /optional\s*=\s*true/.test(m[1]);
          if (name && version) out.push({ name, version, type: isDev ? 'dev' : 'runtime', exact: true });
        }
        return out;
      }
      if (filename === 'Pipfile.lock') {
        const lock = JSON.parse(content);
        for (const [section, type] of [['default', 'runtime'], ['develop', 'dev']]) {
          for (const [name, info] of Object.entries(lock[section] || {})) {
            if (info.version) out.push({ name, version: info.version.replace(/^==/, ''), type, exact: true });
          }
        }
        return out;
      }
      if (filename === 'go.mod') {
        const re = /^\s*(?:require\s+)?([\w.\-~]+\.[\w.\-~/]+)\s+(v[\w.\-+]+)(\s*\/\/\s*indirect)?/gm;
        let m;
        while ((m = re.exec(content))) out.push({ name: m[1], version: m[2].replace(/^v/, ''), type: 'runtime', exact: true });
        return out;
      }
      if (filename === 'Gemfile.lock') {
        const re = /^ {4}([A-Za-z0-9_.\-]+) \(([0-9][^)]*)\)$/gm;
        let m;
        while ((m = re.exec(content))) out.push({ name: m[1], version: m[2], type: 'runtime', exact: true });
        return out;
      }
      if (filename === 'composer.lock') {
        const lock = JSON.parse(content);
        for (const p of lock.packages || []) out.push({ name: p.name, version: String(p.version).replace(/^v/, ''), type: 'runtime', exact: true });
        for (const p of lock['packages-dev'] || []) out.push({ name: p.name, version: String(p.version).replace(/^v/, ''), type: 'dev', exact: true });
        return out;
      }
      if (filename === 'pom.xml') {
        const re = /<dependency>\s*<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>\s*<version>(\d[^<$]*)<\/version>(?:\s*<scope>([^<]+)<\/scope>)?/g;
        let m;
        while ((m = re.exec(content))) out.push({ name: `${m[1].trim()}:${m[2].trim()}`, version: m[3].trim(), type: m[4] === 'test' ? 'dev' : 'runtime', exact: true });
        return out;
      }
    } catch {
      // Parse error
    }
    return [];
  }

  _uniq(pkgs) {
    const seen = new Map();
    for (const p of pkgs) {
      const k = `${p.name}@${p.version}`;
      const prev = seen.get(k);
      if (!prev || (prev.type === 'dev' && p.type === 'runtime')) seen.set(k, p);
    }
    return [...seen.values()];
  }

  _avgCloseTime(issues) {
    if (!issues.length) return null;
    const totalMs = issues.reduce((sum, i) => {
      return sum + (new Date(i.closed_at) - new Date(i.created_at));
    }, 0);
    return Math.round(totalMs / issues.length / 3600000);
  }

  _avgMergeTime(prs) {
    if (!prs.length) return null;
    const totalMs = prs.reduce((sum, p) => {
      return sum + (new Date(p.merged_at) - new Date(p.created_at));
    }, 0);
    return Math.round(totalMs / prs.length / 3600000);
  }

  /**
   * Calculate a project health score (0-100).
   */
  _calculateHealthScore(data) {
    let score = 0;
    let maxScore = 0;

    const checks = [
      // Activity (25 pts)
      { test: () => data.commits?.lastCommitDate && (Date.now() - new Date(data.commits.lastCommitDate) < 90 * 86400000), pts: 10, label: 'Recent commits (< 90 days)' },
      { test: () => data.releases?.length > 0, pts: 8, label: 'Has releases' },
      { test: () => data.releases?.[0]?.publishedAt && (Date.now() - new Date(data.releases[0].publishedAt) < 365 * 86400000), pts: 7, label: 'Recent release (< 1 year)' },

      // Community (25 pts)
      { test: () => data.repository?.stars >= 100, pts: 5, label: '100+ stars' },
      { test: () => data.repository?.stars >= 1000, pts: 5, label: '1000+ stars' },
      { test: () => data.contributors?.count >= 5, pts: 5, label: '5+ contributors' },
      { test: () => data.contributors?.count >= 20, pts: 5, label: '20+ contributors' },
      { test: () => data.repository?.forks >= 50, pts: 5, label: '50+ forks' },

      // Governance (25 pts)
      { test: () => !!data.repository?.license, pts: 8, label: 'Has license' },
      { test: () => data.community ? data.community.hasReadme : null, pts: 4, label: 'Has README' },
      { test: () => data.community ? data.community.hasContributing : null, pts: 4, label: 'Has CONTRIBUTING' },
      { test: () => data.community ? data.community.hasSecurityPolicy : null, pts: 5, label: 'Has security policy' },
      { test: () => data.community ? data.community.hasCodeOfConduct : null, pts: 4, label: 'Has code of conduct' },

      // Maintenance (25 pts)
      { test: () => data.issues ? (data.issues.avgCloseTimeHours != null && data.issues.avgCloseTimeHours < 168) : null, pts: 8, label: 'Issues closed < 1 week avg' },
      { test: () => data.pullRequests ? (data.pullRequests.avgMergeTimeHours != null && data.pullRequests.avgMergeTimeHours < 168) : null, pts: 8, label: 'PRs merged < 1 week avg' },
      { test: () => !data.repository?.archived, pts: 5, label: 'Not archived' },
      { test: () => data.repository?.hasDiscussions, pts: 4, label: 'Has discussions' },
    ];

    const details = [];
    for (const check of checks) {
      const passed = check.test();
      if (passed === null) { details.push({ label: check.label, passed: null, points: check.pts, skipped: true }); continue; }
      maxScore += check.pts;
      if (passed) score += check.pts;
      details.push({ label: check.label, passed: !!passed, points: check.pts });
    }

    return {
      score: maxScore ? Math.round((score / maxScore) * 100) : 0,
      rawScore: score,
      maxScore,
      details,
    };
  }
}

module.exports = GitHubService;
