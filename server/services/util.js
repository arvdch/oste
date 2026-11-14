/**
 * OSTE - shared helpers: persistent disk cache, rate limiter, retrying GET/POST.
 * Keeps us inside free-tier API limits (GitHub 60/h anon, NVD 5/30s, VT 4/min, Groq 8k TPM).
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const CACHE_DIR = path.join(__dirname, '..', '..', '.cache');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function _file(key) {
  return path.join(CACHE_DIR, crypto.createHash('sha1').update(key).digest('hex') + '.json');
}

const cache = {
  get(key, ttlMs) {
    if (process.env.OSTE_NO_CACHE) return undefined;
    try {
      const f = _file(key);
      const st = fs.statSync(f);
      if (Date.now() - st.mtimeMs > ttlMs) return undefined;
      return JSON.parse(fs.readFileSync(f, 'utf8')).v;
    } catch {
      return undefined;
    }
  },
  set(key, value) {
    try {
      fs.mkdirSync(CACHE_DIR, { recursive: true });
      fs.writeFileSync(_file(key), JSON.stringify({ k: key, v: value }));
    } catch { /* cache is best effort */ }
  },
};

/** Delete cache files older than maxAgeMs (best effort). */
function pruneCache(maxAgeMs) {
  try {
    const now = Date.now();
    for (const f of fs.readdirSync(CACHE_DIR)) {
      const fp = path.join(CACHE_DIR, f);
      if (now - fs.statSync(fp).mtimeMs > maxAgeMs) fs.unlinkSync(fp);
    }
  } catch { /* no cache yet */ }
}

/** Serial rate limiter: guarantees >= minGapMs between calls (shared per instance). */
class RateLimiter {
  constructor(minGapMs) {
    this.minGapMs = minGapMs;
    this.chain = Promise.resolve();
    this.last = 0;
  }
  schedule(fn) {
    const run = async () => {
      const wait = this.last + this.minGapMs - Date.now();
      if (wait > 0) await sleep(wait);
      this.last = Date.now();
      return fn();
    };
    const p = this.chain.then(run, run);
    this.chain = p.catch(() => {});
    return p;
  }
}

/** Retry wrapper honoring Retry-After on 429/503 (and 403 when rate limit is reported). */
async function withRetry(fn, { retries = 3, baseMs = 2000, label = 'request', isRetryable } = {}) {
  let attempt = 0;
  for (;;) {
    try {
      return await fn();
    } catch (err) {
      const status = err.response?.status;
      const retryable = isRetryable ? isRetryable(err) : (status === 429 || status === 503 || status === 502 || status === 504 || !status);
      if (!retryable || attempt >= retries) throw err;
      const ra = parseFloat(err.response?.headers?.['retry-after']);
      const wait = Number.isFinite(ra) ? ra * 1000 + 250 : baseMs * 2 ** attempt;
      attempt++;
      await sleep(Math.min(wait, 70000));
    }
  }
}

module.exports = { cache, RateLimiter, withRetry, sleep, pruneCache };
