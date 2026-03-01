// ─── Auth & Billing Middleware ───
// Three tiers: free (IP rate limit) | API key (unlimited) | x402 (pay-per-call)

import crypto from 'crypto';
import { readFileSync, writeFileSync, existsSync, mkdirSync, renameSync } from 'fs';
import { dirname } from 'path';

// ─── Config ───
const FREE_LIMIT = parseInt(process.env.FREE_DAILY_LIMIT, 10) || 10;
const X402_PRICE_USD = parseFloat(process.env.X402_PRICE_USD) || 0.005;
const X402_RECEIVER = process.env.X402_RECEIVER || '0x087ae921CE8d07a4dE6BdacAceD475e9080B2aDF';
const KEYS_FILE = process.env.KEYS_FILE || './data/api-keys.json';

// ─── Persistent key storage ───
let keyStore = {}; // { key: { customerId, subscriptionId, email, createdAt, active } }

function loadKeys() {
  try {
    if (existsSync(KEYS_FILE)) {
      keyStore = JSON.parse(readFileSync(KEYS_FILE, 'utf-8'));
    }
  } catch (e) {
    console.error('[auth] Failed to load keys:', e.message);
  }
}

function saveKeys() {
  try {
    const dir = dirname(KEYS_FILE);
    if (dir && dir !== '.' && !existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
    // Atomic write: write to temp file then rename
    const tmp = KEYS_FILE + '.tmp';
    writeFileSync(tmp, JSON.stringify(keyStore, null, 2));
    renameSync(tmp, KEYS_FILE);
  } catch (e) {
    console.error('[auth] Failed to save keys:', e.message);
  }
}

// Load on startup
loadKeys();

// Also load CSV keys from env (for manually provisioned keys)
const envKeys = (process.env.API_KEYS || '').split(',').map(k => k.trim()).filter(Boolean);
for (const k of envKeys) {
  if (!keyStore[k]) {
    keyStore[k] = { customerId: null, subscriptionId: null, email: 'manual', createdAt: new Date().toISOString(), active: true };
  }
}

export function addApiKey(key, meta = {}) {
  keyStore[key] = {
    customerId: meta.customerId || null,
    subscriptionId: meta.subscriptionId || null,
    email: meta.email || 'unknown',
    createdAt: new Date().toISOString(),
    ...meta,
    active: true, // always force active — never allow override from meta
  };
  saveKeys();
}

export function revokeBySubscription(subscriptionId) {
  let revoked = 0;
  for (const [key, meta] of Object.entries(keyStore)) {
    if (meta.subscriptionId === subscriptionId && meta.active) {
      keyStore[key].active = false;
      keyStore[key].revokedAt = new Date().toISOString();
      revoked++;
    }
  }
  if (revoked > 0) saveKeys();
  return revoked;
}

export function revokeByCustomer(customerId) {
  let revoked = 0;
  for (const [key, meta] of Object.entries(keyStore)) {
    if (meta.customerId === customerId && meta.active) {
      keyStore[key].active = false;
      keyStore[key].revokedAt = new Date().toISOString();
      revoked++;
    }
  }
  if (revoked > 0) saveKeys();
  return revoked;
}

export function generateApiKey(meta = {}) {
  const key = `mcp_${crypto.randomBytes(24).toString('base64url')}`;
  addApiKey(key, meta);
  return key;
}

export function isValidKey(key) {
  return keyStore[key]?.active === true;
}

export function getKeyStats() {
  const keys = Object.values(keyStore);
  return {
    total: keys.length,
    active: keys.filter(k => k.active).length,
    revoked: keys.filter(k => !k.active).length,
  };
}

// ─── In-memory stores (reset daily) ───
const ipCounts = new Map();
let lastReset = Date.now();

function resetIfNeeded() {
  const now = Date.now();
  if (now - lastReset > 86400000) {
    ipCounts.clear();
    lastReset = now;
  }
}

// ─── x402 payment verification ───
const verifiedTxHashes = new Set();

function verifyX402(req) {
  const paymentHeader = req.headers['x-payment'];
  if (!paymentHeader) return false;

  try {
    const payment = JSON.parse(Buffer.from(paymentHeader, 'base64').toString());

    if (payment.receiver?.toLowerCase() !== X402_RECEIVER.toLowerCase()) return false;
    if (parseFloat(payment.amount) < X402_PRICE_USD) return false;
    if (!payment.txHash || typeof payment.txHash !== 'string') return false;
    if (!/^0x[a-fA-F0-9]{64}$/.test(payment.txHash)) return false;
    if (verifiedTxHashes.has(payment.txHash.toLowerCase())) return false;
    
    verifiedTxHashes.add(payment.txHash.toLowerCase());

    // Cap replay set size (prevent memory leak)
    if (verifiedTxHashes.size > 100000) {
      const first = verifiedTxHashes.values().next().value;
      verifiedTxHashes.delete(first);
    }

    return true;
  } catch {
    return false;
  }
}

// ─── Request logging ───
const requestLog = { free: 0, apikey: 0, x402: 0, blocked: 0 };

export function getRequestLog() {
  return { ...requestLog };
}

// ─── Middleware ───
export function authMiddleware(req, res, next) {
  // Skip health
  if (req.path === '/health') return next();
  // Skip MCP SSE
  if (req.path.startsWith('/mcp/')) return next();
  // Skip billing routes (handled separately)
  if (req.path.startsWith('/billing/')) return next();
  // Skip static files (served from public/ at root by express.static)
  if (req.path === '/' || req.path === '/robots.txt' || req.path === '/sitemap.xml' || req.path === '/llms.txt' || req.path === '/llms-full.txt' || req.path === '/index.html') return next();

  // 1. Check x402 payment
  if (req.headers['x-payment']) {
    if (verifyX402(req)) {
      req.authTier = 'x402';
      requestLog.x402++;
      return next();
    }
    requestLog.blocked++;
    return res.status(402).json({
      error: 'Payment required',
      x402: {
        version: '1',
        price: X402_PRICE_USD,
        currency: 'USD',
        receiver: X402_RECEIVER,
        networks: ['base', 'celo'],
        accepts: ['USDC', 'USDT'],
        description: 'Pay per API call with stablecoins'
      }
    });
  }

  // 2. Check API key
  const apiKey = req.headers['x-api-key'] || req.query.apikey;
  if (apiKey) {
    if (isValidKey(apiKey)) {
      req.authTier = 'apikey';
      requestLog.apikey++;
      return next();
    }
    requestLog.blocked++;
    return res.status(401).json({ error: 'Invalid or revoked API key' });
  }

  // 3. Free tier — IP rate limit
  resetIfNeeded();
  const ip = req.ip; // trust proxy is configured in server.js
  const count = (ipCounts.get(ip) || 0) + 1;
  ipCounts.set(ip, count);

  if (count > FREE_LIMIT) {
    requestLog.blocked++;
    return res.status(429).json({
      error: 'Daily free limit reached',
      limit: FREE_LIMIT,
      upgrade: {
        stripe: 'POST /billing/checkout for unlimited API key ($9/mo)',
        x402: {
          price: X402_PRICE_USD,
          currency: 'USD',
          receiver: X402_RECEIVER,
          networks: ['base', 'celo'],
          accepts: ['USDC', 'USDT']
        }
      }
    });
  }

  req.authTier = 'free';
  requestLog.free++;
  res.setHeader('X-RateLimit-Limit', FREE_LIMIT);
  res.setHeader('X-RateLimit-Remaining', Math.max(0, FREE_LIMIT - count));
  next();
}

// ─── Admin endpoints ───
export function adminRoutes(app) {
  const ADMIN_SECRET = process.env.ADMIN_SECRET;

  function checkAdminAuth(req) {
    if (!ADMIN_SECRET) return false;
    const provided = req.headers['x-admin-secret'];
    if (!provided || typeof provided !== 'string') return false;
    const a = Buffer.from(provided);
    const b = Buffer.from(ADMIN_SECRET);
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  }

  app.post('/admin/keys', (req, res) => {
    if (!checkAdminAuth(req)) return res.status(401).json({ error: 'Unauthorized' });
    const key = generateApiKey({ email: req.body?.email || 'admin-generated' });
    res.json({ key, note: 'Store this key — it cannot be retrieved later' });
  });

  app.post('/admin/revoke', (req, res) => {
    if (!checkAdminAuth(req)) return res.status(401).json({ error: 'Unauthorized' });
    const { key, subscriptionId, customerId } = req.body || {};
    let revoked = 0;
    if (key && keyStore[key]) {
      keyStore[key].active = false;
      keyStore[key].revokedAt = new Date().toISOString();
      saveKeys();
      revoked = 1;
    } else if (subscriptionId) {
      revoked = revokeBySubscription(subscriptionId);
    } else if (customerId) {
      revoked = revokeByCustomer(customerId);
    }
    res.json({ revoked });
  });

  app.get('/admin/stats', (req, res) => {
    if (!checkAdminAuth(req)) return res.status(401).json({ error: 'Unauthorized' });
    resetIfNeeded();
    res.json({
      freeUsers: ipCounts.size,
      totalFreeRequests: [...ipCounts.values()].reduce((a, b) => a + b, 0),
      keys: getKeyStats(),
      requests: getRequestLog(),
      freeLimit: FREE_LIMIT,
      x402Price: X402_PRICE_USD,
    });
  });
}
