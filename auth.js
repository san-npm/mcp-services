// ─── Auth & Billing Middleware ───
// Three tiers: free (IP rate limit) | API key (unlimited) | x402 (pay-per-call)

import crypto from 'crypto';
import { readFileSync, writeFileSync, existsSync, mkdirSync, renameSync } from 'fs';
import { dirname } from 'path';
import { createPublicClient, http, formatUnits } from 'viem';
import { base, celo } from 'viem/chains';

// ─── Config ───
const FREE_LIMIT = parseInt(process.env.FREE_DAILY_LIMIT, 10) || 10;
const X402_PRICE_USD = parseFloat(process.env.X402_PRICE_USD) || 0.005;
const X402_RECEIVER = process.env.X402_RECEIVER || '0x087ae921CE8d07a4dE6BdacAceD475e9080B2aDF';
const KEYS_FILE = process.env.KEYS_FILE || './data/api-keys.json';
const DEFAULT_ALLOW_APIKEY_QUERY = process.env.NODE_ENV !== 'production';
const ALLOW_APIKEY_QUERY = process.env.ALLOW_APIKEY_QUERY
  ? ['1', 'true', 'yes', 'on'].includes(process.env.ALLOW_APIKEY_QUERY.toLowerCase())
  : DEFAULT_ALLOW_APIKEY_QUERY;
const APIKEY_QUERY_DEPRECATION_MSG = 'Query API key auth via ?apikey is deprecated; use X-Api-Key header instead.';

function getApiKeyFromRequest(req) {
  const headerApiKey = req.headers['x-api-key'];
  const queryApiKey = req.query.apikey;

  if (headerApiKey) {
    return { apiKey: headerApiKey, source: 'header' };
  }

  if (!queryApiKey) {
    return { apiKey: null, source: null };
  }

  if (!ALLOW_APIKEY_QUERY) {
    return {
      apiKey: null,
      source: 'query',
      disabled: true,
      error: 'Query API key auth is disabled. Use the X-Api-Key header.',
    };
  }

  return {
    apiKey: queryApiKey,
    source: 'query',
    warning: APIKEY_QUERY_DEPRECATION_MSG,
  };
}

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

const BANNED_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

export function addApiKey(key, meta = {}) {
  if (BANNED_KEYS.has(key)) throw new Error('Invalid key name');
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
// Map of txHash -> timestamp for replay protection with TTL
const verifiedTxHashes = new Map();
const TX_HASH_TTL = 7 * 24 * 60 * 60 * 1000; // 7 days
const TX_HASH_MAX = 100000;

// RPC clients for on-chain verification (Base and Celo only, per x402 spec)
const x402Chains = {
  base: createPublicClient({ chain: base, transport: http('https://base-rpc.publicnode.com') }),
  celo: createPublicClient({ chain: celo, transport: http('https://forno.celo.org') }),
};

// Well-known stablecoin addresses on supported chains
const STABLECOIN_ADDRESSES = {
  base: {
    usdc: '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913',
    usdt: '0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2',
  },
  celo: {
    usdc: '0xcebA9300f2b948710d2653dD7B07f33A8B32118C',
    usdt: '0x48065fbBE25f71C9282ddf5e1cD6D6A887483D5e',
  },
};

function purgeExpiredTxHashes() {
  const now = Date.now();
  for (const [hash, ts] of verifiedTxHashes) {
    if (now - ts > TX_HASH_TTL) verifiedTxHashes.delete(hash);
    else break; // Map preserves insertion order; stop at first non-expired
  }
}

async function verifyX402(req) {
  const paymentHeader = req.headers['x-payment'];
  if (!paymentHeader) return false;

  try {
    const payment = JSON.parse(Buffer.from(paymentHeader, 'base64').toString());

    // Basic field validation
    if (payment.receiver?.toLowerCase() !== X402_RECEIVER.toLowerCase()) return false;
    if (parseFloat(payment.amount) < X402_PRICE_USD) return false;
    if (!payment.txHash || typeof payment.txHash !== 'string') return false;
    if (!/^0x[a-fA-F0-9]{64}$/.test(payment.txHash)) return false;

    const txHash = payment.txHash.toLowerCase();
    const network = (payment.network || '').toLowerCase();

    // Check supported network
    const client = x402Chains[network];
    if (!client) return false;

    // Replay protection — purge expired, then check
    purgeExpiredTxHashes();
    if (verifiedTxHashes.has(txHash)) return false;

    // On-chain verification — fetch the transaction receipt
    const receipt = await client.getTransactionReceipt({ hash: txHash });
    if (!receipt || receipt.status !== 'success') return false;

    // Verify the transaction sent value to our receiver address
    // Check for ERC20 Transfer events to receiver with sufficient amount
    const stablecoins = STABLECOIN_ADDRESSES[network] || {};
    const validTokens = Object.values(stablecoins).map(a => a.toLowerCase());
    const transferTopic = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'; // Transfer(address,address,uint256)

    let verified = false;
    for (const log of receipt.logs) {
      if (log.topics[0] !== transferTopic) continue;
      if (!validTokens.includes(log.address.toLowerCase())) continue;

      // Transfer event: topics[2] = to address (padded to 32 bytes)
      const toAddr = '0x' + (log.topics[2] || '').slice(26).toLowerCase();
      if (toAddr !== X402_RECEIVER.toLowerCase()) continue;

      // Decode amount (uint256) — stablecoins are 6 decimals
      const amount = BigInt(log.data);
      const amountUsd = parseFloat(formatUnits(amount, 6));
      if (amountUsd >= X402_PRICE_USD) {
        verified = true;
        break;
      }
    }

    if (!verified) return false;

    // Mark as used
    verifiedTxHashes.set(txHash, Date.now());

    // Cap size
    if (verifiedTxHashes.size > TX_HASH_MAX) {
      const first = verifiedTxHashes.keys().next().value;
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

// ─── MCP auth helper (reuses same tiers as REST) ───
export async function mcpAuth(req, { countUsage = true } = {}) {
  // 1. Check API key (prefer header; query support is deprecated and optional)
  const keyAuth = getApiKeyFromRequest(req);
  if (keyAuth.disabled) {
    requestLog.blocked++;
    return { tier: null, error: keyAuth.error };
  }

  if (keyAuth.apiKey) {
    if (isValidKey(keyAuth.apiKey)) {
      requestLog.apikey++;
      return { tier: 'apikey', apiKey: keyAuth.apiKey, warning: keyAuth.warning || null };
    }
    return { tier: null, error: 'Invalid or revoked API key' };
  }

  // 2. Check x402 payment
  if (req.headers['x-payment']) {
    if (await verifyX402(req)) {
      requestLog.x402++;
      return { tier: 'x402' };
    }
    return { tier: null, error: 'Invalid x402 payment' };
  }

  // 3. Free tier — IP rate limit
  resetIfNeeded();
  const ip = req.ip || 'unknown';

  if (countUsage) {
    const count = (ipCounts.get(ip) || 0) + 1;
    ipCounts.set(ip, count);

    if (count > FREE_LIMIT) {
      requestLog.blocked++;
      return { tier: null, error: `Daily free limit reached (${FREE_LIMIT}/day). Send X-Api-Key header for unlimited access.` };
    }

    requestLog.free++;
  } else {
    // Auth-only check (e.g. SSE handshake) — verify limit without incrementing
    const current = ipCounts.get(ip) || 0;
    if (current >= FREE_LIMIT) {
      return { tier: null, error: `Daily free limit reached (${FREE_LIMIT}/day). Send X-Api-Key header for unlimited access.` };
    }
  }

  return { tier: 'free', ip };
}

// ─── Middleware ───
export async function authMiddleware(req, res, next) {
  // Skip health
  if (req.path === '/health') return next();
  // Skip MCP SSE — auth handled in SSE handler directly
  if (req.path.startsWith("/mcp/")) return next();
  // Skip OAuth discovery
  if (req.path.startsWith("/oauth/")) return next();
  if (req.path.startsWith("/.well-known/")) return next();
  // Skip billing routes (handled separately)
  if (req.path.startsWith('/billing/')) return next();
  // Skip static files (served from public/ at root by express.static)
  if (req.path === '/' || req.path === '/robots.txt' || req.path === '/sitemap.xml' || req.path === '/llms.txt' || req.path === '/llms-full.txt' || req.path === '/index.html') return next();

  // 1. Check x402 payment
  if (req.headers['x-payment']) {
    if (await verifyX402(req)) {
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

  // 2. Check API key (prefer header; query support is deprecated and optional)
  const keyAuth = getApiKeyFromRequest(req);
  if (keyAuth.disabled) {
    requestLog.blocked++;
    return res.status(400).json({
      error: keyAuth.error,
      code: 'QUERY_APIKEY_DISABLED',
    });
  }

  if (keyAuth.warning) {
    res.setHeader('Warning', `299 - "${keyAuth.warning}"`);
    res.setHeader('Deprecation', 'true');
  }

  if (keyAuth.apiKey) {
    if (isValidKey(keyAuth.apiKey)) {
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
    if (key && BANNED_KEYS.has(key)) return res.status(400).json({ error: 'Invalid key name' });
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
