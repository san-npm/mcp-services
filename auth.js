// ─── Auth & Billing Middleware ───
// Three tiers: free (IP rate limit) | API key (unlimited) | x402 (pay-per-call)

import crypto from 'crypto';

// ─── Config ───
const FREE_LIMIT = parseInt(process.env.FREE_DAILY_LIMIT, 10) || 10;
const X402_PRICE_USD = parseFloat(process.env.X402_PRICE_USD) || 0.005; // $0.005 per call
const X402_RECEIVER = process.env.X402_RECEIVER || '0x3d5A8F83F825f4F36b145e1dAD72e3f35a3030aB';
const API_KEYS_CSV = process.env.API_KEYS || ''; // comma-separated valid keys

// ─── In-memory stores (reset daily) ───
const ipCounts = new Map();
let lastReset = Date.now();

function resetIfNeeded() {
  const now = Date.now();
  if (now - lastReset > 86400000) { // 24h
    ipCounts.clear();
    lastReset = now;
  }
}

// ─── API Key validation ───
const validKeys = new Set(API_KEYS_CSV.split(',').map(k => k.trim()).filter(Boolean));

export function addApiKey(key) {
  validKeys.add(key);
}

export function generateApiKey() {
  const key = `mcp_${crypto.randomBytes(24).toString('base64url')}`;
  validKeys.add(key);
  return key;
}

// ─── x402 payment verification ───
function verifyX402(req) {
  // x402 sends payment proof in X-Payment header
  // Format: base64-encoded JSON with { network, token, txHash, amount, receiver }
  const paymentHeader = req.headers['x-payment'];
  if (!paymentHeader) return false;

  try {
    const payment = JSON.parse(Buffer.from(paymentHeader, 'base64').toString());

    // Verify receiver matches
    if (payment.receiver?.toLowerCase() !== X402_RECEIVER.toLowerCase()) return false;

    // Verify minimum amount (in USD-equivalent stablecoins)
    if (parseFloat(payment.amount) < X402_PRICE_USD) return false;

    // TODO: on-chain verification of txHash
    // For now, trust the payment header (add on-chain verification later)
    return true;
  } catch {
    return false;
  }
}

// ─── Middleware ───
export function authMiddleware(req, res, next) {
  // Skip health endpoint
  if (req.path === '/health') return next();

  // Skip MCP SSE (has its own auth if needed)
  if (req.path.startsWith('/mcp/')) return next();

  // 1. Check x402 payment
  if (req.headers['x-payment']) {
    if (verifyX402(req)) {
      req.authTier = 'x402';
      return next();
    }
    return res.status(402).json({
      error: 'Payment required',
      x402: {
        version: '1',
        price: X402_PRICE_USD,
        currency: 'USD',
        receiver: X402_RECEIVER,
        network: 'celo',
        accepts: ['USDC', 'USDT', 'cUSD'],
        description: 'Pay per API call with stablecoins'
      }
    });
  }

  // 2. Check API key
  const apiKey = req.headers['x-api-key'] || req.query.apikey;
  if (apiKey) {
    if (validKeys.has(apiKey)) {
      req.authTier = 'apikey';
      return next();
    }
    return res.status(401).json({ error: 'Invalid API key' });
  }

  // 3. Free tier — IP rate limit
  resetIfNeeded();
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
  const count = (ipCounts.get(ip) || 0) + 1;
  ipCounts.set(ip, count);

  if (count > FREE_LIMIT) {
    return res.status(429).json({
      error: 'Daily free limit reached',
      limit: FREE_LIMIT,
      upgrade: {
        apikey: 'Get unlimited access with an API key — $9/mo',
        x402: {
          price: X402_PRICE_USD,
          currency: 'USD',
          receiver: X402_RECEIVER,
          network: 'celo',
          accepts: ['USDC', 'USDT', 'cUSD']
        }
      }
    });
  }

  req.authTier = 'free';
  res.setHeader('X-RateLimit-Limit', FREE_LIMIT);
  res.setHeader('X-RateLimit-Remaining', Math.max(0, FREE_LIMIT - count));
  next();
}

// ─── Admin endpoint to generate API keys ───
export function adminRoutes(app) {
  const ADMIN_SECRET = process.env.ADMIN_SECRET;

  app.post('/admin/keys', (req, res) => {
    if (!ADMIN_SECRET) return res.status(503).json({ error: 'Admin not configured' });
    if (req.headers['x-admin-secret'] !== ADMIN_SECRET) return res.status(401).json({ error: 'Unauthorized' });

    const key = generateApiKey();
    res.json({ key, note: 'Store this key — it cannot be retrieved later' });
  });

  app.get('/admin/stats', (req, res) => {
    if (!ADMIN_SECRET) return res.status(503).json({ error: 'Admin not configured' });
    if (req.headers['x-admin-secret'] !== ADMIN_SECRET) return res.status(401).json({ error: 'Unauthorized' });

    resetIfNeeded();
    res.json({
      freeUsers: ipCounts.size,
      totalFreeRequests: [...ipCounts.values()].reduce((a, b) => a + b, 0),
      apiKeysActive: validKeys.size,
      freeLimit: FREE_LIMIT,
      x402Price: X402_PRICE_USD
    });
  });
}
