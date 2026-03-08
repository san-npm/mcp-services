// ─── Stripe Billing ───
// $9/mo subscription → unlimited API key

import Stripe from 'stripe';
import crypto from 'crypto';
import { generateApiKey, revokeBySubscription, revokeByCustomer } from './auth.js';
import express from 'express';
import { getClientIp } from './ip.js';
import { checkAndMaybeIncrement } from './rate-store.js';

let stripe = null;
function getStripe() {
  if (!stripe) {
    if (!process.env.STRIPE_SK) throw new Error('STRIPE_SK not configured');
    stripe = new Stripe(process.env.STRIPE_SK);
  }
  return stripe;
}
const PRICE_MONTHLY = 900; // $9.00 in cents
const DOMAIN = process.env.DOMAIN || 'https://mcp.skills.ws';
const CHECKOUT_LIMIT_PER_HOUR = Math.max(1, parseInt(process.env.CHECKOUT_LIMIT_PER_HOUR || '5', 10));
const CHECKOUT_LIMIT_WINDOW_MS = 60 * 60 * 1000;
const STRIPE_WEBHOOK_IP_ALLOWLIST = (process.env.STRIPE_WEBHOOK_IP_ALLOWLIST || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

let priceId = null;

// ─── Initialize Stripe product + price ───
async function ensureProduct() {
  if (priceId) return priceId;

  // Search by metadata — iterate all pages
  let product = null;
  for await (const p of getStripe().products.list({ active: true, limit: 100 })) {
    if (p.metadata?.type === 'mcp-api-key') { product = p; break; }
  }

  if (!product) {
    product = await getStripe().products.create({
      name: 'MCP Services — API Key',
      description: 'Unlimited API access to mcp.skills.ws (screenshot, WHOIS, DNS, SSL, OCR, blockchain)',
      metadata: { type: 'mcp-api-key' }
    });
  }

  const prices = await getStripe().prices.list({ product: product.id, active: true, limit: 1 });
  if (prices.data.length > 0) {
    priceId = prices.data[0].id;
  } else {
    const price = await getStripe().prices.create({
      product: product.id,
      unit_amount: PRICE_MONTHLY,
      currency: 'usd',
      recurring: { interval: 'month' }
    });
    priceId = price.id;
  }

  return priceId;
}

// ─── Rate limit checkout creation ───
async function checkCheckoutRate(ip) {
  const key = `checkout:${ip}`;
  const rate = await checkAndMaybeIncrement(key, CHECKOUT_LIMIT_PER_HOUR, CHECKOUT_LIMIT_WINDOW_MS, true);
  return rate.allowed;
}

function isAllowedWebhookIp(ip) {
  if (!STRIPE_WEBHOOK_IP_ALLOWLIST.length) return true;
  return STRIPE_WEBHOOK_IP_ALLOWLIST.includes(ip);
}

// ─── Routes ───
export function stripeRoutes(app) {

  // IMPORTANT: Webhook needs raw body for signature verification
  // Must be registered BEFORE express.json() or with its own raw parser
  app.post('/billing/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    const webhookIp = getClientIp(req);
    if (!isAllowedWebhookIp(webhookIp)) {
      console.warn('[stripe] webhook blocked by IP allowlist:', webhookIp);
      return res.status(403).send('Forbidden');
    }

    const sig = req.headers['stripe-signature'];
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

    if (!webhookSecret) {
      console.error('[stripe] STRIPE_WEBHOOK_SECRET not configured — rejecting webhook');
      return res.status(500).send('Webhook not configured');
    }

    let event;
    try {
      event = getStripe().webhooks.constructEvent(req.body, sig, webhookSecret);
    } catch (err) {
      console.error('[stripe] webhook sig error:', err.message);
      return res.status(400).send('Invalid signature');
    }

    console.log(`[stripe] webhook event: ${event.type}`);

    switch (event.type) {
      case 'customer.subscription.deleted': {
        const sub = event.data.object;
        const revoked = revokeBySubscription(sub.id);
        console.log(`[stripe] Subscription ${sub.id} cancelled — revoked ${revoked} key(s)`);
        break;
      }
      case 'customer.subscription.paused': {
        const sub = event.data.object;
        const revoked = revokeBySubscription(sub.id);
        console.log(`[stripe] Subscription ${sub.id} paused — revoked ${revoked} key(s)`);
        break;
      }
      case 'invoice.payment_failed': {
        const invoice = event.data.object;
        console.log(`[stripe] Payment failed for customer ${invoice.customer}`);
        // Don't revoke immediately — Stripe retries. Revoke on subscription.deleted
        break;
      }
      case 'invoice.payment_succeeded': {
        const invoice = event.data.object;
        console.log(`[stripe] Payment received: ${invoice.id} ($${(invoice.amount_paid / 100).toFixed(2)})`);
        break;
      }
      default:
        break;
    }

    res.status(200).send('ok');
  });

  // Create checkout session (rate limited)
  app.post('/billing/checkout', async (req, res) => {
    const ip = getClientIp(req);
    if (!await checkCheckoutRate(ip)) {
      return res.status(429).json({ error: 'Too many checkout attempts. Try again later.' });
    }

    try {
      const pid = await ensureProduct();
      const session = await getStripe().checkout.sessions.create({
        mode: 'subscription',
        payment_method_types: ['card'],
        line_items: [{ price: pid, quantity: 1 }],
        billing_address_collection: 'auto',
        success_url: `${DOMAIN}/billing/success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${DOMAIN}/billing/cancel`,
        metadata: { purpose: 'mcp-api-key' },
      });
      res.json({ url: session.url });
    } catch (err) {
      console.error('[stripe] checkout error:', err.message);
      res.status(500).json({ error: 'Failed to create checkout session' });
    }
  });

  // Success — provision API key (one-time retrieval)
  const usedSessions = new Set();

  app.get('/billing/success', async (req, res) => {
    const { session_id } = req.query;
    if (!session_id || typeof session_id !== 'string' || session_id.length > 200) {
      return res.status(400).json({ error: 'Invalid session_id' });
    }

    // Prevent replay — each session_id can only provision once via this endpoint
    if (usedSessions.has(session_id)) {
      return res.json({
        status: 'already_provisioned',
        note: 'API key was already delivered. If you lost it, contact support.'
      });
    }

    try {
      const session = await getStripe().checkout.sessions.retrieve(session_id, {
        expand: ['subscription', 'customer']
      });

      if (session.payment_status !== 'paid') {
        return res.status(402).json({ error: 'Payment not completed' });
      }

      // Already provisioned — don't re-expose the key
      if (session.metadata?.key_provisioned === 'true') {
        usedSessions.add(session_id);
        return res.json({
          status: 'already_provisioned',
          note: 'API key was already delivered. If you lost it, contact support.'
        });
      }

      // Generate key with full metadata for tracking
      const key = generateApiKey({
        customerId: session.customer?.id || session.customer,
        subscriptionId: session.subscription?.id || session.subscription,
        email: session.customer_details?.email || session.customer?.email || 'unknown',
        stripeSessionId: session_id,
      });

      // Store a hash (not the raw key) in session metadata for idempotency
      const keyHash = crypto.createHash('sha256').update(key).digest('hex').slice(0, 12);
      await getStripe().checkout.sessions.update(session_id, {
        metadata: { ...session.metadata, key_provisioned: 'true', key_hash: keyHash }
      });

      // Mark session as used
      usedSessions.add(session_id);
      // Cap set size
      if (usedSessions.size > 10000) {
        const first = usedSessions.values().next().value;
        usedSessions.delete(first);
      }

      console.log(`[stripe] Key provisioned for ${session.customer_details?.email} (sub: ${session.subscription?.id || session.subscription})`);

      res.json({
        status: 'active',
        apiKey: key,
        usage: 'curl -H "X-Api-Key: YOUR_KEY" https://mcp.skills.ws/api/whois?domain=example.com',
        note: 'Store this key securely — it cannot be retrieved later'
      });
    } catch (err) {
      console.error('[stripe] success error:', err.message);
      res.status(500).json({ error: 'Failed to retrieve session' });
    }
  });

  // Cancel page
  app.get('/billing/cancel', (_, res) => {
    res.json({ status: 'cancelled', message: 'Payment cancelled. You can still use the free tier (10 calls/day).' });
  });
}
