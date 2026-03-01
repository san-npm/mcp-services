// ─── Stripe Billing ───
// $9/mo subscription → unlimited API key

import Stripe from 'stripe';
import { generateApiKey, revokeBySubscription, revokeByCustomer } from './auth.js';
import express from 'express';

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

let priceId = null;

// ─── Initialize Stripe product + price ───
async function ensureProduct() {
  if (priceId) return priceId;

  // Search specifically by metadata
  const products = await getStripe().products.list({ limit: 100, active: true });
  let product = products.data.find(p => p.metadata?.type === 'mcp-api-key');

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
const checkoutLimiter = new Map();
function checkCheckoutRate(ip) {
  const now = Date.now();
  const attempts = checkoutLimiter.get(ip) || [];
  const recent = attempts.filter(t => now - t < 3600000); // last hour
  if (recent.length >= 5) return false; // max 5 checkouts per hour per IP
  recent.push(now);
  checkoutLimiter.set(ip, recent);
  return true;
}

// ─── Routes ───
export function stripeRoutes(app) {

  // IMPORTANT: Webhook needs raw body for signature verification
  // Must be registered BEFORE express.json() or with its own raw parser
  app.post('/billing/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    const sig = req.headers['stripe-signature'];
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

    if (!webhookSecret) {
      console.warn('[stripe] No webhook secret configured');
      return res.status(200).send('ok');
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
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
    if (!checkCheckoutRate(ip)) {
      return res.status(429).json({ error: 'Too many checkout attempts. Try again later.' });
    }

    try {
      const pid = await ensureProduct();
      const session = await getStripe().checkout.sessions.create({
        mode: 'subscription',
        payment_method_types: ['card'],
        line_items: [{ price: pid, quantity: 1 }],
        customer_creation: 'always',
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

  // Success — provision API key
  app.get('/billing/success', async (req, res) => {
    const { session_id } = req.query;
    if (!session_id || typeof session_id !== 'string' || session_id.length > 200) {
      return res.status(400).json({ error: 'Invalid session_id' });
    }

    try {
      const session = await getStripe().checkout.sessions.retrieve(session_id, {
        expand: ['subscription', 'customer']
      });

      if (session.payment_status !== 'paid') {
        return res.status(402).json({ error: 'Payment not completed' });
      }

      // Idempotent — check if key already provisioned
      if (session.metadata?.api_key) {
        return res.json({
          status: 'active',
          apiKey: session.metadata.api_key,
          note: 'Store this key — use it in X-Api-Key header'
        });
      }

      // Generate key with full metadata for tracking
      const key = generateApiKey({
        customerId: session.customer?.id || session.customer,
        subscriptionId: session.subscription?.id || session.subscription,
        email: session.customer_details?.email || session.customer?.email || 'unknown',
        stripeSessionId: session_id,
      });

      // Store key in session metadata for idempotency
      await getStripe().checkout.sessions.update(session_id, {
        metadata: { ...session.metadata, api_key: key }
      });

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
