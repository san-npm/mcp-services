// ─── Stripe Billing ───
// $9/mo subscription → unlimited API key

import Stripe from 'stripe';
import { generateApiKey } from './auth.js';

const stripe = new Stripe(process.env.STRIPE_SK);
const PRICE_MONTHLY = 900; // $9.00 in cents
const DOMAIN = process.env.DOMAIN || 'https://mcp.skills.ws';

let priceId = null;

// ─── Initialize Stripe product + price ───
async function ensureProduct() {
  if (priceId) return priceId;

  // Check for existing product
  const products = await stripe.products.list({ limit: 1, active: true });
  let product = products.data.find(p => p.metadata?.type === 'mcp-api-key');

  if (!product) {
    product = await stripe.products.create({
      name: 'MCP Services — API Key',
      description: 'Unlimited API access to mcp.skills.ws (screenshot, WHOIS, DNS, SSL, OCR, blockchain)',
      metadata: { type: 'mcp-api-key' }
    });
  }

  // Check for existing price
  const prices = await stripe.prices.list({ product: product.id, active: true, limit: 1 });
  if (prices.data.length > 0) {
    priceId = prices.data[0].id;
  } else {
    const price = await stripe.prices.create({
      product: product.id,
      unit_amount: PRICE_MONTHLY,
      currency: 'usd',
      recurring: { interval: 'month' }
    });
    priceId = price.id;
  }

  return priceId;
}

// ─── Routes ───
export function stripeRoutes(app) {

  // Create checkout session
  app.post('/billing/checkout', async (req, res) => {
    try {
      const pid = await ensureProduct();
      const session = await stripe.checkout.sessions.create({
        mode: 'subscription',
        payment_method_types: ['card'],
        line_items: [{ price: pid, quantity: 1 }],
        success_url: `${DOMAIN}/billing/success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${DOMAIN}/billing/cancel`,
        metadata: { purpose: 'mcp-api-key' }
      });
      res.json({ url: session.url });
    } catch (err) {
      console.error('[stripe] checkout error:', err.message);
      res.status(500).json({ error: 'Failed to create checkout session' });
    }
  });

  // Success page — returns API key
  app.get('/billing/success', async (req, res) => {
    const { session_id } = req.query;
    if (!session_id) return res.status(400).json({ error: 'Missing session_id' });

    try {
      const session = await stripe.checkout.sessions.retrieve(session_id);
      if (session.payment_status !== 'paid') {
        return res.status(402).json({ error: 'Payment not completed' });
      }

      // Check if key already provisioned (idempotent)
      if (session.metadata?.api_key) {
        return res.json({
          status: 'active',
          apiKey: session.metadata.api_key,
          note: 'Store this key — use it in X-Api-Key header'
        });
      }

      // Generate and store key
      const key = generateApiKey();
      await stripe.checkout.sessions.update(session_id, {
        metadata: { ...session.metadata, api_key: key }
      });

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

  // Webhook for subscription events (cancellation, renewal)
  app.post('/billing/webhook', async (req, res) => {
    const sig = req.headers['stripe-signature'];
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

    if (!webhookSecret) {
      console.warn('[stripe] No webhook secret configured');
      return res.status(200).send('ok');
    }

    let event;
    try {
      event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
    } catch (err) {
      console.error('[stripe] webhook sig error:', err.message);
      return res.status(400).send('Invalid signature');
    }

    switch (event.type) {
      case 'customer.subscription.deleted':
        console.log('[stripe] Subscription cancelled:', event.data.object.id);
        // TODO: revoke API key
        break;
      case 'invoice.payment_succeeded':
        console.log('[stripe] Payment received:', event.data.object.id);
        break;
      default:
        break;
    }

    res.status(200).send('ok');
  });
}
