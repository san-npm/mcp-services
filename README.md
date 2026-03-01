# MCP Services

Multi-tool MCP server + REST API for AI agents. 10 tools across screenshot/PDF generation, domain intelligence, content extraction, and multi-chain EVM blockchain queries.

**Live:** [mcp.skills.ws](https://mcp.skills.ws) | **Docs:** [llms-full.txt](https://mcp.skills.ws/llms-full.txt)

---

## Quick Start

### Connect from Claude Desktop / Cursor / any MCP client

```json
{
  "mcpServers": {
    "mcp-services": {
      "url": "https://mcp.skills.ws/mcp/sse"
    }
  }
}
```

### REST API

```bash
curl "https://mcp.skills.ws/api/whois?domain=example.com"
curl "https://mcp.skills.ws/api/dns?domain=example.com&type=ALL"
curl "https://mcp.skills.ws/api/ssl?domain=example.com"
curl "https://mcp.skills.ws/api/screenshot?url=https://example.com&format=png"
```

No auth needed for the free tier (10 calls/day per IP).

---

## Tools

### Screenshot & PDF
| Tool | Endpoint | Description |
|------|----------|-------------|
| `screenshot` | `GET /api/screenshot` | PNG/JPEG screenshot of any URL |
| `pdf` | `GET /api/pdf` | Generate PDF of any URL |

**Screenshot parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | *required* | URL to screenshot |
| `format` | string | `png` | `png` or `jpeg` |
| `width` | number | `1280` | Viewport width (100–3840) |
| `height` | number | `800` | Viewport height (100–2160) |
| `fullPage` | boolean | `false` | Capture full scrollable page |

### Content Extraction
| Tool | Endpoint | Description |
|------|----------|-------------|
| `html2md` | `GET /api/html2md` | Fetch URL, strip nav/ads/scripts, convert to Markdown |
| `ocr` | `GET /api/ocr` | Extract text from image URL via Tesseract.js OCR |

### Domain Intelligence
| Tool | Endpoint | Description |
|------|----------|-------------|
| `whois` | `GET /api/whois` | WHOIS registrar, creation date, expiry, name servers |
| `dns` | `GET /api/dns` | DNS records — `A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`, `SOA`, or `ALL` |
| `ssl` | `GET /api/ssl` | SSL certificate issuer, validity dates, expiry countdown, fingerprint |

### Blockchain (6 EVM chains)
| Tool | Endpoint | Description |
|------|----------|-------------|
| `balance` | `GET /api/chain/balance` | Native token balance for any address |
| `erc20_balance` | `GET /api/chain/erc20` | ERC20 token balance, symbol, decimals |
| `transaction` | `GET /api/chain/tx` | Transaction details — from, to, value, gas, status |

**Supported chains:**

| Chain | Native Token | Chain ID |
|-------|-------------|----------|
| Ethereum | ETH | 1 |
| Base | ETH | 8453 |
| Arbitrum | ETH | 42161 |
| Optimism | ETH | 10 |
| Polygon | MATIC | 137 |
| Celo | CELO | 42220 |

---

## Authentication

Three tiers — use whichever fits:

| Tier | How | Limit | Cost |
|------|-----|-------|------|
| **Free** | No auth needed | 10 calls/day per IP | $0 |
| **API Key** | `X-Api-Key` header or `?apikey=` query param | Unlimited | $9/mo |
| **x402** | `X-Payment` header | Pay per call | $0.005/call |

### API Key

Subscribe via Stripe to get an unlimited API key:

```bash
# 1. Create checkout session
curl -X POST https://mcp.skills.ws/billing/checkout
# Returns: { "url": "https://checkout.stripe.com/..." }

# 2. Complete payment at the Stripe URL
# 3. You'll receive your API key on the success page (shown once only — save it)

# 4. Use it
curl -H "X-Api-Key: mcp_your_key" "https://mcp.skills.ws/api/whois?domain=example.com"
```

### x402 Pay-per-call

No account needed. Pay with USDC, USDT, or cUSD on Base or Celo. x402-compatible agents handle payment automatically.

```bash
curl -H "X-Payment: <base64-encoded-json>" "https://mcp.skills.ws/api/screenshot?url=https://example.com"
```

Payment JSON format:
```json
{
  "network": "celo",
  "token": "USDC",
  "txHash": "0x...",
  "amount": "0.005",
  "receiver": "0x..."
}
```

When the free limit is exceeded, the API returns `429` with upgrade options. Invalid x402 payment returns `402` with pricing info.

---

## Self-Hosted Setup

### Requirements

- Node.js 22+
- Chromium (for screenshot, PDF, OCR, html2md)

### Install

```bash
git clone https://github.com/san-npm/mcp-services.git
cd mcp-services
npm install
cp .env.example .env   # edit with your settings
node server.js          # runs on port 3100
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3100` | Server port |
| `CHROMIUM_PATH` | `/usr/bin/chromium-browser` | Path to Chromium binary |
| `MAX_BROWSERS` | `3` | Max concurrent browser instances |
| `MAX_SSE_SESSIONS` | `50` | Max concurrent MCP SSE sessions |
| `FREE_DAILY_LIMIT` | `10` | Free tier daily call limit per IP |
| `API_KEYS` | — | Comma-separated manually provisioned API keys |
| `ADMIN_SECRET` | — | Secret for `/admin/*` endpoints |
| `KEYS_FILE` | `./data/api-keys.json` | Persistent API key storage path |
| `STRIPE_SK` | — | Stripe secret key (`sk_live_...` or `sk_test_...`) |
| `STRIPE_WEBHOOK_SECRET` | — | Stripe webhook signing secret (`whsec_...`) |
| `DOMAIN` | `https://mcp.skills.ws` | Base URL for Stripe checkout redirects |
| `X402_PRICE_USD` | `0.005` | x402 price per API call |
| `X402_RECEIVER` | `0x087...` | x402 payment receiver address |

### Stripe Webhook Setup

If using Stripe billing, configure the webhook in your [Stripe Dashboard](https://dashboard.stripe.com/webhooks):

- **Endpoint URL:** `https://your-domain.com/billing/webhook`
- **Events to listen for:**
  - `customer.subscription.deleted`
  - `customer.subscription.paused`
  - `invoice.payment_failed`
  - `invoice.payment_succeeded`

---

## Admin Endpoints

Requires `ADMIN_SECRET` env var and `X-Admin-Secret` header.

```bash
# Generate a new API key
curl -X POST -H "X-Admin-Secret: your_secret" -H "Content-Type: application/json" \
  -d '{"email":"user@example.com"}' https://mcp.skills.ws/admin/keys

# Revoke a key
curl -X POST -H "X-Admin-Secret: your_secret" -H "Content-Type: application/json" \
  -d '{"key":"mcp_xxx"}' https://mcp.skills.ws/admin/revoke

# View stats
curl -H "X-Admin-Secret: your_secret" https://mcp.skills.ws/admin/stats
```

---

## Security

- **SSRF protection:** URL validation + DNS pre-resolution + Puppeteer request interception (blocks redirects to private IPs)
- **DNS rebinding prevention:** Resolved IPs checked against private ranges before browser access
- **Domain validation:** Regex allowlist prevents command injection in WHOIS/DNS/SSL
- **Rate limiting:** IP-based daily limits on free tier, per-IP checkout rate limiting
- **Resource limits:** Max 3 concurrent browsers, 50 SSE sessions, 50MB PDF cap, 2MB content cap
- **Webhook verification:** Stripe signature verification via `constructEvent()`; rejects if webhook secret is not configured
- **API key storage:** Atomic file writes (temp + rename) prevent corruption
- **Constant-time auth:** Admin secret comparison uses `crypto.timingSafeEqual`
- **x402 replay protection:** Transaction hash deduplication with capped Set

---

## Architecture

```
                  ┌──────────────────────────────────┐
                  │          Express Server           │
                  │                                   │
                  │  ┌─────────┐    ┌──────────────┐ │
  MCP SSE ───────►│  │ MCP SDK │    │  Auth Layer   │ │
                  │  │  (SSE)  │    │ free/key/x402 │ │
                  │  └─────────┘    └──────────────┘ │
                  │                                   │
  REST API ──────►│  ┌──────────────────────────────┐ │
                  │  │         10 Tool Handlers      │ │
                  │  │ screenshot │ pdf │ html2md    │ │
                  │  │ ocr │ whois │ dns │ ssl       │ │
                  │  │ balance │ erc20 │ transaction │ │
                  │  └──────────────────────────────┘ │
                  │        │              │            │
                  │  ┌─────┴────┐  ┌─────┴─────────┐ │
                  │  │ Puppeteer│  │ viem (6 RPCs)  │ │
                  │  │ Chromium │  │ whois-json     │ │
                  │  │          │  │ openssl (SSL)  │ │
                  │  └──────────┘  └────────────────┘ │
                  │                                   │
  Stripe ────────►│  ┌──────────────────────────────┐ │
  Webhooks        │  │   Billing (stripe.js)         │ │
                  │  │   checkout → key provisioning │ │
                  │  └──────────────────────────────┘ │
                  └──────────────────────────────────┘
```

## Stack

- **Runtime:** Node.js 22 + Express
- **Browser:** Puppeteer (Chromium) — screenshots, PDF, OCR, html2md
- **Blockchain:** viem — 6 EVM chains via public RPCs
- **Payments:** Stripe (subscriptions), x402 protocol (stablecoins on Base/Celo)
- **MCP:** `@modelcontextprotocol/sdk` with SSE transport
- **Hosting:** [Aleph Cloud](https://aleph.im) (decentralized compute)

## License

MIT — [Commit Media SARL](https://openletz.com)
