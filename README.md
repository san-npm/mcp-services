# MCP Services

Multi-tool MCP server + REST API for AI agents. 21 tools across web scraping, SEO analysis, agent memory, screenshot/PDF generation, domain intelligence, content extraction, and multi-chain EVM blockchain queries.

**Live:** [mcp.skills.ws](https://mcp.skills.ws) | **Docs:** [llms.txt](https://mcp.skills.ws/llms.txt) | **npm:** `npm install -g mcp-services`

---

## Quick Start

### Use the hosted version (no setup)

Add to your MCP client config (Claude Desktop, Cursor, OpenClaw, etc.):

```json
{
  "mcpServers": {
    "mcp-services": {
      "url": "https://mcp.skills.ws/mcp/sse"
    }
  }
}
```

Free tier: 10 calls/day, no auth needed.

### Self-host

```bash
npm install -g mcp-services
mcp-services
# → running on http://localhost:3100
```

No auth needed for the free tier (10 calls/day per IP).

---

## Tools (21)

### Web Scraping
| Tool | Endpoint | Description |
|------|----------|-------------|
| `scrape` | `GET /api/scrape` | URL to clean Markdown with headings, lists, links, code blocks, tables |
| `crawl` | `GET /api/crawl` | Crawl a site from starting URL, follow internal links (depth 1-3, max 20 pages) |
| `extract` | `GET /api/extract` | Extract structured data: JSON-LD, Open Graph, meta tags, headings, links, images, tables |

### SEO Toolkit
| Tool | Endpoint | Description |
|------|----------|-------------|
| `serp` | `GET /api/serp` | Google SERP scraping — top 20 results, People Also Ask, featured snippets, related searches |
| `onpage_seo` | `GET /api/onpage-seo` | Full on-page SEO audit with score (0-100) — title, meta, headings, images, schema, Open Graph |
| `keywords_suggest` | `GET /api/keywords` | Google Autocomplete keyword suggestions with A-Z expansion (100+ ideas) |

### Agent Memory
| Tool | Endpoint | Description |
|------|----------|-------------|
| `memory_store` | `POST /api/memory` | Store a memory (key-value, namespace-scoped, with tags). Upserts on key conflict |
| `memory_get` | `GET /api/memory` | Retrieve a memory by namespace + key |
| `memory_search` | `GET /api/memory/search` | Full-text search across memories in a namespace |
| `memory_list` | `GET /api/memory/list` | List all memories in a namespace with pagination |
| `memory_delete` | `DELETE /api/memory` | Delete a memory by namespace + key |

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

No account needed. Pay with USDC or USDT on Base or Celo. x402-compatible agents handle payment automatically.

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
cp .env.example .env
node server.js
```

Requires: Node.js 20+, Chromium (for screenshot/PDF/scrape/SEO tools).

---

## Tools (15)

### Web Scraping
| Tool | Description |
|------|-------------|
| `scrape` | URL to clean Markdown — headings, lists, links, code blocks, tables |
| `crawl` | Crawl a site (depth 1-3, max 20 pages), return markdown per page |
| `extract` | Structured data: JSON-LD, Open Graph, meta tags, headings, links, images, tables |

### SEO Toolkit
| Tool | Description |
|------|-------------|
| `serp` | Google SERP scraping — top 20 results, People Also Ask, featured snippets |
| `onpage_seo` | Full on-page SEO audit with score (0-100) — title, meta, headings, images, schema |
| `keywords_suggest` | Google Autocomplete keyword ideas with A-Z expansion (100+ suggestions) |

### Agent Memory
| Tool | Description |
|------|-------------|
| `memory_store` | Store a memory (key-value, namespace-scoped, with tags) |
| `memory_get` | Retrieve a memory by namespace + key |
| `memory_search` | Full-text search across memories in a namespace |
| `memory_list` | List all memories with pagination |
| `memory_delete` | Delete a memory |

### Content & Media
| Tool | Description |
|------|-------------|
| `screenshot` | PNG/JPEG screenshot of any URL (configurable viewport) |
| `pdf` | Generate PDF from any URL |
| `html2md` | Simple URL to Markdown conversion |
| `ocr` | Extract text from image URL via Tesseract OCR |

### Domain Intelligence
| Tool | Description |
|------|-------------|
| `whois` | WHOIS domain registration lookup |
| `dns` | DNS records — A, AAAA, MX, NS, TXT, CNAME, SOA |
| `ssl` | SSL certificate details and expiry check |

### Blockchain (6 chains)
| Tool | Description |
|------|-------------|
| `balance` | Native token balance (ETH, MATIC, CELO) |
| `erc20_balance` | ERC20 token balance with symbol and decimals |
| `transaction` | Transaction details by hash |

**Supported chains:** Ethereum, Base, Arbitrum, Optimism, Polygon, Celo

---

## REST API

All tools are also available as REST endpoints:

```bash
# Web Scraping
curl "https://mcp.skills.ws/api/scrape?url=https://example.com"
curl "https://mcp.skills.ws/api/crawl?url=https://example.com&depth=2&maxPages=10"
curl "https://mcp.skills.ws/api/extract?url=https://example.com"

# SEO
curl "https://mcp.skills.ws/api/serp?keyword=mcp+server"
curl "https://mcp.skills.ws/api/onpage-seo?url=https://example.com"
curl "https://mcp.skills.ws/api/keywords?keyword=ai+agents"

# Memory
curl -X POST "https://mcp.skills.ws/api/memory" \
  -H "Content-Type: application/json" \
  -d '{"namespace":"my-agent","key":"greeting","value":"Hello world","tags":["demo"]}'
curl "https://mcp.skills.ws/api/memory?namespace=my-agent&key=greeting"
curl "https://mcp.skills.ws/api/memory/search?namespace=my-agent&query=hello"

# Domain Intelligence
curl "https://mcp.skills.ws/api/whois?domain=example.com"
curl "https://mcp.skills.ws/api/dns?domain=example.com&type=ALL"
curl "https://mcp.skills.ws/api/ssl?domain=example.com"

# Content
curl "https://mcp.skills.ws/api/screenshot?url=https://example.com&format=png"
curl "https://mcp.skills.ws/api/pdf?url=https://example.com"

# Blockchain
curl "https://mcp.skills.ws/api/chain/balance?address=0x...&chain=ethereum"
curl "https://mcp.skills.ws/api/chain/erc20?address=0x...&token=0x...&chain=celo"
```

---

## Pricing

| Plan | Price | Calls | Auth |
|------|-------|-------|------|
| **Free** | $0 | 10/day per IP | None |
| **Pro** | $9/mo | Unlimited | `X-Api-Key` header |
| **x402** | $0.005/call | Pay-per-use | `X-Payment` header (USDC/USDT on Base & Celo) |

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3100` | Server port |
| `CHROMIUM_PATH` | `/usr/bin/chromium-browser` | Path to Chromium |
| `MAX_BROWSERS` | `3` | Max concurrent browser instances |
| `MAX_SSE_SESSIONS` | `50` | Max MCP SSE sessions |
| `FREE_DAILY_LIMIT` | `10` | Free tier daily limit |
| `API_KEYS` | — | Comma-separated valid API keys |
| `ADMIN_SECRET` | — | Secret for admin endpoints |
| `STRIPE_SECRET_KEY` | — | Stripe API key for Pro subscriptions |
| `STRIPE_WEBHOOK_SECRET` | — | Stripe webhook signing secret |
| `X402_PRICE_USD` | `0.005` | x402 price per call |
| `X402_RECEIVER` | — | x402 payment receiver address |
| `MEMORY_DB_PATH` | `./data/memory.db` | SQLite memory database path |

---

## Security

- SSRF protection: URL validation + DNS pre-resolution + Puppeteer request interception
- Domain validation: regex allowlist prevents command injection
- Memory namespace isolation per auth tier (API key hash, IP, or x402)
- Rate limiting on free tier
- Resource limits: max concurrent browsers, SSE sessions, PDF size cap

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
                  │  │         21 Tool Handlers      │ │
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
