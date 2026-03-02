# MCP Services

Hosted MCP server with **15 tools** for AI agents: web scraping, SEO analysis, persistent agent memory, screenshot, PDF, WHOIS, DNS, SSL, OCR, HTML-to-Markdown, and multi-chain blockchain data.

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

Or clone and run:

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

## License

MIT — [Commit Media SARL](https://openletz.com)
