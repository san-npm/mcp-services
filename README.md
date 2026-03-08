# MCP Services

Multi-tool MCP server + REST API for AI agents. 29 tools across web scraping, SEO analysis, agent memory, screenshot/PDF generation, domain intelligence, content extraction, multi-chain EVM blockchain queries, and security toolkit.

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
# -> running on http://localhost:3100
```

---

## Tools (29)

### Web Scraping
| Tool | Endpoint | Description |
|------|----------|-------------|
| `scrape` | `GET /api/scrape` | URL to clean Markdown with headings, lists, links, code blocks, tables |
| `crawl` | `GET /api/crawl` | Crawl a site from starting URL, follow internal links (depth 1-3, max 20 pages) |
| `extract` | `GET /api/extract` | Extract structured data: JSON-LD, Open Graph, meta tags, headings, links, images, tables |

### SEO Toolkit
| Tool | Endpoint | Description |
|------|----------|-------------|
| `serp` | `GET /api/serp` | Google SERP scraping -- top 20 results, People Also Ask, featured snippets, related searches |
| `onpage_seo` | `GET /api/onpage-seo` | Full on-page SEO audit with score (0-100) -- title, meta, headings, images, schema, Open Graph |
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
| `pdf2docx` | `GET /api/pdf2docx` | Convert PDF (from URL) to Word/DOCX -- text extraction with heading detection |

### Content Extraction
| Tool | Endpoint | Description |
|------|----------|-------------|
| `html2md` | `GET /api/html2md` | Fetch URL, strip nav/ads/scripts, convert to Markdown |
| `ocr` | `GET /api/ocr` | Extract text from image URL via Tesseract.js OCR |

### Domain Intelligence
| Tool | Endpoint | Description |
|------|----------|-------------|
| `whois` | `GET /api/whois` | WHOIS registrar, creation date, expiry, name servers |
| `dns` | `GET /api/dns` | DNS records -- `A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`, `SOA`, or `ALL` |
| `ssl` | `GET /api/ssl` | SSL certificate issuer, validity dates, expiry countdown, fingerprint |

### Blockchain (6 EVM chains)
| Tool | Endpoint | Description |
|------|----------|-------------|
| `balance` | `GET /api/chain/balance` | Native token balance for any address |
| `erc20_balance` | `GET /api/chain/erc20` | ERC20 token balance, symbol, decimals |
| `transaction` | `GET /api/chain/tx` | Transaction details -- from, to, value, gas, status |

**Supported chains:** Ethereum, Base, Arbitrum, Optimism, Polygon, Celo

### Security Toolkit
| Tool | Endpoint | Description |
|------|----------|-------------|
| `url_scan` | `GET /api/security/url-scan` | Phishing & malware detection -- VirusTotal + heuristics (typosquatting, homoglyphs, suspicious TLDs, free hosting) |
| `wallet_check` | `GET /api/security/wallet-check` | Ethereum wallet risk assessment -- Etherscan verification, tx patterns, OFAC sanctions, address poisoning warnings |
| `contract_scan` | `GET /api/security/contract-scan` | Smart contract honeypot & risk detection -- Honeypot.is + source code analysis (mint, blacklist, fee manipulation, proxy) |
| `email_headers` | `GET /api/security/email-headers` | Email authentication check -- SPF, DKIM, DMARC, MX records via DNS |
| `threat_intel` | `GET /api/security/threat-intel` | IOC lookup -- AbuseIPDB + VirusTotal + OTX AlienVault with weighted confidence scoring for IPs, domains, URLs, hashes |
| `header_audit` | `GET /api/security/header-audit` | Security header score (0-100) -- HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, cookie flags |
| `vuln_headers` | `GET /api/security/vuln-headers` | Information leakage detection -- Server version, X-Powered-By, debug headers, CORS misconfiguration |

Security tools degrade gracefully without API keys (heuristics-only mode). Optional keys: `VT_API_KEY`, `ABUSEIPDB_API_KEY`, `ETHERSCAN_API_KEY`.

---

## Authentication

Three tiers -- use whichever fits:

| Tier | How | Limit | Cost |
|------|-----|-------|------|
| **Free** | No auth needed | 10 calls/day per IP | $0 |
| **API Key** | `X-Api-Key` header | Unlimited | $9/mo |
| **x402** | `X-Payment` header | Pay per call | $0.005/call |

### API Key

Subscribe via Stripe to get an unlimited API key:

For migration only, query-string API keys (`?apikey=`) can be temporarily re-enabled with `ALLOW_APIKEY_QUERY=true`. This mode is deprecated; prefer `X-Api-Key`.


```bash
# 1. Create checkout session
curl -X POST https://mcp.skills.ws/billing/checkout
# Returns: { "url": "https://checkout.stripe.com/..." }

# 2. Complete payment at the Stripe URL
# 3. You'll receive your API key on the success page (shown once only -- save it)

# 4. Use it
curl -H "X-Api-Key: mcp_your_key" "https://mcp.skills.ws/api/whois?domain=example.com"
```

### x402 Pay-per-call

No account needed. Pay with USDC or USDT on Base or Celo. x402-compatible agents handle payment automatically.

```bash
curl -H "X-Payment: <base64-encoded-json>" "https://mcp.skills.ws/api/screenshot?url=https://example.com"
```

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
curl "https://mcp.skills.ws/api/pdf2docx?url=https://example.com/document.pdf"

# Blockchain
curl "https://mcp.skills.ws/api/chain/balance?address=0x...&chain=ethereum"
curl "https://mcp.skills.ws/api/chain/erc20?address=0x...&token=0x...&chain=celo"

# Security
curl "https://mcp.skills.ws/api/security/url-scan?url=https://suspicious-site.com"
curl "https://mcp.skills.ws/api/security/wallet-check?address=0x...&chain=ethereum"
curl "https://mcp.skills.ws/api/security/contract-scan?address=0x...&chainId=1"
curl "https://mcp.skills.ws/api/security/email-headers?domain=example.com"
curl "https://mcp.skills.ws/api/security/threat-intel?ioc=8.8.8.8&type=ip"
curl "https://mcp.skills.ws/api/security/header-audit?url=https://example.com"
curl "https://mcp.skills.ws/api/security/vuln-headers?url=https://example.com"
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3100` | Server port |
| `CHROMIUM_PATH` | `/usr/bin/chromium-browser` | Path to Chromium |
| `MAX_BROWSERS` | `3` | Max concurrent browser instances |
| `MAX_SSE_SESSIONS` | `50` | Max MCP SSE sessions |
| `MAX_SSE_PER_IP` | `5` | Max concurrent SSE sessions per client IP |
| `SSE_CONNECT_MAX_PER_WINDOW` | `30` | Max SSE connection attempts per IP per window |
| `SSE_CONNECT_WINDOW_MS` | `60000` | SSE connect rate-limit window in ms |
| `SSE_ALLOWED_HOSTS` | -- | Comma-separated allowlist for `Host` header on `/mcp/sse` + `/mcp/messages` (e.g. `mcp.example.com,localhost`) |
| `SSE_ALLOWED_ORIGINS` | -- | Optional comma-separated allowlist for `Origin` header (full origins like `https://app.example.com`) |
| `FREE_DAILY_LIMIT` | `10` | Free tier request limit |
| `FREE_WINDOW_MS` | `86400000` | Free-tier rate-limit window in ms |
| `REDIS_URL` | -- | Optional Redis backend for shared/distributed rate-limits |
| `API_KEYS` | -- | Comma-separated valid API keys |
| `ALLOW_APIKEY_QUERY` | `true` in non-production, `false` in production | Allow deprecated `?apikey=` auth during migration |
| `ADMIN_SECRET` | -- | Secret for admin endpoints |
| `STRIPE_SK` | -- | Stripe API key for Pro subscriptions |
| `STRIPE_WEBHOOK_SECRET` | -- | Stripe webhook signing secret |
| `STRIPE_WEBHOOK_IP_ALLOWLIST` | -- | Optional CSV allowlist for webhook source IPs |
| `CHECKOUT_LIMIT_PER_HOUR` | `5` | Per-IP Stripe checkout creation limit |
| `X402_PRICE_USD` | `0.005` | x402 price per call |
| `X402_RECEIVER` | -- | x402 payment receiver address |
| `X402_MAX_TX_AGE_SECONDS` | `86400` | Maximum accepted payment tx age in seconds (stale txs are rejected) |
| `X402_TX_CACHE_FILE` | `./data/x402-tx-cache.json` | Persistent replay-protection cache for used x402 tx hashes |
| `X402_TEST_MODE` | `0` | Set to `1` only for local/offline testing; ignored in production |
| `MEMORY_DB_PATH` | `./data/memory.db` | SQLite memory database path |
| `VT_API_KEY` | -- | VirusTotal API key (free: 4/min, 500/day) |
| `ABUSEIPDB_API_KEY` | -- | AbuseIPDB API key (free: 1000/day) |
| `ETHERSCAN_API_KEY` | -- | Etherscan API key (free: 5/sec) |
| `TRUST_PROXY` | `false` | Express trust proxy setting (`false`, `true`, hop count like `1`, or subnet names/CIDRs like `loopback`/`10.0.0.0/8`) |

---

## Reverse proxy & client IP configuration

`mcp-services` defaults to `TRUST_PROXY=false`, which means the app ignores `X-Forwarded-For` and uses the direct socket peer IP for rate limits and free-tier memory namespacing.

Enable `TRUST_PROXY` only when your deployment is actually behind a trusted reverse proxy/load balancer that rewrites forwarding headers. Common options:

- `TRUST_PROXY=1` when exactly one trusted proxy sits in front of Node.js
- `TRUST_PROXY=loopback` for local proxy setups
- `TRUST_PROXY=<cidr>` (or comma-separated values) for explicit trusted proxy ranges

When trust proxy is enabled, Express derives `req.ip` from `X-Forwarded-For` according to that trust policy. Ensure your edge proxy:

1. Appends/sets a valid `X-Forwarded-For` chain
2. Prevents direct untrusted clients from spoofing forwarding headers
3. Forwards the real client address as the left-most IP in `X-Forwarded-For`

If `X-Forwarded-For` is present while `TRUST_PROXY=false`, the server logs a defensive warning and ignores that header.

For production, set `SSE_ALLOWED_HOSTS` and `SSE_ALLOWED_ORIGINS` to strict, explicit values (only your public MCP domain and trusted app origins). Avoid wildcards or broad internal host lists.

## Deployment hardening checklist (recommended)

- Set `NODE_ENV=production`
- Keep `ALLOW_APIKEY_QUERY=false` (header auth only)
- Configure `TRUST_PROXY` correctly for your network path (do not blindly set `true`)
- Set strict `SSE_ALLOWED_HOSTS` and `SSE_ALLOWED_ORIGINS`
- Use `REDIS_URL` for shared rate-limits in multi-instance deployments
- Rotate `ADMIN_SECRET` and Stripe keys periodically
- Keep `X402_TEST_MODE=0` in production (enforced by server)
- Persist `KEYS_FILE`, `MEMORY_DB_PATH`, and `X402_TX_CACHE_FILE` on durable storage
- Run `npm audit` in CI and fail builds on high/critical vulnerabilities

### Production env quickstart

```bash
cp .env.production.example .env
# then edit .env values for your domain, proxy topology, redis and secrets
```

### Stripe webhook edge allowlist auto-sync (nginx)

```bash
# Generate CIDR allowlist include from Stripe source and reload nginx
scripts/sync-stripe-webhook-ips.sh \
  --out /etc/nginx/snippets/stripe-webhook-allowlist.conf \
  --reload "systemctl reload nginx"
```

See `deploy/nginx/stripe-webhook.conf.example` for the webhook location block.

---

## Security

- SSRF protection: URL validation + DNS pre-resolution + private IP blocking + Puppeteer request interception
- Domain validation: regex allowlist prevents command injection
- Input sanitization: format validation per IOC type, address format checks, chain allowlists
- Memory namespace isolation per auth tier (API key hash, IP, or x402)
- Rate limiting on free tier
- Resource limits: max concurrent browsers, SSE sessions, PDF size cap, 5MB response body limit
- Response size limits on external API fetches

---

## Architecture

```
                  +------------------------------------+
                  |          Express Server             |
                  |                                     |
                  |  +---------+    +--------------+    |
  MCP SSE ------->  | MCP SDK |    |  Auth Layer   |   |
                  |  |  (SSE)  |    | free/key/x402 |   |
                  |  +---------+    +--------------+    |
                  |                                     |
  REST API ------>  +--------------------------------+  |
                  |  |        29 Tool Handlers        |  |
                  |  | scrape | crawl | extract       |  |
                  |  | serp | onpage_seo | keywords   |  |
                  |  | memory (5) | screenshot | pdf  |  |
                  |  | html2md | ocr | whois | dns    |  |
                  |  | ssl | balance | erc20 | tx     |  |
                  |  | url_scan | wallet_check        |  |
                  |  | contract_scan | email_headers   |  |
                  |  | threat_intel | header_audit     |  |
                  |  | vuln_headers                    |  |
                  |  +--------------------------------+  |
                  |        |              |              |
                  |  +-----+----+  +-----+----------+   |
                  |  | Puppeteer|  | viem (6 RPCs)   |   |
                  |  | Chromium |  | whois-json      |   |
                  |  |          |  | dns/promises    |   |
                  |  |          |  | security.js     |   |
                  |  +----------+  +-----------------+   |
                  |                                     |
  Stripe -------->  +--------------------------------+  |
  Webhooks        |  |   Billing (stripe.js)          |  |
                  |  |   checkout -> key provisioning  |  |
                  |  +--------------------------------+  |
                  +------------------------------------+
```

## Stack

- **Runtime:** Node.js 22 + Express
- **Browser:** Puppeteer (Chromium) -- screenshots, PDF, OCR, html2md
- **Blockchain:** viem -- 6 EVM chains via public RPCs
- **Security:** VirusTotal, AbuseIPDB, Etherscan, Honeypot.is, OTX AlienVault + heuristics
- **Payments:** Stripe (subscriptions), x402 protocol (stablecoins on Base/Celo)
- **MCP:** `@modelcontextprotocol/sdk` with SSE transport
- **Hosting:** [Aleph Cloud](https://aleph.im) (decentralized compute)

## License

MIT -- [Commit Media SARL](https://openletz.com)
