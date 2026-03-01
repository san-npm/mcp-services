# MCP Services

Multi-tool MCP server + REST API for AI agents. Screenshot, PDF, WHOIS, DNS, SSL, OCR, HTML-to-Markdown, and multi-chain blockchain data.

## Live Endpoint

`https://mcp.skills.ws`

## Authentication

Three tiers — use whichever fits:

| Tier | Auth | Limit | Cost |
|------|------|-------|------|
| **Free** | None | 10 calls/day per IP | $0 |
| **API Key** | `X-Api-Key` header | Unlimited | $9/mo |
| **x402** | `X-Payment` header | Pay per call | $0.005/call |

### API Key

```bash
curl -H "X-Api-Key: mcp_your_key" https://mcp.skills.ws/api/whois?domain=example.com
```

### x402 (Pay-per-call with stablecoins)

No account needed. Pay with USDC, USDT, or cUSD on Celo. Send payment proof in the `X-Payment` header.

```bash
# x402-compatible agents handle this automatically
curl -H "X-Payment: <base64-payment-proof>" https://mcp.skills.ws/api/screenshot?url=https://example.com
```

When rate-limited or missing payment, the API returns HTTP 402/429 with pricing info.

## Services

### Screenshot / PDF
- `GET /api/screenshot?url=<url>&format=png|jpeg&width=1280&height=800&fullPage=true|false`
- `GET /api/pdf?url=<url>`

### Content Extraction
- `GET /api/html2md?url=<url>` — Fetch URL and convert to clean Markdown
- `GET /api/ocr?url=<image_url>` — Extract text from image via OCR (Tesseract.js)

### Domain Intelligence
- `GET /api/whois?domain=<domain>`
- `GET /api/dns?domain=<domain>&type=A|AAAA|MX|NS|TXT|CNAME|SOA|ALL`
- `GET /api/ssl?domain=<domain>` — SSL certificate details + expiry check

### Blockchain (6 chains: Ethereum, Base, Arbitrum, Optimism, Polygon, Celo)
- `GET /api/chain/balance?address=<addr>&chain=ethereum`
- `GET /api/chain/tx?hash=<hash>&chain=ethereum`
- `GET /api/chain/erc20?address=<addr>&token=<contract>&chain=ethereum`

### MCP Protocol (SSE)
- `GET /mcp/sse` — SSE stream for MCP clients
- `POST /mcp/messages?sessionId=<id>` — Send MCP messages

### Health
- `GET /health`

## MCP Tools

| Tool | Description |
|------|-------------|
| `screenshot` | Take PNG/JPEG screenshot of any URL |
| `pdf` | Generate PDF of any URL |
| `html2md` | Fetch URL and extract content as Markdown |
| `ocr` | Extract text from image via OCR |
| `whois` | WHOIS lookup for any domain |
| `dns` | DNS record lookup (A, MX, NS, TXT, etc.) |
| `ssl` | SSL certificate details + expiry check |
| `balance` | Native token balance on 6 chains |
| `erc20_balance` | ERC20 token balance |
| `transaction` | Transaction details by hash |

## Connect from Claude / MCP Client

```json
{
  "mcpServers": {
    "mcp-services": {
      "url": "https://mcp.skills.ws/mcp/sse"
    }
  }
}
```

## Self-hosted

```bash
npm install
cp .env.example .env  # edit with your settings
node server.js        # runs on port 3100
```

Requires Chromium for screenshot/PDF.

## Stack

- Node.js 22 + Express
- Puppeteer (Chromium) for screenshots/PDF
- viem for blockchain queries
- whois-json for WHOIS
- MCP SDK (SSE transport)
- x402 payment protocol (stablecoins on Base, Celo, Arbitrum, Polygon)
- Hosted on Aleph Cloud (decentralized compute)

## License

MIT — [Commit Media SARL](https://openletz.com)
