# MCP Services

Multi-tool MCP server + REST API for AI agents. Screenshot, WHOIS, DNS, and multi-chain blockchain data.

## Live Endpoint

`https://forest-remedy-module-sells.trycloudflare.com`

> Note: Cloudflare tunnel URL changes on restart. Check this README for the latest.

## Services

### Screenshot / PDF
- `GET /api/screenshot?url=<url>&format=png|jpeg&width=1280&height=800&fullPage=true|false`
- `GET /api/pdf?url=<url>`

### Domain Intelligence
- `GET /api/whois?domain=<domain>`
- `GET /api/dns?domain=<domain>&type=A|AAAA|MX|NS|TXT|CNAME|SOA|ALL`

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
| `whois` | WHOIS lookup for any domain |
| `dns` | DNS record lookup (A, MX, NS, TXT, etc.) |
| `balance` | Native token balance on 6 chains |
| `erc20_balance` | ERC20 token balance |
| `transaction` | Transaction details by hash |

## Connect from Claude / MCP Client

```json
{
  "mcpServers": {
    "mcp-services": {
      "url": "https://forest-remedy-module-sells.trycloudflare.com/mcp/sse"
    }
  }
}
```

## Self-hosted

```bash
npm install
node server.js
# Runs on port 3100
```

Requires Chromium for screenshot/PDF.

## Stack

- Node.js 22 + Express
- Puppeteer (Chromium) for screenshots/PDF
- viem for blockchain queries
- whois-json for WHOIS
- MCP SDK (SSE transport)
- Hosted on Aleph Cloud (decentralized compute)
