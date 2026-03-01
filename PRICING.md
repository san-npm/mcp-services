# MCP Services — Pricing

## Plans

| | Free | Pro | Pay-Per-Call |
|---|---|---|---|
| **Price** | $0 | $9/mo | $0.005/call |
| **Calls** | 10/day | Unlimited | Unlimited |
| **Auth** | None (IP-based) | API key | x402 payment header |
| **Rate limit** | 10 calls/day/IP | None | None |
| **Support** | Community | Email | — |
| **Payment** | — | Credit card (Stripe) | USDC or USDT on Base/Celo |

## Tools Included (All Plans)

| Tool | Endpoint | Description |
|---|---|---|
| Screenshot | `/api/screenshot` | Capture any webpage as PNG/JPEG |
| WHOIS | `/api/whois` | Domain registration data |
| DNS | `/api/dns` | A, AAAA, MX, NS, TXT, CNAME, SOA records |
| SSL | `/api/ssl` | Certificate analysis, chain, expiry |
| OCR | `/api/ocr` | Extract text from images |
| Blockchain | `/api/blockchain` | Balances, token prices, multi-chain |

## How to Get Started

### Free — Just call it
```bash
curl https://mcp.skills.ws/api/dns?domain=example.com
```

### Pro — Get an API key
```bash
# 1. Create checkout
curl -X POST https://mcp.skills.ws/billing/checkout
# 2. Pay via Stripe ($9/mo)
# 3. Use your key
curl -H "X-Api-Key: mcp_YOUR_KEY" https://mcp.skills.ws/api/whois?domain=example.com
```

### Pay-Per-Call — x402 micropayments
Send $0.005 in USDC/USDT to `0x087ae921CE8d07a4dE6BdacAceD475e9080B2aDF` on Base or Celo, then include the tx proof in your request header.

## MCP Integration

Connect any MCP-compatible client (Claude Desktop, Claude Code, Cursor):

```json
{
  "mcpServers": {
    "skills-ws": {
      "url": "https://mcp.skills.ws/mcp/sse"
    }
  }
}
```

## FAQ

**Which plan is cheaper?**
If you make more than 1,800 calls/month → Pro ($9 flat).
Less than that → Pay-Per-Call is cheaper.

**Can I switch plans?**
Yes. Cancel Stripe anytime, switch to pay-per-call, or vice versa.

**What chains are supported for x402?**
Base and Celo only. USDC and USDT only.

**Is there a refund policy?**
Stripe subscriptions can be cancelled anytime. No refunds for x402 payments (they're per-call).
