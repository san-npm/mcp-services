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

## Tools Included (All Plans — 21 tools)

| Category | Tools | Endpoints |
|---|---|---|
| Web Scraping | scrape, crawl, extract | `/api/scrape`, `/api/crawl`, `/api/extract` |
| SEO Toolkit | serp, onpage_seo, keywords_suggest | `/api/serp`, `/api/onpage-seo`, `/api/keywords` |
| Agent Memory | memory_store/get/search/list/delete | `/api/memory`, `/api/memory/search`, `/api/memory/list` |
| Screenshot & PDF | screenshot, pdf | `/api/screenshot`, `/api/pdf` |
| Content | html2md, ocr | `/api/html2md`, `/api/ocr` |
| Domain Intel | whois, dns, ssl | `/api/whois`, `/api/dns`, `/api/ssl` |
| Blockchain | balance, erc20_balance, transaction | `/api/chain/balance`, `/api/chain/erc20`, `/api/chain/tx` |

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
