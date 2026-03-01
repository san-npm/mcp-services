import express from 'express';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import puppeteer from 'puppeteer-core';
import whois from 'whois-json';
import { createPublicClient, http, formatEther, formatUnits, isAddress } from 'viem';
import { mainnet, base, arbitrum, optimism, polygon, celo } from 'viem/chains';
import { spawn } from 'child_process';
import { resolve, resolve4 } from 'dns/promises';

const PORT = process.env.PORT || 3100;
const MAX_BROWSERS = parseInt(process.env.MAX_BROWSERS, 10) || 3;
const MAX_SSE_SESSIONS = parseInt(process.env.MAX_SSE_SESSIONS, 10) || 50;
const MAX_PDF_BYTES = 50 * 1024 * 1024; // 50 MB
const MAX_CONTENT_LENGTH = 2 * 1024 * 1024; // 2 MB for html2md/ocr text
let activeBrowsers = 0;

// ─── Chain configs ───
const CHAINS = {
  ethereum: { chain: mainnet, rpc: 'https://ethereum-rpc.publicnode.com' },
  base: { chain: base, rpc: 'https://base-rpc.publicnode.com' },
  arbitrum: { chain: arbitrum, rpc: 'https://arbitrum-one-rpc.publicnode.com' },
  optimism: { chain: optimism, rpc: 'https://optimism-rpc.publicnode.com' },
  polygon: { chain: polygon, rpc: 'https://polygon-bor-rpc.publicnode.com' },
  celo: { chain: celo, rpc: 'https://forno.celo.org' },
};

// ─── Shared helpers ───

function launchBrowser() {
  return puppeteer.launch({
    executablePath: process.env.CHROMIUM_PATH || '/usr/bin/chromium-browser',
    headless: true,
    // --no-sandbox is required when running inside containers (Aleph Cloud)
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
  });
}

async function withBrowser(fn, res) {
  if (activeBrowsers >= MAX_BROWSERS) {
    if (res) return res.status(429).json({ error: 'Too many concurrent requests, try again later' });
    throw new Error('Too many concurrent requests');
  }
  activeBrowsers++;
  let browser;
  try {
    browser = await launchBrowser();
    return await fn(browser);
  } finally {
    activeBrowsers--;
    if (browser) await browser.close();
  }
}

// Check if an IP address is private/internal
function isPrivateIp(ip) {
  // IPv4
  const parts = ip.split('.');
  if (parts.length === 4 && parts.every(p => !isNaN(p))) {
    const [a, b] = parts.map(Number);
    if (a === 10) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 127) return true;
    if (a === 169 && b === 254) return true; // Link-local + cloud metadata
    if (a === 0) return true;
  }
  // IPv6 private ranges
  const clean = ip.replace(/^\[|\]$/g, '').toLowerCase();
  if (clean.startsWith('fc') || clean.startsWith('fd')) return true;
  if (clean.startsWith('fe80')) return true;
  if (clean === '::' || clean === '::1') return true;
  if (clean.startsWith('::ffff:')) {
    const mapped = clean.slice(7);
    return isPrivateIp(mapped);
  }
  return false;
}

// URL validation — block SSRF (synchronous parse-time check)
function validateUrl(urlStr) {
  try {
    const u = new URL(urlStr);
    if (!['http:', 'https:'].includes(u.protocol)) return false;
    const host = u.hostname.toLowerCase();

    // Loopback
    if (host === 'localhost' || host === '127.0.0.1' || host === '::1') return false;
    if (host === '[::1]') return false;

    // IPv4-mapped IPv6 (::ffff:x.x.x.x)
    const v4mapped = host.match(/^(?:\[?::ffff:)?(\d+\.\d+\.\d+\.\d+)\]?$/);
    const ipv4 = v4mapped ? v4mapped[1] : host;

    if (isPrivateIp(ipv4)) return false;

    // IPv6 private ranges
    if (host.startsWith('[') || host.includes(':')) {
      if (isPrivateIp(host)) return false;
    }

    // Cloud metadata and internal domains
    if (host.endsWith('.internal') || host.endsWith('.local')) return false;
    if (host === 'metadata.google.internal') return false;

    return true;
  } catch { return false; }
}

// Async URL validation — resolves DNS and checks all IPs against blocklist
// Prevents DNS rebinding by verifying resolved IPs before browser access
async function validateUrlAsync(urlStr) {
  if (!validateUrl(urlStr)) return false;
  try {
    const u = new URL(urlStr);
    const host = u.hostname.toLowerCase();
    // If it's already an IP literal, no DNS resolution needed
    if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) return true; // already checked by validateUrl
    if (host.startsWith('[')) return true; // already checked by validateUrl
    const addrs = await resolve4(host);
    return addrs.every(ip => !isPrivateIp(ip));
  } catch {
    // DNS resolution failed — could be a non-existent domain, let Puppeteer handle the error
    return true;
  }
}

// Set up Puppeteer request interception to block SSRF via redirects
async function setupSsrfProtection(page) {
  await page.setRequestInterception(true);
  page.on('request', (req) => {
    const reqUrl = req.url();
    if (!validateUrl(reqUrl)) {
      req.abort('blockedbyclient');
    } else {
      req.continue();
    }
  });
}

// Domain validation — prevent command injection
function validateDomain(domain) {
  if (!domain || typeof domain !== 'string') return false;
  if (domain.length > 253) return false;
  return /^[a-zA-Z0-9][a-zA-Z0-9.\-]*[a-zA-Z0-9]$/.test(domain);
}

// DNS record type allowlist
const VALID_DNS_TYPES = new Set(['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']);

// Clamp viewport dimensions
function clampInt(val, fallback, min, max) {
  const n = parseInt(val, 10);
  if (isNaN(n)) return fallback;
  return Math.min(Math.max(n, min), max);
}

// Async openssl — non-blocking alternative to spawnSync
function runOpenssl(args, input = '', timeout = 10000) {
  return new Promise((resolve, reject) => {
    const proc = spawn('openssl', args, { timeout });
    let stdout = '';
    let stderr = '';
    if (input) proc.stdin.write(input);
    proc.stdin.end();
    proc.stdout.on('data', (d) => { stdout += d; });
    proc.stderr.on('data', (d) => { stderr += d; });
    proc.on('close', (code) => resolve({ stdout, stderr, code }));
    proc.on('error', reject);
  });
}

// Parse SSL cert output
function parseCertOutput(raw) {
  const lines = raw.split('\n').filter(Boolean);
  const cert = {};
  for (const line of lines) {
    const [key, ...val] = line.split('=');
    const k = key.trim().toLowerCase();
    if (k === 'subject') cert.subject = val.join('=').trim();
    else if (k === 'issuer') cert.issuer = val.join('=').trim();
    else if (k.includes('notbefore')) cert.validFrom = val.join('=').trim();
    else if (k.includes('notafter')) cert.validUntil = val.join('=').trim();
    else if (k === 'serial') cert.serial = val.join('=').trim();
    else if (k.includes('fingerprint')) cert.fingerprint = val.join('=').trim();
  }
  if (cert.validUntil) {
    const expiry = new Date(cert.validUntil);
    const daysLeft = Math.floor((expiry - new Date()) / 86400000);
    cert.daysUntilExpiry = daysLeft;
    cert.expired = daysLeft < 0;
    cert.expiringSoon = daysLeft >= 0 && daysLeft < 30;
  }
  return cert;
}

// ─── Express API ───
const app = express();
app.use(express.json());

// Health
app.get('/health', (_, res) => res.json({ status: 'ok', services: ['screenshot', 'whois', 'blockchain'] }));

// Screenshot endpoint
app.get('/api/screenshot', async (req, res) => {
  const { url, format = 'png', width = 1280, height = 800, fullPage = false } = req.query;
  if (!url) return res.status(400).json({ error: 'url parameter required' });
  if (!validateUrl(url)) return res.status(400).json({ error: 'Invalid or blocked URL' });
  if (!await validateUrlAsync(url)) return res.status(400).json({ error: 'URL resolves to blocked address' });

  const w = clampInt(width, 1280, 100, 3840);
  const h = clampInt(height, 800, 100, 2160);

  try {
    const result = await withBrowser(async (browser) => {
      const page = await browser.newPage();
      await setupSsrfProtection(page);
      await page.setViewport({ width: w, height: h });
      await page.goto(url, { waitUntil: 'networkidle2', timeout: 30000 });

      const screenshot = await page.screenshot({
        type: format === 'jpeg' ? 'jpeg' : 'png',
        fullPage: fullPage === 'true',
        encoding: 'base64'
      });

      return {
        url, format,
        width: w, height: h,
        fullPage: fullPage === 'true',
        image: `data:image/${format};base64,${screenshot}`,
        size: screenshot.length
      };
    }, res);
    if (result) res.json(result);
  } catch (err) {
    console.error('[screenshot]', err);
    if (!res.headersSent) res.status(500).json({ error: 'Screenshot failed' });
  }
});

// PDF endpoint
app.get('/api/pdf', async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: 'url parameter required' });
  if (!validateUrl(url)) return res.status(400).json({ error: 'Invalid or blocked URL' });
  if (!await validateUrlAsync(url)) return res.status(400).json({ error: 'URL resolves to blocked address' });

  try {
    const pdf = await withBrowser(async (browser) => {
      const page = await browser.newPage();
      await setupSsrfProtection(page);
      await page.goto(url, { waitUntil: 'networkidle2', timeout: 30000 });
      const buf = await page.pdf({ format: 'A4', printBackground: true });
      if (buf.length > MAX_PDF_BYTES) throw new Error('PDF too large');
      return buf;
    }, res);
    if (pdf) {
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="page.pdf"`);
      res.send(pdf);
    }
  } catch (err) {
    console.error('[pdf]', err);
    if (!res.headersSent) res.status(500).json({ error: 'PDF generation failed' });
  }
});

// WHOIS endpoint
app.get('/api/whois', async (req, res) => {
  const { domain } = req.query;
  if (!domain) return res.status(400).json({ error: 'domain parameter required' });
  if (!validateDomain(domain)) return res.status(400).json({ error: 'Invalid domain' });

  try {
    const result = await whois(domain);
    res.json({ domain, whois: result });
  } catch (err) {
    console.error('[whois]', err);
    res.status(500).json({ error: 'WHOIS lookup failed' });
  }
});

// DNS endpoint
app.get('/api/dns', async (req, res) => {
  const { domain, type = 'A' } = req.query;
  if (!domain) return res.status(400).json({ error: 'domain parameter required' });
  if (!validateDomain(domain)) return res.status(400).json({ error: 'Invalid domain' });

  try {
    const records = {};
    const types = type === 'ALL' ? [...VALID_DNS_TYPES] : [type.toUpperCase()];

    for (const t of types) {
      if (!VALID_DNS_TYPES.has(t)) { records[t] = null; continue; }
      try {
        switch (t) {
          case 'A': records.A = await resolve(domain, 'A'); break;
          case 'AAAA': records.AAAA = await resolve(domain, 'AAAA'); break;
          case 'MX': records.MX = await resolve(domain, 'MX'); break;
          case 'NS': records.NS = await resolve(domain, 'NS'); break;
          case 'TXT': records.TXT = await resolve(domain, 'TXT'); break;
          case 'CNAME': records.CNAME = await resolve(domain, 'CNAME'); break;
          case 'SOA': records.SOA = await resolve(domain, 'SOA'); break;
        }
      } catch (e) {
        records[t] = null;
      }
    }
    res.json({ domain, records });
  } catch (err) {
    console.error('[dns]', err);
    res.status(500).json({ error: 'DNS lookup failed' });
  }
});

// Blockchain - Balance
app.get('/api/chain/balance', async (req, res) => {
  const { address, chain = 'ethereum' } = req.query;
  if (!address) return res.status(400).json({ error: 'address parameter required' });
  if (!isAddress(address)) return res.status(400).json({ error: 'Invalid address' });

  const chainConfig = CHAINS[chain.toLowerCase()];
  if (!chainConfig) return res.status(400).json({ error: `Unknown chain: ${chain}. Available: ${Object.keys(CHAINS).join(', ')}` });

  try {
    const client = createPublicClient({ chain: chainConfig.chain, transport: http(chainConfig.rpc) });
    const balance = await client.getBalance({ address });
    const symbol = chainConfig.chain.nativeCurrency.symbol;

    res.json({
      address, chain,
      balance: formatEther(balance),
      symbol,
      raw: balance.toString()
    });
  } catch (err) {
    console.error('[balance]', err);
    res.status(500).json({ error: 'Balance lookup failed' });
  }
});

// Blockchain - Transaction
app.get('/api/chain/tx', async (req, res) => {
  const { hash, chain = 'ethereum' } = req.query;
  if (!hash) return res.status(400).json({ error: 'hash parameter required' });
  if (!/^0x[a-fA-F0-9]{64}$/.test(hash)) return res.status(400).json({ error: 'Invalid transaction hash' });

  const chainConfig = CHAINS[chain.toLowerCase()];
  if (!chainConfig) return res.status(400).json({ error: `Unknown chain: ${chain}` });

  try {
    const client = createPublicClient({ chain: chainConfig.chain, transport: http(chainConfig.rpc) });
    const tx = await client.getTransaction({ hash });
    if (!tx) return res.status(404).json({ error: 'Transaction not found' });
    const receipt = await client.getTransactionReceipt({ hash });
    if (!receipt) return res.status(404).json({ error: 'Transaction receipt not found (pending?)' });

    res.json({
      hash, chain,
      from: tx.from,
      to: tx.to,
      value: formatEther(tx.value),
      gasUsed: receipt.gasUsed.toString(),
      status: receipt.status,
      blockNumber: Number(tx.blockNumber)
    });
  } catch (err) {
    console.error('[tx]', err);
    res.status(500).json({ error: 'Transaction lookup failed' });
  }
});

// Blockchain - ERC20 balance
app.get('/api/chain/erc20', async (req, res) => {
  const { address, token, chain = 'ethereum' } = req.query;
  if (!address || !token) return res.status(400).json({ error: 'address and token parameters required' });
  if (!isAddress(address)) return res.status(400).json({ error: 'Invalid address' });
  if (!isAddress(token)) return res.status(400).json({ error: 'Invalid token address' });

  const chainConfig = CHAINS[chain.toLowerCase()];
  if (!chainConfig) return res.status(400).json({ error: `Unknown chain: ${chain}` });

  try {
    const client = createPublicClient({ chain: chainConfig.chain, transport: http(chainConfig.rpc) });
    const erc20Abi = [
      { name: 'balanceOf', type: 'function', stateMutability: 'view', inputs: [{ name: 'account', type: 'address' }], outputs: [{ type: 'uint256' }] },
      { name: 'decimals', type: 'function', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint8' }] },
      { name: 'symbol', type: 'function', stateMutability: 'view', inputs: [], outputs: [{ type: 'string' }] },
    ];

    const [balance, decimals, symbol] = await Promise.all([
      client.readContract({ address: token, abi: erc20Abi, functionName: 'balanceOf', args: [address] }),
      client.readContract({ address: token, abi: erc20Abi, functionName: 'decimals' }),
      client.readContract({ address: token, abi: erc20Abi, functionName: 'symbol' }),
    ]);

    res.json({ address, token, chain, balance: formatUnits(balance, decimals), symbol, decimals });
  } catch (err) {
    console.error('[erc20]', err);
    res.status(500).json({ error: 'ERC20 balance lookup failed' });
  }
});

// HTML to Markdown
app.get('/api/html2md', async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: 'url parameter required' });
  if (!validateUrl(url)) return res.status(400).json({ error: 'Invalid or blocked URL' });
  if (!await validateUrlAsync(url)) return res.status(400).json({ error: 'URL resolves to blocked address' });

  try {
    const result = await withBrowser(async (browser) => {
      const page = await browser.newPage();
      await setupSsrfProtection(page);
      await page.goto(url, { waitUntil: 'networkidle2', timeout: 30000 });

      const content = await page.evaluate((maxLen) => {
        const remove = document.querySelectorAll('script, style, nav, footer, aside, [role="banner"], [role="navigation"], .ad, .ads, .sidebar');
        remove.forEach(el => el.remove());

        const article = document.querySelector('article, main, [role="main"]') || document.body;

        function nodeToMd(node, depth = 0) {
          if (node.nodeType === 3) return node.textContent;
          if (node.nodeType !== 1) return '';

          const tag = node.tagName.toLowerCase();
          const children = Array.from(node.childNodes).map(c => nodeToMd(c, depth)).join('');

          switch (tag) {
            case 'h1': return `\n# ${children.trim()}\n`;
            case 'h2': return `\n## ${children.trim()}\n`;
            case 'h3': return `\n### ${children.trim()}\n`;
            case 'h4': return `\n#### ${children.trim()}\n`;
            case 'p': return `\n${children.trim()}\n`;
            case 'br': return '\n';
            case 'strong': case 'b': return `**${children.trim()}**`;
            case 'em': case 'i': return `*${children.trim()}*`;
            case 'a': return `[${children.trim()}](${node.href || ''})`;
            case 'code': return `\`${children.trim()}\``;
            case 'pre': return `\n\`\`\`\n${children.trim()}\n\`\`\`\n`;
            case 'li': return `- ${children.trim()}\n`;
            case 'ul': case 'ol': return `\n${children}`;
            case 'blockquote': return `\n> ${children.trim()}\n`;
            case 'img': return `![${node.alt || ''}](${node.src || ''})`;
            case 'table': return `\n${children}\n`;
            case 'tr': return children + '\n';
            case 'th': case 'td': return `| ${children.trim()} `;
            default: return children;
          }
        }

        const md = nodeToMd(article).replace(/\n{3,}/g, '\n\n').trim();
        return md.length > maxLen ? md.slice(0, maxLen) + '\n\n[Content truncated]' : md;
      }, MAX_CONTENT_LENGTH);

      const title = await page.title();
      return { url, title, markdown: content, length: content.length };
    }, res);
    if (result) res.json(result);
  } catch (err) {
    console.error('[html2md]', err);
    if (!res.headersSent) res.status(500).json({ error: 'Content extraction failed' });
  }
});

// OCR — extract text from image URL
app.get('/api/ocr', async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: 'url parameter required' });
  if (!validateUrl(url)) return res.status(400).json({ error: 'Invalid or blocked URL' });
  if (!await validateUrlAsync(url)) return res.status(400).json({ error: 'URL resolves to blocked address' });

  try {
    const result = await withBrowser(async (browser) => {
      const page = await browser.newPage();
      await setupSsrfProtection(page);

      await page.setContent(`
        <script src="https://cdn.jsdelivr.net/npm/tesseract.js@5.1.1/dist/tesseract.min.js"></script>
        <img id="img" crossorigin="anonymous" />
      `);

      const text = await page.evaluate(async (imageUrl) => {
        const { createWorker } = window.Tesseract;
        const worker = await createWorker('eng');
        const { data: { text } } = await worker.recognize(imageUrl);
        await worker.terminate();
        return text;
      }, url);

      return { url, text: text.trim(), length: text.trim().length };
    }, res);
    if (result) res.json(result);
  } catch (err) {
    console.error('[ocr]', err);
    if (!res.headersSent) res.status(500).json({ error: 'OCR extraction failed' });
  }
});

// SSL Certificate checker — async spawn to avoid blocking event loop
app.get('/api/ssl', async (req, res) => {
  const { domain } = req.query;
  if (!domain) return res.status(400).json({ error: 'domain parameter required' });
  if (!validateDomain(domain)) return res.status(400).json({ error: 'Invalid domain' });

  try {
    const connect = await runOpenssl(
      ['s_client', '-servername', domain, '-connect', `${domain}:443`],
      '', 10000
    );
    const x509 = await runOpenssl(
      ['x509', '-noout', '-subject', '-issuer', '-dates', '-serial', '-fingerprint'],
      connect.stdout || '', 5000
    );
    const cert = parseCertOutput(x509.stdout || '');
    res.json({ domain, certificate: cert });
  } catch (err) {
    console.error('[ssl]', err);
    res.status(500).json({ error: 'SSL check failed' });
  }
});

// ─── MCP Server ───
const mcpServer = new McpServer({
  name: 'mcp-services',
  version: '1.0.0',
});

// Register MCP tools
mcpServer.tool('screenshot', 'Take a screenshot of any URL. Returns base64 PNG/JPEG image.', {
  url: { type: 'string', description: 'URL to screenshot' },
  format: { type: 'string', description: 'png or jpeg', default: 'png' },
  width: { type: 'number', description: 'Viewport width', default: 1280 },
  height: { type: 'number', description: 'Viewport height', default: 800 },
  fullPage: { type: 'boolean', description: 'Capture full scrollable page', default: false },
}, async ({ url, format = 'png', width = 1280, height = 800, fullPage = false }) => {
  if (!validateUrl(url)) throw new Error('Invalid or blocked URL');
  if (!await validateUrlAsync(url)) throw new Error('URL resolves to blocked address');
  const w = clampInt(width, 1280, 100, 3840);
  const h = clampInt(height, 800, 100, 2160);
  return withBrowser(async (browser) => {
    const page = await browser.newPage();
    await setupSsrfProtection(page);
    await page.setViewport({ width: w, height: h });
    await page.goto(url, { waitUntil: 'networkidle2', timeout: 30000 });
    const screenshot = await page.screenshot({ type: format === 'jpeg' ? 'jpeg' : 'png', fullPage, encoding: 'base64' });
    return { content: [{ type: 'image', data: screenshot, mimeType: `image/${format}` }] };
  });
});

mcpServer.tool('pdf', 'Generate a PDF of any URL.', {
  url: { type: 'string', description: 'URL to convert to PDF' },
}, async ({ url }) => {
  if (!validateUrl(url)) throw new Error('Invalid or blocked URL');
  if (!await validateUrlAsync(url)) throw new Error('URL resolves to blocked address');
  return withBrowser(async (browser) => {
    const page = await browser.newPage();
    await setupSsrfProtection(page);
    await page.goto(url, { waitUntil: 'networkidle2', timeout: 30000 });
    const pdf = await page.pdf({ format: 'A4', printBackground: true });
    if (pdf.length > MAX_PDF_BYTES) throw new Error('PDF too large');
    return { content: [{ type: 'resource', uri: `data:application/pdf;base64,${pdf.toString('base64')}`, mimeType: 'application/pdf' }] };
  });
});

mcpServer.tool('whois', 'Look up WHOIS information for a domain.', {
  domain: { type: 'string', description: 'Domain name to look up' },
}, async ({ domain }) => {
  if (!validateDomain(domain)) throw new Error('Invalid domain');
  const result = await whois(domain);
  return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
});

mcpServer.tool('dns', 'Look up DNS records for a domain.', {
  domain: { type: 'string', description: 'Domain name' },
  type: { type: 'string', description: 'Record type: A, AAAA, MX, NS, TXT, CNAME, SOA, or ALL', default: 'ALL' },
}, async ({ domain, type = 'ALL' }) => {
  if (!validateDomain(domain)) throw new Error('Invalid domain');
  const records = {};
  const types = type === 'ALL' ? [...VALID_DNS_TYPES] : [type.toUpperCase()];
  for (const t of types) {
    if (!VALID_DNS_TYPES.has(t)) { records[t] = null; continue; }
    try {
      records[t] = await resolve(domain, t);
    } catch { records[t] = null; }
  }
  return { content: [{ type: 'text', text: JSON.stringify({ domain, records }, null, 2) }] };
});

mcpServer.tool('balance', 'Get native token balance for an address on any supported chain.', {
  address: { type: 'string', description: 'Wallet address' },
  chain: { type: 'string', description: 'Chain name: ethereum, base, arbitrum, optimism, polygon, celo', default: 'ethereum' },
}, async ({ address, chain = 'ethereum' }) => {
  if (!isAddress(address)) throw new Error('Invalid address');
  const chainConfig = CHAINS[chain.toLowerCase()];
  if (!chainConfig) throw new Error(`Unknown chain: ${chain}`);
  const client = createPublicClient({ chain: chainConfig.chain, transport: http(chainConfig.rpc) });
  const balance = await client.getBalance({ address });
  const symbol = chainConfig.chain.nativeCurrency.symbol;
  return { content: [{ type: 'text', text: JSON.stringify({ address, chain, balance: formatEther(balance), symbol }) }] };
});

mcpServer.tool('erc20_balance', 'Get ERC20 token balance for an address.', {
  address: { type: 'string', description: 'Wallet address' },
  token: { type: 'string', description: 'Token contract address' },
  chain: { type: 'string', description: 'Chain name', default: 'ethereum' },
}, async ({ address, token, chain = 'ethereum' }) => {
  if (!isAddress(address)) throw new Error('Invalid address');
  if (!isAddress(token)) throw new Error('Invalid token address');
  const chainConfig = CHAINS[chain.toLowerCase()];
  if (!chainConfig) throw new Error(`Unknown chain: ${chain}`);
  const client = createPublicClient({ chain: chainConfig.chain, transport: http(chainConfig.rpc) });
  const erc20Abi = [
    { name: 'balanceOf', type: 'function', stateMutability: 'view', inputs: [{ name: 'account', type: 'address' }], outputs: [{ type: 'uint256' }] },
    { name: 'decimals', type: 'function', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint8' }] },
    { name: 'symbol', type: 'function', stateMutability: 'view', inputs: [], outputs: [{ type: 'string' }] },
  ];
  const [balance, decimals, symbol] = await Promise.all([
    client.readContract({ address: token, abi: erc20Abi, functionName: 'balanceOf', args: [address] }),
    client.readContract({ address: token, abi: erc20Abi, functionName: 'decimals' }),
    client.readContract({ address: token, abi: erc20Abi, functionName: 'symbol' }),
  ]);
  return { content: [{ type: 'text', text: JSON.stringify({ address, token, chain, balance: formatUnits(balance, decimals), symbol, decimals }) }] };
});

mcpServer.tool('transaction', 'Get transaction details by hash.', {
  hash: { type: 'string', description: 'Transaction hash' },
  chain: { type: 'string', description: 'Chain name', default: 'ethereum' },
}, async ({ hash, chain = 'ethereum' }) => {
  if (!/^0x[a-fA-F0-9]{64}$/.test(hash)) throw new Error('Invalid transaction hash');
  const chainConfig = CHAINS[chain.toLowerCase()];
  if (!chainConfig) throw new Error(`Unknown chain: ${chain}`);
  const client = createPublicClient({ chain: chainConfig.chain, transport: http(chainConfig.rpc) });
  const tx = await client.getTransaction({ hash });
  if (!tx) throw new Error('Transaction not found');
  const receipt = await client.getTransactionReceipt({ hash });
  if (!receipt) throw new Error('Transaction receipt not found (pending?)');
  return { content: [{ type: 'text', text: JSON.stringify({
    hash, chain, from: tx.from, to: tx.to, value: formatEther(tx.value),
    gasUsed: receipt.gasUsed.toString(), status: receipt.status, blockNumber: Number(tx.blockNumber)
  }, null, 2) }] };
});

mcpServer.tool('html2md', 'Fetch a URL and convert the page content to clean Markdown. Removes nav, ads, scripts.', {
  url: { type: 'string', description: 'URL to fetch and convert' },
}, async ({ url }) => {
  if (!validateUrl(url)) throw new Error('Invalid or blocked URL');
  if (!await validateUrlAsync(url)) throw new Error('URL resolves to blocked address');
  return withBrowser(async (browser) => {
    const page = await browser.newPage();
    await setupSsrfProtection(page);
    await page.goto(url, { waitUntil: 'networkidle2', timeout: 30000 });
    const content = await page.evaluate(() => {
      document.querySelectorAll('script, style, nav, footer, aside, .ad, .ads, .sidebar').forEach(el => el.remove());
      const article = document.querySelector('article, main, [role="main"]') || document.body;
      return article.innerText;
    });
    const title = await page.title();
    const text = content.replace(/\n{3,}/g, '\n\n').trim();
    const truncated = text.length > 2097152 ? text.slice(0, 2097152) + '\n\n[Content truncated]' : text;
    return { content: [{ type: 'text', text: `# ${title}\n\n${truncated}` }] };
  });
});

mcpServer.tool('ocr', 'Extract text from an image URL using OCR.', {
  url: { type: 'string', description: 'Image URL to extract text from' },
}, async ({ url }) => {
  if (!validateUrl(url)) throw new Error('Invalid or blocked URL');
  if (!await validateUrlAsync(url)) throw new Error('URL resolves to blocked address');
  return withBrowser(async (browser) => {
    const page = await browser.newPage();
    await setupSsrfProtection(page);
    await page.setContent(`<script src="https://cdn.jsdelivr.net/npm/tesseract.js@5.1.1/dist/tesseract.min.js"></script>`);
    const text = await page.evaluate(async (imageUrl) => {
      const { createWorker } = window.Tesseract;
      const worker = await createWorker('eng');
      const { data: { text } } = await worker.recognize(imageUrl);
      await worker.terminate();
      return text;
    }, url);
    return { content: [{ type: 'text', text: text.trim() }] };
  });
});

mcpServer.tool('ssl', 'Check SSL certificate details for a domain. Returns issuer, validity dates, expiry status.', {
  domain: { type: 'string', description: 'Domain to check SSL certificate for' },
}, async ({ domain }) => {
  if (!validateDomain(domain)) throw new Error('Invalid domain');
  const connect = await runOpenssl(
    ['s_client', '-servername', domain, '-connect', `${domain}:443`],
    '', 10000
  );
  const x509 = await runOpenssl(
    ['x509', '-noout', '-subject', '-issuer', '-dates', '-serial'],
    connect.stdout || '', 5000
  );
  const cert = parseCertOutput(x509.stdout || '');
  return { content: [{ type: 'text', text: JSON.stringify({ domain, certificate: cert }, null, 2) }] };
});

// ─── SSE Transport for MCP ───
const transports = {};

app.get('/mcp/sse', async (req, res) => {
  if (Object.keys(transports).length >= MAX_SSE_SESSIONS) {
    return res.status(429).json({ error: 'Too many active sessions' });
  }

  const transport = new SSEServerTransport('/mcp/messages', res);
  transports[transport.sessionId] = transport;

  const cleanup = () => { delete transports[transport.sessionId]; };
  res.on('close', cleanup);
  res.on('error', cleanup);

  try {
    await mcpServer.connect(transport);
  } catch (err) {
    console.error('[mcp]', err);
    cleanup();
    if (!res.headersSent) res.status(500).end();
  }
});

app.post('/mcp/messages', async (req, res) => {
  const sessionId = req.query.sessionId;
  const transport = transports[sessionId];
  if (!transport) return res.status(400).json({ error: 'Unknown session' });
  try {
    await transport.handlePostMessage(req, res);
  } catch (err) {
    console.error('[mcp/messages]', err);
    if (!res.headersSent) res.status(500).json({ error: 'Message handling failed' });
  }
});

// ─── Start ───
app.listen(PORT, '0.0.0.0', () => {
  console.log(`MCP Services running on port ${PORT}`);
  console.log(`  HTTP API: http://localhost:${PORT}/api/`);
  console.log(`  MCP SSE:  http://localhost:${PORT}/mcp/sse`);
  console.log(`  Health:   http://localhost:${PORT}/health`);
});
