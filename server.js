#!/usr/bin/env node
import 'dotenv/config';
import crypto from 'crypto';
import express from 'express';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import puppeteer from 'puppeteer-core';
import whois from 'whois-json';
import { createPublicClient, http, formatEther, formatUnits, isAddress } from 'viem';
import { mainnet, base, arbitrum, optimism, polygon, celo } from 'viem/chains';
import { spawn } from 'child_process';
import { resolve, resolve4 } from 'dns/promises';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { authMiddleware, adminRoutes, mcpAuth } from './auth.js';
import { stripeRoutes } from './stripe.js';
import { scrapeUrl, crawlSite, extractData, DOM_TO_MD_SCRIPT } from './scrape.js';
import { serpScrape, onpageSeo, keywordsSuggest } from './seo.js';
import { memoryStore, memoryGet, memorySearch, memoryList, memoryDelete, resolveNamespace } from './memory.js';
import { urlScan, walletCheck, contractScan, emailHeaders, threatIntel, headerAudit, vulnHeaders } from './security.js';
import { getDocument } from 'pdfjs-dist/legacy/build/pdf.mjs';
import { Document as DocxDocument, Packer, Paragraph, TextRun, HeadingLevel } from 'docx';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const PORT = process.env.PORT || 3100;
const MAX_BROWSERS = parseInt(process.env.MAX_BROWSERS, 10) || 3;
const MAX_SSE_SESSIONS = parseInt(process.env.MAX_SSE_SESSIONS, 10) || 50;
const MAX_PDF_BYTES = 50 * 1024 * 1024; // 50 MB
const MAX_CONTENT_LENGTH = 2 * 1024 * 1024; // 2 MB for html2md/ocr text
let activeBrowsers = 0;

// ─── PDF to DOCX conversion helper ───
const MAX_PDF_PAGES = 200;

async function convertPdfToDocx(pdfBuffer) {
  const doc = await getDocument({ data: new Uint8Array(pdfBuffer) }).promise;
  const paragraphs = [];
  const pageCount = Math.min(doc.numPages, MAX_PDF_PAGES);

  for (let i = 1; i <= pageCount; i++) {
    const page = await doc.getPage(i);
    const content = await page.getTextContent();
    const lines = [];
    let currentLine = '';
    let lastY = null;
    for (const item of content.items) {
      if (lastY !== null && Math.abs(item.transform[5] - lastY) > 2) {
        lines.push(currentLine);
        currentLine = '';
      }
      currentLine += (currentLine && lastY !== null && Math.abs(item.transform[5] - lastY) <= 2 ? ' ' : '') + item.str;
      lastY = item.transform[5];
    }
    if (currentLine) lines.push(currentLine);

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) { paragraphs.push(new Paragraph({ text: '' })); continue; }
      const isHeading = trimmed.length < 100 && trimmed === trimmed.toUpperCase() && /[A-Z]/.test(trimmed);
      paragraphs.push(new Paragraph({
        children: [new TextRun({ text: trimmed, bold: isHeading, size: isHeading ? 28 : 22 })],
        heading: isHeading ? HeadingLevel.HEADING_2 : undefined,
      }));
    }
    if (i < pageCount) paragraphs.push(new Paragraph({ text: '' }));
  }
  doc.destroy();

  const wordDoc = new DocxDocument({
    sections: [{ properties: {}, children: paragraphs }],
    creator: 'MCP Services',
    title: 'Converted PDF',
  });
  return Packer.toBuffer(wordDoc);
}

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
    // DNS resolution failed — fail closed to prevent SSRF bypass
    return false;
  }
}

// SSRF-safe fetch — resolves DNS upfront, pins the IP, and fetches via IP with Host header
// Prevents DNS rebinding between validateUrlAsync() and the actual fetch()
const MAX_REDIRECTS = 5;
async function ssrfSafeFetch(urlStr, opts = {}, _depth = 0) {
  if (_depth > MAX_REDIRECTS) throw new Error(`Too many redirects (max ${MAX_REDIRECTS})`);
  const u = new URL(urlStr);
  const host = u.hostname.toLowerCase();
  let targetUrl = urlStr;

  // Resolve DNS and pin the IP for non-IP-literal hosts
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(host) && !host.startsWith('[')) {
    const addrs = await resolve4(host);
    if (!addrs.length) throw new Error('DNS resolution failed');
    if (!addrs.every(ip => !isPrivateIp(ip))) throw new Error('URL resolves to blocked address');
    // Replace hostname with resolved IP, pass original Host via header
    u.hostname = addrs[0];
    targetUrl = u.toString();
    opts.headers = { ...opts.headers, Host: host };
  }

  const resp = await fetch(targetUrl, { ...opts, redirect: 'manual' });

  // Block redirects to internal addresses
  if ([301, 302, 303, 307, 308].includes(resp.status)) {
    const location = resp.headers.get('location');
    if (location) {
      const redirectUrl = new URL(location, urlStr);
      if (!validateUrl(redirectUrl.href)) throw new Error('Redirect to blocked URL');
      if (!await validateUrlAsync(redirectUrl.href)) throw new Error('Redirect resolves to blocked address');
      return ssrfSafeFetch(redirectUrl.href, opts, _depth + 1);
    }
  }

  return resp;
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
// Domain args are validated by validateDomain() (requires alphanumeric first char, blocking --flag).
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
app.set('trust proxy', 1); // Trust first proxy — required for accurate req.ip behind reverse proxy

// Stripe billing routes FIRST (webhook needs raw body before express.json parses it)
stripeRoutes(app);

// JSON body parser (after webhook route)
app.use(express.json({ limit: '100kb' }));

// Auth & billing middleware
app.use(authMiddleware);
adminRoutes(app);

// ─── Static files & SEO ───
app.use(express.static(join(__dirname, 'public'), {
  maxAge: '1h',
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'public, max-age=3600');
    }
  }
}));

// Landing page fallback
app.get('/', (_, res) => {
  res.sendFile(join(__dirname, 'public', 'index.html'));
});

// MCP OAuth — not supported, return proper JSON so clients don't choke on HTML 404s
app.get('/.well-known/oauth-authorization-server', (_, res) => {
  res.status(404).json({ error: 'OAuth not supported. Connect to /mcp/sse directly (free tier) or with ?apikey=YOUR_KEY.' });
});
app.all('/oauth/:path*', (_, res) => {
  res.status(404).json({ error: 'OAuth not supported.' });
});

// Health
app.get('/health', (_, res) => res.json({
  status: 'ok',
  services: ['scrape', 'crawl', 'extract', 'serp', 'onpage-seo', 'keywords', 'memory-store', 'memory-get', 'memory-search', 'memory-list', 'memory-delete', 'screenshot', 'pdf', 'pdf2docx', 'html2md', 'ocr', 'whois', 'dns', 'ssl', 'balance', 'erc20', 'transaction', 'url-scan', 'wallet-check', 'contract-scan', 'email-headers', 'threat-intel', 'header-audit', 'vuln-headers']
}));

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

// PDF to DOCX endpoint
app.get('/api/pdf2docx', async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: 'url parameter required (URL to a PDF file)' });
  if (!validateUrl(url)) return res.status(400).json({ error: 'Invalid or blocked URL' });
  if (!await validateUrlAsync(url)) return res.status(400).json({ error: 'URL resolves to blocked address' });

  try {
    const resp = await ssrfSafeFetch(url);
    if (!resp.ok) throw new Error(`Failed to fetch PDF: HTTP ${resp.status}`);
    const contentType = resp.headers.get('content-type') || '';
    if (!contentType.includes('pdf') && !new URL(url).pathname.toLowerCase().endsWith('.pdf')) {
      return res.status(400).json({ error: 'URL does not appear to be a PDF file' });
    }
    const contentLength = parseInt(resp.headers.get('content-length'), 10);
    if (contentLength > MAX_PDF_BYTES) return res.status(400).json({ error: 'PDF too large (max 50MB)' });
    const buf = Buffer.from(await resp.arrayBuffer());
    if (buf.length > MAX_PDF_BYTES) return res.status(400).json({ error: 'PDF too large (max 50MB)' });

    const docxBuf = await convertPdfToDocx(buf);
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
    res.setHeader('Content-Disposition', 'attachment; filename="converted.docx"');
    res.send(docxBuf);
  } catch (err) {
    console.error('[pdf2docx]', err);
    if (!res.headersSent) res.status(500).json({ error: 'PDF to DOCX conversion failed' });
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

// ─── Web Scraper endpoints ───

app.get('/api/scrape', async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: 'url parameter required' });
  if (!validateUrl(url)) return res.status(400).json({ error: 'Invalid or blocked URL' });
  if (!await validateUrlAsync(url)) return res.status(400).json({ error: 'URL resolves to blocked address' });

  try {
    const result = await withBrowser(async (browser) => {
      return scrapeUrl(browser, url, setupSsrfProtection);
    }, res);
    if (result) res.json(result);
  } catch (err) {
    console.error('[scrape]', err);
    if (!res.headersSent) res.status(500).json({ error: 'Scrape failed' });
  }
});

app.get('/api/crawl', async (req, res) => {
  const { url, depth = 1, maxPages = 10 } = req.query;
  if (!url) return res.status(400).json({ error: 'url parameter required' });
  if (!validateUrl(url)) return res.status(400).json({ error: 'Invalid or blocked URL' });
  if (!await validateUrlAsync(url)) return res.status(400).json({ error: 'URL resolves to blocked address' });

  try {
    const result = await withBrowser(async (browser) => {
      return crawlSite(browser, url, parseInt(depth), parseInt(maxPages), setupSsrfProtection, validateUrl, validateUrlAsync);
    }, res);
    if (result) res.json(result);
  } catch (err) {
    console.error('[crawl]', err);
    if (!res.headersSent) res.status(500).json({ error: 'Crawl failed' });
  }
});

app.get('/api/extract', async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: 'url parameter required' });
  if (!validateUrl(url)) return res.status(400).json({ error: 'Invalid or blocked URL' });
  if (!await validateUrlAsync(url)) return res.status(400).json({ error: 'URL resolves to blocked address' });

  try {
    const result = await withBrowser(async (browser) => {
      return extractData(browser, url, setupSsrfProtection);
    }, res);
    if (result) res.json(result);
  } catch (err) {
    console.error('[extract]', err);
    if (!res.headersSent) res.status(500).json({ error: 'Extraction failed' });
  }
});

// ─── SEO Toolkit endpoints ───

app.get('/api/serp', async (req, res) => {
  const { keyword } = req.query;
  if (!keyword) return res.status(400).json({ error: 'keyword parameter required' });
  if (keyword.length > 200) return res.status(400).json({ error: 'keyword too long' });

  try {
    const result = await withBrowser(async (browser) => {
      return serpScrape(browser, keyword, setupSsrfProtection);
    }, res);
    if (result) res.json(result);
  } catch (err) {
    console.error('[serp]', err);
    if (!res.headersSent) res.status(500).json({ error: 'SERP scrape failed' });
  }
});

app.get('/api/onpage-seo', async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: 'url parameter required' });
  if (!validateUrl(url)) return res.status(400).json({ error: 'Invalid or blocked URL' });
  if (!await validateUrlAsync(url)) return res.status(400).json({ error: 'URL resolves to blocked address' });

  try {
    const result = await withBrowser(async (browser) => {
      return onpageSeo(browser, url, setupSsrfProtection);
    }, res);
    if (result) res.json(result);
  } catch (err) {
    console.error('[onpage-seo]', err);
    if (!res.headersSent) res.status(500).json({ error: 'On-page SEO analysis failed' });
  }
});

app.get('/api/keywords', async (req, res) => {
  const { keyword } = req.query;
  if (!keyword) return res.status(400).json({ error: 'keyword parameter required' });
  if (keyword.length > 200) return res.status(400).json({ error: 'keyword too long' });

  try {
    const result = await keywordsSuggest(keyword);
    res.json(result);
  } catch (err) {
    console.error('[keywords]', err);
    res.status(500).json({ error: 'Keyword suggestions failed' });
  }
});

// ─── Agent Memory endpoints ───

app.post('/api/memory', (req, res) => {
  try {
    const { namespace, key, value, tags } = req.body || {};
    if (!namespace || !key || !value) return res.status(400).json({ error: 'namespace, key, and value are required' });
    const ns = resolveNamespace(req, namespace);
    const result = memoryStore(ns, key, value, tags);
    res.json(result);
  } catch (err) {
    console.error('[memory/store]', err);
    res.status(500).json({ error: err.message || 'Memory store failed' });
  }
});

app.get('/api/memory', (req, res) => {
  try {
    const { namespace, key } = req.query;
    if (!namespace || !key) return res.status(400).json({ error: 'namespace and key are required' });
    const ns = resolveNamespace(req, namespace);
    const result = memoryGet(ns, key);
    if (!result) return res.status(404).json({ error: 'Memory not found' });
    res.json(result);
  } catch (err) {
    console.error('[memory/get]', err);
    res.status(500).json({ error: err.message || 'Memory get failed' });
  }
});

app.get('/api/memory/search', (req, res) => {
  try {
    const { namespace, query, limit } = req.query;
    if (!namespace || !query) return res.status(400).json({ error: 'namespace and query are required' });
    const ns = resolveNamespace(req, namespace);
    const result = memorySearch(ns, query, parseInt(limit) || 20);
    res.json(result);
  } catch (err) {
    console.error('[memory/search]', err);
    res.status(500).json({ error: err.message || 'Memory search failed' });
  }
});

app.get('/api/memory/list', (req, res) => {
  try {
    const { namespace, offset, limit } = req.query;
    if (!namespace) return res.status(400).json({ error: 'namespace is required' });
    const ns = resolveNamespace(req, namespace);
    const result = memoryList(ns, parseInt(offset) || 0, parseInt(limit) || 20);
    res.json(result);
  } catch (err) {
    console.error('[memory/list]', err);
    res.status(500).json({ error: err.message || 'Memory list failed' });
  }
});

app.delete('/api/memory', (req, res) => {
  try {
    const { namespace, key } = req.query;
    if (!namespace || !key) return res.status(400).json({ error: 'namespace and key are required' });
    const ns = resolveNamespace(req, namespace);
    const result = memoryDelete(ns, key);
    res.json(result);
  } catch (err) {
    console.error('[memory/delete]', err);
    res.status(500).json({ error: err.message || 'Memory delete failed' });
  }
});

// ─── Security endpoints ───

app.get('/api/security/url-scan', async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: 'url parameter required' });
  try {
    const result = await urlScan(url);
    res.json(result);
  } catch (err) {
    console.error('[url_scan]', err);
    res.status(500).json({ error: 'URL scan failed' });
  }
});

app.get('/api/security/wallet-check', async (req, res) => {
  const { address, chain = 'ethereum' } = req.query;
  if (!address) return res.status(400).json({ error: 'address parameter required' });
  try {
    const result = await walletCheck(address, chain);
    res.json(result);
  } catch (err) {
    console.error('[wallet_check]', err);
    res.status(500).json({ error: 'Wallet check failed' });
  }
});

app.get('/api/security/contract-scan', async (req, res) => {
  const { address, chainId = '1' } = req.query;
  if (!address) return res.status(400).json({ error: 'address parameter required' });
  try {
    const result = await contractScan(address, parseInt(chainId));
    res.json(result);
  } catch (err) {
    console.error('[contract_scan]', err);
    res.status(500).json({ error: 'Contract scan failed' });
  }
});

app.get('/api/security/email-headers', async (req, res) => {
  const { domain } = req.query;
  if (!domain) return res.status(400).json({ error: 'domain parameter required' });
  try {
    const result = await emailHeaders(domain);
    res.json(result);
  } catch (err) {
    console.error('[email_headers]', err);
    res.status(500).json({ error: 'Email header check failed' });
  }
});

app.get('/api/security/threat-intel', async (req, res) => {
  const { ioc, type = 'auto' } = req.query;
  if (!ioc) return res.status(400).json({ error: 'ioc parameter required' });
  try {
    const result = await threatIntel(ioc, type);
    res.json(result);
  } catch (err) {
    console.error('[threat_intel]', err);
    res.status(500).json({ error: 'Threat intel lookup failed' });
  }
});

app.get('/api/security/header-audit', async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: 'url parameter required' });
  try {
    const result = await headerAudit(url);
    res.json(result);
  } catch (err) {
    console.error('[header_audit]', err);
    res.status(500).json({ error: 'Header audit failed' });
  }
});

app.get('/api/security/vuln-headers', async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: 'url parameter required' });
  try {
    const result = await vulnHeaders(url);
    res.json(result);
  } catch (err) {
    console.error('[vuln_headers]', err);
    res.status(500).json({ error: 'Vulnerability header check failed' });
  }
});

// ─── MCP Server Factory ───
// Creates a fresh McpServer per SSE connection (SDK requires one instance per transport)
function createMcpServer() {
const mcpServer = new McpServer({
  name: 'mcp-services',
  version: '2.0.0',
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

mcpServer.tool('pdf2docx', 'Convert a PDF file (from URL) to DOCX/Word format. Extracts text and structure from the PDF and builds a Word document.', {
  url: { type: 'string', description: 'URL to a PDF file' },
}, async ({ url }) => {
  if (!validateUrl(url)) throw new Error('Invalid or blocked URL');
  if (!await validateUrlAsync(url)) throw new Error('URL resolves to blocked address');

  const resp = await ssrfSafeFetch(url);
  if (!resp.ok) throw new Error(`Failed to fetch PDF: HTTP ${resp.status}`);
  const contentType = resp.headers.get('content-type') || '';
  if (!contentType.includes('pdf') && !new URL(url).pathname.toLowerCase().endsWith('.pdf')) {
    throw new Error('URL does not appear to be a PDF file');
  }
  const contentLength = parseInt(resp.headers.get('content-length'), 10);
  if (contentLength > MAX_PDF_BYTES) throw new Error('PDF too large (max 50MB)');
  const buf = Buffer.from(await resp.arrayBuffer());
  if (buf.length > MAX_PDF_BYTES) throw new Error('PDF too large (max 50MB)');

  const docxBuf = await convertPdfToDocx(buf);
  return {
    content: [{
      type: 'resource',
      uri: `data:application/vnd.openxmlformats-officedocument.wordprocessingml.document;base64,${docxBuf.toString('base64')}`,
      mimeType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    }],
  };
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
    const result = await page.evaluate(`${DOM_TO_MD_SCRIPT}(${MAX_CONTENT_LENGTH})`);
    return { content: [{ type: 'text', text: `# ${result.title}\n\n${result.markdown}` }] };
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

// ─── Web Scraper MCP tools ───

mcpServer.tool('scrape', 'Scrape a URL and convert to clean Markdown. Returns title, markdown content, word count, and links found.', {
  url: { type: 'string', description: 'URL to scrape' },
}, async ({ url }) => {
  if (!validateUrl(url)) throw new Error('Invalid or blocked URL');
  if (!await validateUrlAsync(url)) throw new Error('URL resolves to blocked address');
  return withBrowser(async (browser) => {
    const result = await scrapeUrl(browser, url, setupSsrfProtection);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });
});

mcpServer.tool('crawl', 'Crawl a website starting from a URL. Follows internal links up to specified depth. Returns markdown for each page.', {
  url: { type: 'string', description: 'Starting URL to crawl' },
  depth: { type: 'number', description: 'Max crawl depth (1-3)', default: 1 },
  maxPages: { type: 'number', description: 'Max pages to crawl (1-20)', default: 10 },
}, async ({ url, depth = 1, maxPages = 10 }) => {
  if (!validateUrl(url)) throw new Error('Invalid or blocked URL');
  if (!await validateUrlAsync(url)) throw new Error('URL resolves to blocked address');
  return withBrowser(async (browser) => {
    const result = await crawlSite(browser, url, depth, maxPages, setupSsrfProtection, validateUrl, validateUrlAsync);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });
});

mcpServer.tool('extract', 'Extract structured data from a URL: JSON-LD, Open Graph, meta tags, headings, links, images, tables.', {
  url: { type: 'string', description: 'URL to extract data from' },
}, async ({ url }) => {
  if (!validateUrl(url)) throw new Error('Invalid or blocked URL');
  if (!await validateUrlAsync(url)) throw new Error('URL resolves to blocked address');
  return withBrowser(async (browser) => {
    const result = await extractData(browser, url, setupSsrfProtection);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });
});

// ─── SEO Toolkit MCP tools ───

mcpServer.tool('serp', 'Scrape Google search results for a keyword. Returns organic results, People Also Ask, featured snippets, and related searches.', {
  keyword: { type: 'string', description: 'Search keyword' },
}, async ({ keyword }) => {
  if (!keyword || keyword.length > 200) throw new Error('Invalid keyword');
  return withBrowser(async (browser) => {
    const result = await serpScrape(browser, keyword, setupSsrfProtection);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });
});

mcpServer.tool('onpage_seo', 'Full on-page SEO analysis of a URL. Scores title, meta description, headings, images, links, schema markup, Open Graph, and more.', {
  url: { type: 'string', description: 'URL to analyze' },
}, async ({ url }) => {
  if (!validateUrl(url)) throw new Error('Invalid or blocked URL');
  if (!await validateUrlAsync(url)) throw new Error('URL resolves to blocked address');
  return withBrowser(async (browser) => {
    const result = await onpageSeo(browser, url, setupSsrfProtection);
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  });
});

mcpServer.tool('keywords_suggest', 'Get keyword suggestions using Google Autocomplete. Returns up to 100 related keyword ideas.', {
  keyword: { type: 'string', description: 'Seed keyword' },
}, async ({ keyword }) => {
  if (!keyword || keyword.length > 200) throw new Error('Invalid keyword');
  const result = await keywordsSuggest(keyword);
  return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
});

// ─── Agent Memory MCP tools ───

// Resolve MCP memory namespace with per-session isolation
function mcpNamespace(namespace, extra) {
  const sid = extra?.sessionId;
  const auth = sid ? sessionAuth[sid] : null;
  if (auth?.tier === 'apikey') {
    // API key users get isolated by key hash (same as REST)
    const hash = crypto.createHash('sha256').update(auth.apiKey).digest('hex').slice(0, 16);
    return `key:${hash}:${namespace}`;
  }
  if (auth?.tier === 'x402') {
    return `x402:${namespace}`;
  }
  // Free tier — scope by IP
  const ip = auth?.ip || 'unknown';
  return `free:${ip}:${namespace}`;
}

mcpServer.tool('memory_store', 'Store a memory in persistent storage. Memories are scoped by namespace. Upserts on key conflict.', {
  namespace: { type: 'string', description: 'Memory namespace (e.g., "my-agent", "project-x")' },
  key: { type: 'string', description: 'Memory key (max 256 chars)' },
  value: { type: 'string', description: 'Memory value (max 100KB)' },
  tags: { type: 'string', description: 'Comma-separated tags (optional)', default: '' },
}, async ({ namespace, key, value, tags = '' }, extra) => {
  const tagArr = tags ? tags.split(',').map(t => t.trim()).filter(Boolean) : [];
  const result = memoryStore(mcpNamespace(namespace, extra), key, value, tagArr);
  return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
});

mcpServer.tool('memory_get', 'Retrieve a memory by namespace and key.', {
  namespace: { type: 'string', description: 'Memory namespace' },
  key: { type: 'string', description: 'Memory key' },
}, async ({ namespace, key }, extra) => {
  const result = memoryGet(mcpNamespace(namespace, extra), key);
  if (!result) return { content: [{ type: 'text', text: JSON.stringify({ error: 'Memory not found' }) }] };
  return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
});

mcpServer.tool('memory_search', 'Search memories by text query within a namespace. Uses full-text search.', {
  namespace: { type: 'string', description: 'Memory namespace' },
  query: { type: 'string', description: 'Search query' },
  limit: { type: 'number', description: 'Max results (1-50)', default: 20 },
}, async ({ namespace, query, limit = 20 }, extra) => {
  const result = memorySearch(mcpNamespace(namespace, extra), query, limit);
  return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
});

mcpServer.tool('memory_list', 'List all memories in a namespace with pagination.', {
  namespace: { type: 'string', description: 'Memory namespace' },
  offset: { type: 'number', description: 'Pagination offset', default: 0 },
  limit: { type: 'number', description: 'Max items (1-100)', default: 20 },
}, async ({ namespace, offset = 0, limit = 20 }, extra) => {
  const result = memoryList(mcpNamespace(namespace, extra), offset, limit);
  return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
});

mcpServer.tool('memory_delete', 'Delete a memory by namespace and key.', {
  namespace: { type: 'string', description: 'Memory namespace' },
  key: { type: 'string', description: 'Memory key' },
}, async ({ namespace, key }, extra) => {
  const result = memoryDelete(mcpNamespace(namespace, extra), key);
  return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
});

// ─── Security MCP tools ───

mcpServer.tool('url_scan', 'Scan a URL for phishing, typosquatting, homoglyphs, and malware. Uses VirusTotal (if configured) and heuristic analysis. Returns severity (clean/suspicious/malicious) with detailed risk indicators.', {
  url: { type: 'string', description: 'URL to scan' },
}, async ({ url }) => {
  const result = await urlScan(url);
  return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
});

mcpServer.tool('wallet_check', 'Check a wallet address for scam reports, OFAC sanctions, contract verification status, and suspicious transaction patterns. Supports Ethereum, Base, Arbitrum, Optimism, Polygon.', {
  address: { type: 'string', description: 'Wallet or contract address (0x...)' },
  chain: { type: 'string', description: 'Chain: ethereum, base, arbitrum, optimism, polygon', default: 'ethereum' },
}, async ({ address, chain = 'ethereum' }) => {
  const result = await walletCheck(address, chain);
  return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
});

mcpServer.tool('contract_scan', 'Scan a smart contract for honeypot detection, rug pull indicators (mint functions, blacklists, fee manipulation, proxy patterns), and source verification status.', {
  address: { type: 'string', description: 'Contract address (0x...)' },
  chainId: { type: 'number', description: 'Chain ID: 1 (ETH), 8453 (Base), 42161 (Arb), 10 (OP), 137 (Polygon)', default: 1 },
}, async ({ address, chainId = 1 }) => {
  const result = await contractScan(address, chainId);
  return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
});

mcpServer.tool('email_headers', 'Validate email authentication for a domain. Checks SPF, DKIM (common selectors), DMARC policy, and MX records. Detects spoofing vulnerabilities.', {
  domain: { type: 'string', description: 'Domain to check (e.g., example.com)' },
}, async ({ domain }) => {
  const result = await emailHeaders(domain);
  return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
});

mcpServer.tool('threat_intel', 'Look up an IOC (IP, domain, URL, or file hash) across threat intelligence sources. Uses AbuseIPDB, VirusTotal, and OTX AlienVault with weighted confidence scoring.', {
  ioc: { type: 'string', description: 'Indicator of compromise: IP address, domain, URL, MD5, SHA1, or SHA256 hash' },
  type: { type: 'string', description: 'IOC type: auto, ip, domain, url, hash_md5, hash_sha1, hash_sha256', default: 'auto' },
}, async ({ ioc, type = 'auto' }) => {
  const result = await threatIntel(ioc, type);
  return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
});

mcpServer.tool('header_audit', 'Audit security headers of a URL. Checks HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, and cookie security. Returns a score (0-100).', {
  url: { type: 'string', description: 'URL to audit' },
}, async ({ url }) => {
  const result = await headerAudit(url);
  return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
});

mcpServer.tool('vuln_headers', 'Detect information leakage in HTTP response headers. Checks for exposed server versions, debug headers, X-Powered-By, CORS misconfigurations, and error responses.', {
  url: { type: 'string', description: 'URL to check' },
}, async ({ url }) => {
  const result = await vulnHeaders(url);
  return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
});

return mcpServer;
} // end createMcpServer

// ─── SSE Transport for MCP ───
const transports = {};
// Map sessionId -> auth context for per-session scoping
const sessionAuth = {};

app.get('/mcp/sse', async (req, res) => {
  if (Object.keys(transports).length >= MAX_SSE_SESSIONS) {
    return res.status(429).json({ error: 'Too many active sessions' });
  }

  // Authenticate the MCP connection — don't count against free limit (only tool calls count)
  const auth = await mcpAuth(req, { countUsage: false });
  if (!auth.tier) {
    return res.status(auth.error?.includes('API key') ? 401 : 429).json({ error: auth.error });
  }

  const transport = new SSEServerTransport('/mcp/messages', res);
  transports[transport.sessionId] = transport;
  sessionAuth[transport.sessionId] = auth;

  const server = createMcpServer();

  const cleanup = () => {
    delete transports[transport.sessionId];
    delete sessionAuth[transport.sessionId];
    server.close().catch(() => {});
  };
  res.on('close', cleanup);
  res.on('error', cleanup);

  try {
    await server.connect(transport);
  } catch (err) {
    console.error('[mcp]', err);
    cleanup();
    if (!res.headersSent) res.status(500).end();
  }
});

app.post('/mcp/messages', async (req, res) => {
  const sessionId = Array.isArray(req.query.sessionId) ? req.query.sessionId[0] : req.query.sessionId;
  const transport = transports[sessionId];
  if (!transport) return res.status(400).json({ error: 'Unknown session' });

  // For free tier, count only tool calls (initialize/ping/notifications should not consume quota).
  const auth = sessionAuth[sessionId];
  const message = req.body;
  const messages = Array.isArray(message) ? message : [message];
  const isToolCall = messages.some(m => m && typeof m === 'object' && m.method === 'tools/call');
  if (auth?.tier === 'free' && isToolCall) {
    const recheck = await mcpAuth(req, { countUsage: true });
    if (!recheck.tier) {
      return res.status(429).json({ error: recheck.error });
    }
  }

  try {
    // express.json() has already consumed req stream globally, so pass parsed body
    // to the SDK transport (otherwise it tries to re-read the drained stream).
    await transport.handlePostMessage(req, res, req.body);
  } catch (err) {
    console.error('[mcp/messages]', err);
    if (!res.headersSent) res.status(500).json({ error: 'Message handling failed' });
  }
});

// ─── Start ───
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`MCP Services running on port ${PORT}`);
  console.log(`  HTTP API: http://localhost:${PORT}/api/`);
  console.log(`  MCP SSE:  http://localhost:${PORT}/mcp/sse`);
  console.log(`  Health:   http://localhost:${PORT}/health`);
});

// ─── Graceful shutdown ───
async function shutdown(signal) {
  console.log(`\n[shutdown] ${signal} received, shutting down gracefully...`);

  // Stop accepting new connections
  server.close(() => console.log('[shutdown] HTTP server closed'));

  // Close all SSE connections
  for (const [id, transport] of Object.entries(transports)) {
    try { transport.close?.(); } catch {}
    delete transports[id];
    delete sessionAuth[id];
  }
  console.log('[shutdown] SSE sessions closed');

  // Close SQLite database (imported from memory.js)
  try {
    const { closeDb } = await import('./memory.js');
    closeDb();
    console.log('[shutdown] SQLite database closed');
  } catch {}

  process.exit(0);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
