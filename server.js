import express from 'express';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import puppeteer from 'puppeteer-core';
import whois from 'whois-json';
import { createPublicClient, http, formatEther, formatUnits } from 'viem';
import { mainnet, base, arbitrum, optimism, polygon, celo } from 'viem/chains';
import { execSync } from 'child_process';
import { resolve } from 'dns/promises';
import { readFileSync } from 'fs';

const PORT = process.env.PORT || 3100;

// ─── Chain configs ───
const CHAINS = {
  ethereum: { chain: mainnet, rpc: 'https://ethereum-rpc.publicnode.com' },
  base: { chain: base, rpc: 'https://base-rpc.publicnode.com' },
  arbitrum: { chain: arbitrum, rpc: 'https://arbitrum-one-rpc.publicnode.com' },
  optimism: { chain: optimism, rpc: 'https://optimism-rpc.publicnode.com' },
  polygon: { chain: polygon, rpc: 'https://polygon-bor-rpc.publicnode.com' },
  celo: { chain: celo, rpc: 'https://forno.celo.org' },
};

// ─── Express API (for x402 / direct HTTP) ───
const app = express();
app.use(express.json());

// URL validation — block SSRF
function validateUrl(urlStr) {
  try {
    const u = new URL(urlStr);
    if (!['http:', 'https:'].includes(u.protocol)) return false;
    const host = u.hostname.toLowerCase();
    if (host === 'localhost' || host === '127.0.0.1' || host === '::1') return false;
    if (host.startsWith('10.') || host.startsWith('172.16.') || host.startsWith('192.168.')) return false;
    if (host === '169.254.169.254') return false;
    if (host.endsWith('.internal') || host.endsWith('.local')) return false;
    return true;
  } catch { return false; }
}

// Health
app.get('/health', (_, res) => res.json({ status: 'ok', services: ['screenshot', 'whois', 'blockchain'] }));

// Screenshot endpoint
app.get('/api/screenshot', async (req, res) => {
  const { url, format = 'png', width = 1280, height = 800, fullPage = false } = req.query;
  if (!url) return res.status(400).json({ error: 'url parameter required' });
  if (!validateUrl(url)) return res.status(400).json({ error: 'Invalid or blocked URL' });
  
  let browser;
  try {
    browser = await puppeteer.launch({
      executablePath: '/usr/bin/chromium-browser',
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
    });
    const page = await browser.newPage();
    await page.setViewport({ width: parseInt(width), height: parseInt(height) });
    await page.goto(url, { waitUntil: 'networkidle2', timeout: 30000 });
    
    const screenshot = await page.screenshot({ 
      type: format === 'jpeg' ? 'jpeg' : 'png',
      fullPage: fullPage === 'true',
      encoding: 'base64'
    });
    
    res.json({ 
      url, 
      format,
      width: parseInt(width),
      height: parseInt(height),
      fullPage: fullPage === 'true',
      image: `data:image/${format};base64,${screenshot}`,
      size: screenshot.length 
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  } finally {
    if (browser) await browser.close();
  }
});

// PDF endpoint
app.get('/api/pdf', async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: 'url parameter required' });
  if (!validateUrl(url)) return res.status(400).json({ error: 'Invalid or blocked URL' });
  
  let browser;
  try {
    browser = await puppeteer.launch({
      executablePath: '/usr/bin/chromium-browser',
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
    });
    const page = await browser.newPage();
    await page.goto(url, { waitUntil: 'networkidle2', timeout: 30000 });
    const pdf = await page.pdf({ format: 'A4', printBackground: true });
    
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="page.pdf"`);
    res.send(pdf);
  } catch (err) {
    res.status(500).json({ error: err.message });
  } finally {
    if (browser) await browser.close();
  }
});

// WHOIS endpoint
app.get('/api/whois', async (req, res) => {
  const { domain } = req.query;
  if (!domain) return res.status(400).json({ error: 'domain parameter required' });
  
  try {
    const result = await whois(domain);
    res.json({ domain, whois: result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DNS endpoint
app.get('/api/dns', async (req, res) => {
  const { domain, type = 'A' } = req.query;
  if (!domain) return res.status(400).json({ error: 'domain parameter required' });
  
  try {
    const records = {};
    const types = type === 'ALL' ? ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA'] : [type.toUpperCase()];
    
    for (const t of types) {
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
    res.status(500).json({ error: err.message });
  }
});

// Blockchain - Balance
app.get('/api/chain/balance', async (req, res) => {
  const { address, chain = 'ethereum' } = req.query;
  if (!address) return res.status(400).json({ error: 'address parameter required' });
  
  const chainConfig = CHAINS[chain.toLowerCase()];
  if (!chainConfig) return res.status(400).json({ error: `Unknown chain: ${chain}. Available: ${Object.keys(CHAINS).join(', ')}` });
  
  try {
    const client = createPublicClient({ chain: chainConfig.chain, transport: http(chainConfig.rpc) });
    const balance = await client.getBalance({ address });
    const symbol = chainConfig.chain.nativeCurrency.symbol;
    
    res.json({ 
      address, 
      chain, 
      balance: formatEther(balance),
      symbol,
      raw: balance.toString()
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Blockchain - Transaction
app.get('/api/chain/tx', async (req, res) => {
  const { hash, chain = 'ethereum' } = req.query;
  if (!hash) return res.status(400).json({ error: 'hash parameter required' });
  
  const chainConfig = CHAINS[chain.toLowerCase()];
  if (!chainConfig) return res.status(400).json({ error: `Unknown chain: ${chain}` });
  
  try {
    const client = createPublicClient({ chain: chainConfig.chain, transport: http(chainConfig.rpc) });
    const tx = await client.getTransaction({ hash });
    const receipt = await client.getTransactionReceipt({ hash });
    
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
    res.status(500).json({ error: err.message });
  }
});

// Blockchain - ERC20 balance
app.get('/api/chain/erc20', async (req, res) => {
  const { address, token, chain = 'ethereum' } = req.query;
  if (!address || !token) return res.status(400).json({ error: 'address and token parameters required' });
  
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
    res.status(500).json({ error: err.message });
  }
});

// HTML to Markdown
app.get('/api/html2md', async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: 'url parameter required' });
  if (!validateUrl(url)) return res.status(400).json({ error: 'Invalid or blocked URL' });
  
  let browser;
  try {
    browser = await puppeteer.launch({
      executablePath: '/usr/bin/chromium-browser',
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
    });
    const page = await browser.newPage();
    await page.goto(url, { waitUntil: 'networkidle2', timeout: 30000 });
    
    // Extract readable content and convert to markdown-like text
    const content = await page.evaluate(() => {
      // Remove scripts, styles, nav, footer, ads
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
      
      return nodeToMd(article).replace(/\n{3,}/g, '\n\n').trim();
    });
    
    const title = await page.title();
    res.json({ url, title, markdown: content, length: content.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  } finally {
    if (browser) await browser.close();
  }
});

// OCR — extract text from image URL
app.get('/api/ocr', async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).json({ error: 'url parameter required' });
  if (!validateUrl(url)) return res.status(400).json({ error: 'Invalid or blocked URL' });
  
  let browser;
  try {
    // Download image and use Tesseract via Chromium's canvas
    browser = await puppeteer.launch({
      executablePath: '/usr/bin/chromium-browser',
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
    });
    const page = await browser.newPage();
    
    // Load Tesseract.js via CDN and process the image
    await page.setContent(`
      <script src="https://cdn.jsdelivr.net/npm/tesseract.js@5/dist/tesseract.min.js"></script>
      <img id="img" crossorigin="anonymous" />
    `);
    
    const text = await page.evaluate(async (imageUrl) => {
      const { createWorker } = window.Tesseract;
      const worker = await createWorker('eng');
      const { data: { text } } = await worker.recognize(imageUrl);
      await worker.terminate();
      return text;
    }, url);
    
    res.json({ url, text: text.trim(), length: text.trim().length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  } finally {
    if (browser) await browser.close();
  }
});

// SSL Certificate checker
app.get('/api/ssl', async (req, res) => {
  const { domain } = req.query;
  if (!domain) return res.status(400).json({ error: 'domain parameter required' });
  
  try {
    const { execSync } = await import('child_process');
    const raw = execSync(
      `echo | openssl s_client -servername ${domain} -connect ${domain}:443 2>/dev/null | openssl x509 -noout -subject -issuer -dates -serial -fingerprint 2>/dev/null`,
      { timeout: 10000, encoding: 'utf-8' }
    );
    
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
    
    // Check expiry
    if (cert.validUntil) {
      const expiry = new Date(cert.validUntil);
      const daysLeft = Math.floor((expiry - new Date()) / 86400000);
      cert.daysUntilExpiry = daysLeft;
      cert.expired = daysLeft < 0;
      cert.expiringSoon = daysLeft >= 0 && daysLeft < 30;
    }
    
    res.json({ domain, certificate: cert });
  } catch (err) {
    res.status(500).json({ error: err.message });
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
  let browser;
  try {
    browser = await puppeteer.launch({
      executablePath: '/usr/bin/chromium-browser',
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
    });
    const page = await browser.newPage();
    await page.setViewport({ width, height });
    await page.goto(url, { waitUntil: 'networkidle2', timeout: 30000 });
    const screenshot = await page.screenshot({ type: format === 'jpeg' ? 'jpeg' : 'png', fullPage, encoding: 'base64' });
    return { content: [{ type: 'image', data: screenshot, mimeType: `image/${format}` }] };
  } finally {
    if (browser) await browser.close();
  }
});

mcpServer.tool('pdf', 'Generate a PDF of any URL.', {
  url: { type: 'string', description: 'URL to convert to PDF' },
}, async ({ url }) => {
  let browser;
  try {
    browser = await puppeteer.launch({
      executablePath: '/usr/bin/chromium-browser',
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
    });
    const page = await browser.newPage();
    await page.goto(url, { waitUntil: 'networkidle2', timeout: 30000 });
    const pdf = await page.pdf({ format: 'A4', printBackground: true });
    return { content: [{ type: 'resource', uri: `data:application/pdf;base64,${pdf.toString('base64')}`, mimeType: 'application/pdf' }] };
  } finally {
    if (browser) await browser.close();
  }
});

mcpServer.tool('whois', 'Look up WHOIS information for a domain.', {
  domain: { type: 'string', description: 'Domain name to look up' },
}, async ({ domain }) => {
  const result = await whois(domain);
  return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
});

mcpServer.tool('dns', 'Look up DNS records for a domain.', {
  domain: { type: 'string', description: 'Domain name' },
  type: { type: 'string', description: 'Record type: A, AAAA, MX, NS, TXT, CNAME, SOA, or ALL', default: 'ALL' },
}, async ({ domain, type = 'ALL' }) => {
  const records = {};
  const types = type === 'ALL' ? ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA'] : [type.toUpperCase()];
  for (const t of types) {
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
  const chainConfig = CHAINS[chain.toLowerCase()];
  if (!chainConfig) throw new Error(`Unknown chain: ${chain}`);
  const client = createPublicClient({ chain: chainConfig.chain, transport: http(chainConfig.rpc) });
  const tx = await client.getTransaction({ hash });
  const receipt = await client.getTransactionReceipt({ hash });
  return { content: [{ type: 'text', text: JSON.stringify({
    hash, chain, from: tx.from, to: tx.to, value: formatEther(tx.value),
    gasUsed: receipt.gasUsed.toString(), status: receipt.status, blockNumber: Number(tx.blockNumber)
  }, null, 2) }] };
});

mcpServer.tool('html2md', 'Fetch a URL and convert the page content to clean Markdown. Removes nav, ads, scripts.', {
  url: { type: 'string', description: 'URL to fetch and convert' },
}, async ({ url }) => {
  if (!validateUrl(url)) throw new Error('Invalid or blocked URL');
  let browser;
  try {
    browser = await puppeteer.launch({
      executablePath: '/usr/bin/chromium-browser', headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
    });
    const page = await browser.newPage();
    await page.goto(url, { waitUntil: 'networkidle2', timeout: 30000 });
    const content = await page.evaluate(() => {
      document.querySelectorAll('script, style, nav, footer, aside, .ad, .ads, .sidebar').forEach(el => el.remove());
      const article = document.querySelector('article, main, [role="main"]') || document.body;
      return article.innerText;
    });
    const title = await page.title();
    return { content: [{ type: 'text', text: `# ${title}\n\n${content.replace(/\n{3,}/g, '\n\n').trim()}` }] };
  } finally { if (browser) await browser.close(); }
});

mcpServer.tool('ocr', 'Extract text from an image URL using OCR.', {
  url: { type: 'string', description: 'Image URL to extract text from' },
}, async ({ url }) => {
  if (!validateUrl(url)) throw new Error('Invalid or blocked URL');
  let browser;
  try {
    browser = await puppeteer.launch({
      executablePath: '/usr/bin/chromium-browser', headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
    });
    const page = await browser.newPage();
    await page.setContent(`<script src="https://cdn.jsdelivr.net/npm/tesseract.js@5/dist/tesseract.min.js"></script>`);
    const text = await page.evaluate(async (imageUrl) => {
      const { createWorker } = window.Tesseract;
      const worker = await createWorker('eng');
      const { data: { text } } = await worker.recognize(imageUrl);
      await worker.terminate();
      return text;
    }, url);
    return { content: [{ type: 'text', text: text.trim() }] };
  } finally { if (browser) await browser.close(); }
});

mcpServer.tool('ssl', 'Check SSL certificate details for a domain. Returns issuer, validity dates, expiry status.', {
  domain: { type: 'string', description: 'Domain to check SSL certificate for' },
}, async ({ domain }) => {
  const { execSync } = await import('child_process');
  const raw = execSync(
    `echo | openssl s_client -servername ${domain} -connect ${domain}:443 2>/dev/null | openssl x509 -noout -subject -issuer -dates -serial 2>/dev/null`,
    { timeout: 10000, encoding: 'utf-8' }
  );
  const lines = raw.split('\n').filter(Boolean);
  const cert = {};
  for (const line of lines) {
    const [key, ...val] = line.split('=');
    const k = key.trim().toLowerCase();
    if (k === 'subject') cert.subject = val.join('=').trim();
    else if (k === 'issuer') cert.issuer = val.join('=').trim();
    else if (k.includes('notbefore')) cert.validFrom = val.join('=').trim();
    else if (k.includes('notafter')) cert.validUntil = val.join('=').trim();
  }
  if (cert.validUntil) {
    const daysLeft = Math.floor((new Date(cert.validUntil) - new Date()) / 86400000);
    cert.daysUntilExpiry = daysLeft;
    cert.expired = daysLeft < 0;
  }
  return { content: [{ type: 'text', text: JSON.stringify({ domain, certificate: cert }, null, 2) }] };
});

// ─── SSE Transport for MCP ───
const transports = {};

app.get('/mcp/sse', async (req, res) => {
  const transport = new SSEServerTransport('/mcp/messages', res);
  transports[transport.sessionId] = transport;
  
  res.on('close', () => {
    delete transports[transport.sessionId];
  });
  
  await mcpServer.connect(transport);
});

app.post('/mcp/messages', async (req, res) => {
  const sessionId = req.query.sessionId;
  const transport = transports[sessionId];
  if (!transport) return res.status(400).json({ error: 'Unknown session' });
  await transport.handlePostMessage(req, res);
});

// ─── Start ───
app.listen(PORT, '0.0.0.0', () => {
  console.log(`MCP Services running on port ${PORT}`);
  console.log(`  HTTP API: http://localhost:${PORT}/api/`);
  console.log(`  MCP SSE:  http://localhost:${PORT}/mcp/sse`);
  console.log(`  Health:   http://localhost:${PORT}/health`);
});
