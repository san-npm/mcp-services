// ─── Security Toolkit Service ───
// Tools: url_scan, wallet_check, contract_scan, email_headers, threat_intel, header_audit, vuln_headers

import https from 'https';
import http from 'http';
import { resolve, resolve4 } from 'dns/promises';

// ─── Shared helpers ───

const VT_API_KEY = process.env.VT_API_KEY || '';
const ABUSEIPDB_API_KEY = process.env.ABUSEIPDB_API_KEY || '';
const ETHERSCAN_API_KEY = process.env.ETHERSCAN_API_KEY || '';

// SSRF protection — block private/internal IPs
function isPrivateIp(ip) {
  const parts = ip.split('.');
  if (parts.length === 4 && parts.every(p => !isNaN(p))) {
    const [a, b] = parts.map(Number);
    if (a === 10 || a === 127 || a === 0) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 169 && b === 254) return true;
  }
  const clean = ip.replace(/^\[|\]$/g, '').toLowerCase();
  if (clean.startsWith('fc') || clean.startsWith('fd') || clean.startsWith('fe80')) return true;
  if (clean === '::' || clean === '::1') return true;
  return false;
}

function validateUserUrl(urlStr) {
  try {
    const u = new URL(urlStr);
    if (!['http:', 'https:'].includes(u.protocol)) return false;
    const host = u.hostname.toLowerCase();
    if (host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '[::1]') return false;
    if (host.endsWith('.internal') || host.endsWith('.local')) return false;
    if (host === 'metadata.google.internal') return false;
    if (isPrivateIp(host)) return false;
    return true;
  } catch { return false; }
}

async function validateUserUrlAsync(urlStr) {
  if (!validateUserUrl(urlStr)) return false;
  try {
    const host = new URL(urlStr).hostname.toLowerCase();
    if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) return true;
    const addrs = await resolve4(host);
    return addrs.every(ip => !isPrivateIp(ip));
  } catch { return false; }
}

const MAX_RESPONSE_BYTES = 5 * 1024 * 1024; // 5 MB max response body

function fetchJson(url, options = {}) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    const req = mod.get(url, { headers: options.headers || {}, timeout: 10000 }, (res) => {
      let data = '';
      let bytes = 0;
      res.on('data', (chunk) => {
        bytes += chunk.length;
        if (bytes > MAX_RESPONSE_BYTES) { res.destroy(); reject(new Error('Response too large')); return; }
        data += chunk;
      });
      res.on('end', () => {
        try { resolve({ status: res.statusCode, data: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, data }); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Request timeout')); });
  });
}

function fetchHeaders(url) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    const req = mod.get(url, { timeout: 10000 }, (res) => {
      res.destroy();
      resolve({ status: res.statusCode, headers: res.headers });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Request timeout')); });
  });
}

// ─── Known brand list for typosquatting ───

const KNOWN_BRANDS = [
  'google.com', 'facebook.com', 'paypal.com', 'amazon.com', 'microsoft.com',
  'apple.com', 'netflix.com', 'coinbase.com', 'binance.com', 'metamask.io',
  'uniswap.org', 'opensea.io', 'github.com', 'linkedin.com', 'twitter.com',
  'instagram.com', 'chase.com', 'wellsfargo.com', 'bankofamerica.com',
  'kraken.com', 'blockchain.com', 'ledger.com', 'trezor.io',
];

const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'buzz', 'tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'cc',
  'click', 'link', 'info', 'icu', 'cam', 'rest', 'surf', 'monster',
]);

const FREE_HOSTING = new Set([
  '000webhostapp.com', 'netlify.app', 'vercel.app', 'herokuapp.com',
  'pages.dev', 'web.app', 'firebaseapp.com', 'glitch.me', 'replit.dev',
]);

// OFAC/SDN sanctioned addresses (subset — high-profile Ethereum addresses)
const OFAC_SANCTIONED = new Set([
  '0x8589427373d6d84e98730d7795d8f6f8731fda16', // Tornado Cash: Router
  '0x722122df12d4e14e13ac3b6895a86e84145b6967', // Tornado Cash: Proxy
  '0xdd4c48c0b24039969fc16d1cdf626eab821d3384', // Tornado Cash: 100 ETH
  '0xd90e2f925da726b50c4ed8d0fb90ad053324f31b', // Tornado Cash: 10 ETH
  '0xd96f2b1cf787cf46a2d398fb12267c916e4a22e2', // Tornado Cash: 1 ETH
  '0x4736dcf1b7a3d580672cce6e7c65cd5cc9cfbba9', // Tornado Cash: 0.1 ETH
  '0xd4b88df4d29f5cedd6857912842cff3b20c8cfa3', // Tornado Cash: Old
  '0x910cbd523d972eb0a6f4cae4618ad62622b39dbf', // Tornado Cash: Governance
  '0xa7e5d5a720f06526557c513402f2e6b5fa20b008', // Tornado Cash: Mining
]);

// ─── Similarity check (Levenshtein-based) ───

function similarity(a, b) {
  const lenA = a.length, lenB = b.length;
  const matrix = Array.from({ length: lenA + 1 }, (_, i) =>
    Array.from({ length: lenB + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );
  for (let i = 1; i <= lenA; i++) {
    for (let j = 1; j <= lenB; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(matrix[i - 1][j] + 1, matrix[i][j - 1] + 1, matrix[i - 1][j - 1] + cost);
    }
  }
  return 1 - matrix[lenA][lenB] / Math.max(lenA, lenB);
}

// Homoglyph detection
const HOMOGLYPHS = { '0': 'o', '1': 'l', 'l': '1', 'o': '0', 'rn': 'm', 'vv': 'w', 'cl': 'd' };

function detectHomoglyphs(domain) {
  const alerts = [];
  const base = domain.split('.')[0].toLowerCase();
  for (const [fake, real] of Object.entries(HOMOGLYPHS)) {
    if (base.includes(fake)) {
      const normalized = base.replace(new RegExp(fake, 'g'), real);
      for (const brand of KNOWN_BRANDS) {
        const brandBase = brand.split('.')[0].toLowerCase();
        if (normalized === brandBase || similarity(normalized, brandBase) >= 0.9) {
          alerts.push({ type: 'homoglyph', detail: `'${domain}' uses '${fake}' resembling '${real}' in '${brand}'` });
        }
      }
    }
  }
  return alerts;
}

// ─── 1. URL Scan ───

export async function urlScan(url) {
  const result = {
    url,
    severity: 'clean',
    risks: [],
    virustotal: null,
    typosquatting: [],
    heuristics: [],
  };

  let parsedUrl;
  try { parsedUrl = new URL(url); }
  catch { return { ...result, severity: 'malicious', risks: ['Invalid URL format'] }; }

  // Only scan HTTP/HTTPS URLs
  if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
    return { ...result, severity: 'suspicious', risks: [`Non-HTTP protocol: ${parsedUrl.protocol}`] };
  }

  const hostname = parsedUrl.hostname.toLowerCase();
  const tld = hostname.split('.').pop();
  const baseDomain = hostname.split('.').slice(-2).join('.');
  const domainBase = hostname.split('.')[0];

  // Heuristic checks
  if (parsedUrl.protocol === 'http:' && parsedUrl.pathname.toLowerCase().includes('login')) {
    result.heuristics.push({ indicator: 'HTTP login page', risk: 'critical' });
  }
  if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
    result.heuristics.push({ indicator: 'IP address as hostname', risk: 'high' });
  }
  if (hostname.split('.').length > 4) {
    result.heuristics.push({ indicator: `Excessive subdomains (${hostname.split('.').length} levels)`, risk: 'medium' });
  }
  if (SUSPICIOUS_TLDS.has(tld)) {
    result.heuristics.push({ indicator: `Suspicious TLD: .${tld}`, risk: 'medium' });
  }
  for (const freeHost of FREE_HOSTING) {
    if (hostname.endsWith(freeHost)) {
      result.heuristics.push({ indicator: `Free hosting: ${freeHost}`, risk: 'medium' });
      break;
    }
  }

  // Homoglyph detection
  const homoglyphs = detectHomoglyphs(hostname);
  if (homoglyphs.length > 0) {
    result.heuristics.push(...homoglyphs.map(h => ({ indicator: h.detail, risk: 'high' })));
  }

  // Typosquatting check
  for (const brand of KNOWN_BRANDS) {
    const brandBase = brand.split('.')[0].toLowerCase();
    const sim = similarity(domainBase, brandBase);
    if (sim >= 0.8 && baseDomain !== brand) {
      result.typosquatting.push({ brand, similarity: Math.round(sim * 100) + '%' });
    }
  }

  // VirusTotal scan (if key available)
  if (VT_API_KEY) {
    try {
      const urlId = Buffer.from(url).toString('base64').replace(/=/g, '');
      const vt = await fetchJson(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
        headers: { 'x-apikey': VT_API_KEY },
      });
      if (vt.status === 200 && vt.data?.data?.attributes) {
        const stats = vt.data.data.attributes.last_analysis_stats;
        const reputation = vt.data.data.attributes.reputation;
        result.virustotal = { stats, reputation };
        if (stats.malicious > 3) {
          result.risks.push(`VirusTotal: ${stats.malicious} engines flagged as malicious`);
        } else if (stats.malicious > 0 || stats.suspicious > 0) {
          result.risks.push(`VirusTotal: ${stats.malicious} malicious, ${stats.suspicious} suspicious`);
        }
      }
    } catch { /* VT unavailable — continue with heuristics */ }
  }

  // Calculate severity
  const hasHighRisk = result.heuristics.some(h => h.risk === 'critical' || h.risk === 'high');
  const hasMediumRisk = result.heuristics.some(h => h.risk === 'medium');
  const hasTyposquat = result.typosquatting.length > 0;
  const vtMalicious = result.virustotal?.stats?.malicious > 3;
  const vtSuspicious = result.virustotal?.stats?.malicious > 0;

  if (vtMalicious || (hasHighRisk && hasTyposquat)) {
    result.severity = 'malicious';
  } else if (vtSuspicious || hasHighRisk || hasTyposquat) {
    result.severity = 'suspicious';
  } else if (hasMediumRisk) {
    result.severity = 'suspicious';
  }

  result.risks = [
    ...result.risks,
    ...result.heuristics.map(h => h.indicator),
    ...result.typosquatting.map(t => `Typosquatting: resembles ${t.brand} (${t.similarity})`),
  ];

  return result;
}

// ─── 2. Wallet Check ───

export async function walletCheck(address, chain = 'ethereum') {
  const result = {
    address,
    chain,
    severity: 'clean',
    risks: [],
    labels: [],
    contract: null,
  };

  // Validate address format (strict hex check prevents injection)
  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) {
    return { ...result, severity: 'malicious', risks: ['Invalid Ethereum address format'] };
  }

  // Validate chain name (prevent injection into API URLs)
  const validChains = ['ethereum', 'base', 'arbitrum', 'optimism', 'polygon'];
  if (!validChains.includes(chain.toLowerCase())) {
    return { ...result, risks: [`Unknown chain: ${chain}. Supported: ${validChains.join(', ')}`] };
  }

  // Address poisoning check — warn if address has suspicious prefix/suffix pattern
  // (This is informational — the agent should always verify full addresses)
  result.risks.push('Always verify the FULL address — address poisoning uses similar prefix/suffix');

  // Check if it's a contract
  const explorerApi = {
    ethereum: 'https://api.etherscan.io/api',
    base: 'https://api.basescan.org/api',
    arbitrum: 'https://api.arbiscan.io/api',
    optimism: 'https://api-optimistic.etherscan.io/api',
    polygon: 'https://api.polygonscan.com/api',
  }[chain.toLowerCase()];

  if (ETHERSCAN_API_KEY) {
    try {
      // Check contract source verification
      const srcResp = await fetchJson(
        `${explorerApi}?module=contract&action=getabi&address=${address}&apikey=${ETHERSCAN_API_KEY}`
      );
      const isContract = srcResp.data?.status === '1';
      const isVerified = isContract; // getabi returns 1 only for verified contracts
      result.contract = { isContract: isContract || srcResp.data?.result === 'Contract source code not verified', isVerified };

      if (srcResp.data?.result === 'Contract source code not verified') {
        result.contract.isContract = true;
        result.contract.isVerified = false;
        result.risks.push('Contract source code not verified on block explorer');
      }

      // Check recent transactions for pattern analysis
      const txResp = await fetchJson(
        `${explorerApi}?module=account&action=txlist&address=${address}&startblock=0&endblock=99999999&page=1&offset=5&sort=desc&apikey=${ETHERSCAN_API_KEY}`
      );
      if (txResp.data?.status === '1' && Array.isArray(txResp.data.result)) {
        const txs = txResp.data.result;
        const txCount = txs.length;
        // Check if address is very new with high value
        if (txCount <= 3) {
          const totalValue = txs.reduce((sum, tx) => sum + parseFloat(tx.value || '0') / 1e18, 0);
          if (totalValue > 10) {
            result.risks.push(`New address (${txCount} txs) with high value received (${totalValue.toFixed(2)} ETH)`);
          }
        }
      }
    } catch { /* Etherscan unavailable */ }
  }

  if (OFAC_SANCTIONED.has(address.toLowerCase())) {
    result.severity = 'malicious';
    result.risks.push('Address is on OFAC/SDN sanctions list');
    result.labels.push('OFAC_SANCTIONED');
  }

  // Calculate severity
  const riskCount = result.risks.filter(r => !r.startsWith('Always verify')).length;
  if (result.severity !== 'malicious') {
    if (riskCount >= 3) result.severity = 'suspicious';
    else if (riskCount >= 1 && result.contract?.isContract && !result.contract?.isVerified) result.severity = 'suspicious';
  }

  return result;
}

// ─── 3. Contract Scan ───

export async function contractScan(address, chainId = 1) {
  chainId = parseInt(chainId) || 1;
  const validChainIds = [1, 8453, 42161, 10, 137];

  const result = {
    address,
    chainId,
    severity: 'clean',
    risks: [],
    honeypot: null,
    contractInfo: null,
  };

  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) {
    return { ...result, severity: 'malicious', risks: ['Invalid contract address'] };
  }

  if (!validChainIds.includes(chainId)) {
    result.risks.push(`Unsupported chain ID: ${chainId}. Supported: ${validChainIds.join(', ')}. Falling back to Ethereum.`);
    chainId = 1;
  }

  // Honeypot.is check
  try {
    const hp = await fetchJson(`https://api.honeypot.is/v2/IsHoneypot?address=${address}&chainID=${chainId}`);
    if (hp.status === 200 && hp.data) {
      result.honeypot = {
        isHoneypot: hp.data.honeypotResult?.isHoneypot ?? null,
        buyTax: hp.data.simulationResult?.buyTax ?? null,
        sellTax: hp.data.simulationResult?.sellTax ?? null,
        transferTax: hp.data.simulationResult?.transferTax ?? null,
      };
      if (hp.data.honeypotResult?.isHoneypot) {
        result.severity = 'malicious';
        result.risks.push('HONEYPOT DETECTED — contract blocks selling');
      }
      if (hp.data.simulationResult?.sellTax > 10) {
        result.risks.push(`High sell tax: ${hp.data.simulationResult.sellTax}%`);
      }
      if (hp.data.simulationResult?.buyTax > 10) {
        result.risks.push(`High buy tax: ${hp.data.simulationResult.buyTax}%`);
      }
    }
  } catch { /* honeypot.is unavailable */ }

  // Etherscan contract checks
  if (ETHERSCAN_API_KEY) {
    const explorerApi = {
      1: 'https://api.etherscan.io/api',
      8453: 'https://api.basescan.org/api',
      42161: 'https://api.arbiscan.io/api',
      10: 'https://api-optimistic.etherscan.io/api',
      137: 'https://api.polygonscan.com/api',
    }[chainId] || 'https://api.etherscan.io/api';

    try {
      // Check source verification
      const srcResp = await fetchJson(
        `${explorerApi}?module=contract&action=getsourcecode&address=${address}&apikey=${ETHERSCAN_API_KEY}`
      );
      if (srcResp.data?.status === '1' && Array.isArray(srcResp.data.result)) {
        const info = srcResp.data.result[0];
        const hasSource = info.SourceCode && info.SourceCode !== '';
        const isProxy = info.Proxy === '1' || (info.Implementation && info.Implementation !== '');

        result.contractInfo = {
          name: info.ContractName || 'Unknown',
          verified: hasSource,
          proxy: isProxy,
          compiler: info.CompilerVersion || null,
        };

        if (!hasSource) {
          result.risks.push('Source code NOT verified — cannot audit');
        }
        if (isProxy) {
          result.risks.push('Proxy contract — owner can change logic');
        }

        // Analyze source code for rug pull patterns
        const source = (info.SourceCode || '').toLowerCase();
        if (source) {
          if (source.includes('_mint') && !source.includes('constructor')) {
            const mintOutsideConstructor = source.indexOf('_mint') > source.indexOf('}');
            if (mintOutsideConstructor || source.match(/function\s+\w*mint/i)) {
              result.risks.push('Mint function callable outside constructor — owner can inflate supply');
            }
          }
          if (source.includes('blacklist') || source.includes('isblacklisted') || source.includes('blocklist')) {
            result.risks.push('Blacklist/blocklist function found — owner can freeze addresses');
          }
          if (source.match(/settax|setfee|updatefee|updatetax/i)) {
            result.risks.push('Fee/tax manipulation function — owner can change trading fees');
          }
          if (source.includes('pause') && source.includes('whennotpaused')) {
            result.risks.push('Pausable contract — owner can halt transfers');
          }
        }
      }
    } catch { /* Etherscan unavailable */ }
  }

  // Calculate severity
  if (result.severity !== 'malicious') {
    const criticalRisks = result.risks.filter(r =>
      r.includes('HONEYPOT') || r.includes('NOT verified') || r.includes('inflate supply')
    ).length;
    const mediumRisks = result.risks.length - criticalRisks;

    if (criticalRisks >= 2) result.severity = 'malicious';
    else if (criticalRisks >= 1 || mediumRisks >= 3) result.severity = 'suspicious';
  }

  return result;
}

// ─── 4. Email Headers ───

export async function emailHeaders(domain) {
  const result = {
    domain,
    severity: 'clean',
    risks: [],
    spf: null,
    dkim: null,
    dmarc: null,
    mx: null,
  };

  if (!/^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(domain)) {
    return { ...result, severity: 'malicious', risks: ['Invalid domain format'] };
  }

  // SPF check
  try {
    const txtRecords = await resolve(domain, 'TXT');
    const spfRecords = txtRecords.flat().filter(r => r.startsWith('v=spf1'));
    if (spfRecords.length === 0) {
      result.spf = { exists: false, record: null };
      result.risks.push('No SPF record — domain does not specify authorized mail senders');
    } else if (spfRecords.length > 1) {
      result.spf = { exists: true, record: spfRecords, multiple: true };
      result.risks.push('Multiple SPF records — causes validation failures (RFC 7208)');
    } else {
      const spf = spfRecords[0];
      result.spf = { exists: true, record: spf };
      if (spf.includes('+all') || spf.includes('?all')) {
        result.risks.push(`Weak SPF policy: '${spf.includes('+all') ? '+all' : '?all'}' allows any server to send`);
      }
    }
  } catch { result.spf = { exists: false, error: 'DNS lookup failed' }; }

  // DMARC check
  try {
    const dmarcRecords = await resolve(`_dmarc.${domain}`, 'TXT');
    const dmarc = dmarcRecords.flat().find(r => r.startsWith('v=DMARC1'));
    if (!dmarc) {
      result.dmarc = { exists: false, record: null };
      result.risks.push('No DMARC record — no spoofing protection policy');
    } else {
      const policy = dmarc.match(/p=(\w+)/)?.[1] || 'none';
      result.dmarc = { exists: true, record: dmarc, policy };
      if (policy === 'none') {
        result.risks.push('DMARC policy is "none" — monitoring only, not enforcing');
      }
    }
  } catch { result.dmarc = { exists: false, error: 'DNS lookup failed' }; }

  // MX check
  try {
    const mxRecords = await resolve(domain, 'MX');
    result.mx = mxRecords.map(r => ({ priority: r.priority, exchange: r.exchange }));
    if (mxRecords.length === 0) {
      result.risks.push('No MX records — domain cannot receive email');
    }
  } catch {
    result.mx = [];
    result.risks.push('No MX records found');
  }

  // DKIM — check common selectors
  const dkimSelectors = ['default', 'google', 'selector1', 'selector2', 'k1', 's1', 'dkim'];
  result.dkim = { found: false, selectors: [] };
  for (const sel of dkimSelectors) {
    try {
      const dkimRecords = await resolve(`${sel}._domainkey.${domain}`, 'TXT');
      const record = dkimRecords.flat().join('');
      if (record.includes('v=DKIM1') || record.includes('p=')) {
        result.dkim.found = true;
        result.dkim.selectors.push({ selector: sel, record: record.slice(0, 200) });
      }
    } catch { /* selector not found — try next */ }
  }
  if (!result.dkim.found) {
    result.risks.push('No DKIM records found (checked common selectors) — emails may not be signed');
  }

  // Calculate severity
  const criticalCount = result.risks.filter(r => r.includes('+all')).length;
  const highCount = result.risks.filter(r => r.includes('No SPF') || r.includes('No DMARC')).length;

  if (criticalCount > 0) result.severity = 'malicious';
  else if (highCount >= 2) result.severity = 'suspicious';
  else if (result.risks.length > 0) result.severity = 'suspicious';
  else result.severity = 'clean';

  return result;
}

// ─── 5. Threat Intel ───

export async function threatIntel(ioc, iocType = 'auto') {
  const result = {
    ioc,
    iocType,
    severity: 'clean',
    risks: [],
    sources: {},
  };

  // Reject empty input
  if (!ioc || !ioc.trim()) {
    return { ...result, iocType: 'unknown', risks: ['Empty IOC — provide an IP, domain, URL, or file hash'] };
  }

  // Validate explicit type or auto-detect
  const validTypes = ['auto', 'ip', 'domain', 'url', 'hash_md5', 'hash_sha1', 'hash_sha256'];
  if (!validTypes.includes(iocType)) {
    return { ...result, iocType: 'unknown', risks: [`Unknown IOC type: ${iocType}. Supported: ip, domain, url, hash_md5, hash_sha1, hash_sha256 (or 'auto' for detection)`] };
  }
  if (iocType === 'auto') {
    if (/^\d+\.\d+\.\d+\.\d+$/.test(ioc)) iocType = 'ip';
    else if (/^[a-fA-F0-9]{32}$/.test(ioc)) iocType = 'hash_md5';
    else if (/^[a-fA-F0-9]{40}$/.test(ioc)) iocType = 'hash_sha1';
    else if (/^[a-fA-F0-9]{64}$/.test(ioc)) iocType = 'hash_sha256';
    else if (/^https?:\/\//.test(ioc)) iocType = 'url';
    else if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(ioc)) iocType = 'domain';
    else iocType = 'unknown';
  }
  result.iocType = iocType;

  if (iocType === 'unknown') {
    return { ...result, risks: ['Could not identify IOC type. Supported: IPv4 address, domain, URL, MD5, SHA1, SHA256 hash. Note: use wallet_check for Ethereum addresses, IPv6 not yet supported.'] };
  }

  // Validate IOC format to prevent injection
  if (iocType === 'ip' && !/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ioc)) {
    return { ...result, risks: ['Invalid IP address format'] };
  }
  if (iocType === 'domain' && !/^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(ioc)) {
    return { ...result, risks: ['Invalid domain format'] };
  }
  if (iocType.startsWith('hash_') && !/^[a-fA-F0-9]+$/.test(ioc)) {
    return { ...result, risks: ['Invalid hash format'] };
  }

  let combinedWeight = 0;

  // AbuseIPDB (IP only)
  if (iocType === 'ip' && ABUSEIPDB_API_KEY) {
    try {
      const resp = await fetchJson(
        `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ioc)}&maxAgeInDays=90`,
        { headers: { 'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json' } }
      );
      if (resp.status === 200 && resp.data?.data) {
        const d = resp.data.data;
        result.sources.abuseipdb = {
          abuseConfidence: d.abuseConfidenceScore,
          totalReports: d.totalReports,
          country: d.countryCode,
          isp: d.isp,
          usageType: d.usageType,
        };
        const weight = d.abuseConfidenceScore / 100;
        combinedWeight += weight;
        if (d.abuseConfidenceScore > 50) {
          result.risks.push(`AbuseIPDB: ${d.abuseConfidenceScore}% confidence, ${d.totalReports} reports`);
        }
      }
    } catch { /* AbuseIPDB unavailable */ }
  }

  // VirusTotal (URL, domain, IP, hash)
  if (VT_API_KEY && iocType !== 'unknown') {
    try {
      let vtUrl;
      if (iocType === 'ip') vtUrl = `https://www.virustotal.com/api/v3/ip_addresses/${ioc}`;
      else if (iocType === 'domain') vtUrl = `https://www.virustotal.com/api/v3/domains/${ioc}`;
      else if (iocType === 'url') {
        const urlId = Buffer.from(ioc).toString('base64').replace(/=/g, '');
        vtUrl = `https://www.virustotal.com/api/v3/urls/${urlId}`;
      }
      else if (iocType.startsWith('hash_')) vtUrl = `https://www.virustotal.com/api/v3/files/${ioc}`;

      if (vtUrl) {
        const vt = await fetchJson(vtUrl, { headers: { 'x-apikey': VT_API_KEY } });
        if (vt.status === 200 && vt.data?.data?.attributes) {
          const stats = vt.data.data.attributes.last_analysis_stats;
          result.sources.virustotal = stats;
          const totalEngines = (stats.malicious || 0) + (stats.undetected || 0) + (stats.harmless || 0) + (stats.suspicious || 0);
          const vtWeight = totalEngines > 0 ? (stats.malicious || 0) / totalEngines : 0;
          combinedWeight += vtWeight;
          if (stats.malicious > 0) {
            result.risks.push(`VirusTotal: ${stats.malicious}/${totalEngines} engines flagged`);
          }
        }
      }
    } catch { /* VT unavailable */ }
  }

  // OTX AlienVault (domain, IP — no key required)
  if (iocType === 'domain' || iocType === 'ip') {
    try {
      const otxType = iocType === 'ip' ? 'IPv4' : 'domain';
      const otx = await fetchJson(
        `https://otx.alienvault.com/api/v1/indicators/${otxType}/${encodeURIComponent(ioc)}/general`
      );
      if (otx.status === 200 && otx.data) {
        const pulseCount = otx.data.pulse_info?.count || 0;
        result.sources.otx = {
          pulseCount,
          reputation: otx.data.reputation || 0,
          country: otx.data.country_name || null,
        };
        if (pulseCount > 0) {
          combinedWeight += 0.5;
          result.risks.push(`OTX AlienVault: found in ${pulseCount} threat pulses`);
        }
      }
    } catch { /* OTX unavailable */ }
  }

  // Weighted severity scoring
  if (combinedWeight >= 1.5) result.severity = 'malicious';
  else if (combinedWeight >= 0.5) result.severity = 'suspicious';
  else if (combinedWeight > 0) result.severity = 'low_confidence';

  result.confidenceWeight = Math.round(combinedWeight * 100) / 100;

  return result;
}

// ─── 6. Header Audit ───

export async function headerAudit(url) {
  const result = {
    url,
    severity: 'clean',
    score: 100,
    risks: [],
    headers: {},
    missing: [],
    present: [],
  };

  if (!validateUserUrl(url)) return { ...result, severity: 'malicious', score: 0, risks: ['Invalid or blocked URL'] };
  if (!await validateUserUrlAsync(url)) return { ...result, severity: 'malicious', score: 0, risks: ['URL resolves to blocked address'] };

  let parsed;
  try { parsed = new URL(url); }
  catch { return { ...result, severity: 'malicious', score: 0, risks: ['Invalid URL'] }; }

  let resp;
  try {
    resp = await fetchHeaders(url);
  } catch (err) {
    return { ...result, severity: 'suspicious', score: 0, risks: [`Failed to fetch: ${err.message}`] };
  }

  const h = resp.headers;
  result.headers = h;

  // Security header checks
  const checks = [
    { name: 'strict-transport-security', label: 'HSTS', weight: 15, check: (v) => {
      if (!v) return 'Missing — no HTTPS enforcement';
      if (!v.includes('max-age')) return 'HSTS present but no max-age';
      const maxAge = parseInt(v.match(/max-age=(\d+)/)?.[1] || '0');
      if (maxAge < 31536000) return `HSTS max-age too short (${maxAge}s, recommend >= 31536000)`;
      return null;
    }},
    { name: 'content-security-policy', label: 'CSP', weight: 15, check: (v) => {
      if (!v) return 'Missing — no XSS/injection protection';
      if (v.includes("'unsafe-inline'") && v.includes("'unsafe-eval'")) return 'CSP present but uses unsafe-inline AND unsafe-eval';
      return null;
    }},
    { name: 'x-content-type-options', label: 'X-Content-Type-Options', weight: 10, check: (v) => {
      if (!v) return 'Missing — MIME sniffing not prevented';
      if (v !== 'nosniff') return `Invalid value: ${v} (should be nosniff)`;
      return null;
    }},
    { name: 'x-frame-options', label: 'X-Frame-Options', weight: 10, check: (v) => {
      if (!v) return 'Missing — clickjacking not prevented';
      if (!['deny', 'sameorigin'].includes(v.toLowerCase())) return `Weak value: ${v}`;
      return null;
    }},
    { name: 'referrer-policy', label: 'Referrer-Policy', weight: 5, check: (v) => {
      if (!v) return 'Missing — referrer information may leak';
      return null;
    }},
    { name: 'permissions-policy', label: 'Permissions-Policy', weight: 5, check: (v) => {
      if (!v) return 'Missing — browser features not restricted';
      return null;
    }},
    { name: 'x-xss-protection', label: 'X-XSS-Protection', weight: 5, check: (v) => {
      // Modern browsers ignore this, CSP is preferred
      if (v === '0') return null; // Intentionally disabled (correct if CSP is set)
      return null;
    }},
  ];

  for (const c of checks) {
    const value = h[c.name] || null;
    const issue = c.check(value);
    if (issue) {
      result.risks.push(`${c.label}: ${issue}`);
      result.missing.push(c.name);
      result.score -= c.weight;
    } else if (value) {
      result.present.push(c.name);
    }
  }

  // Cookie security (check Set-Cookie headers)
  const setCookie = h['set-cookie'];
  if (setCookie) {
    const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
    for (const cookie of cookies) {
      const cl = cookie.toLowerCase();
      if (!cl.includes('httponly')) result.risks.push(`Cookie missing HttpOnly flag: ${cookie.split('=')[0]}`);
      if (!cl.includes('secure') && parsed.protocol === 'https:') result.risks.push(`Cookie missing Secure flag: ${cookie.split('=')[0]}`);
      if (!cl.includes('samesite')) result.risks.push(`Cookie missing SameSite attribute: ${cookie.split('=')[0]}`);
    }
  }

  result.score = Math.max(0, result.score);
  if (result.score < 30) result.severity = 'malicious';
  else if (result.score < 60) result.severity = 'suspicious';
  else if (result.score < 80) result.severity = 'suspicious';

  return result;
}

// ─── 7. Vuln Headers ───

export async function vulnHeaders(url) {
  const result = {
    url,
    severity: 'clean',
    risks: [],
    exposedInfo: [],
  };

  if (!validateUserUrl(url)) return { ...result, severity: 'malicious', risks: ['Invalid or blocked URL'] };
  if (!await validateUserUrlAsync(url)) return { ...result, severity: 'malicious', risks: ['URL resolves to blocked address'] };

  let resp;
  try {
    resp = await fetchHeaders(url);
  } catch (err) {
    return { ...result, severity: 'suspicious', risks: [`Failed to fetch: ${err.message}`] };
  }

  const h = resp.headers;

  // Server version disclosure
  const server = h['server'];
  if (server && /\d+\.\d+/.test(server)) {
    result.risks.push(`Server version exposed: ${server}`);
    result.exposedInfo.push({ header: 'Server', value: server });
  }

  // X-Powered-By
  const poweredBy = h['x-powered-by'];
  if (poweredBy) {
    result.risks.push(`X-Powered-By exposed: ${poweredBy}`);
    result.exposedInfo.push({ header: 'X-Powered-By', value: poweredBy });
  }

  // X-AspNet-Version
  const aspnet = h['x-aspnet-version'];
  if (aspnet) {
    result.risks.push(`ASP.NET version exposed: ${aspnet}`);
    result.exposedInfo.push({ header: 'X-AspNet-Version', value: aspnet });
  }

  // X-AspNetMvc-Version
  const aspnetMvc = h['x-aspnetmvc-version'];
  if (aspnetMvc) {
    result.risks.push(`ASP.NET MVC version exposed: ${aspnetMvc}`);
    result.exposedInfo.push({ header: 'X-AspNetMvc-Version', value: aspnetMvc });
  }

  // Debug headers
  const debug = h['x-debug-token'] || h['x-debug-token-link'] || h['x-debug'];
  if (debug) {
    result.risks.push('Debug headers present — application may be in debug mode');
    result.exposedInfo.push({ header: 'Debug', value: debug });
  }

  // Stack trace in error response
  if (resp.status >= 400) {
    result.risks.push(`HTTP ${resp.status} error response — check if stack traces are exposed in body`);
  }

  // CORS misconfiguration
  const acao = h['access-control-allow-origin'];
  const acac = h['access-control-allow-credentials'];
  if (acao === '*' && acac === 'true') {
    result.risks.push('CORS misconfiguration: Allow-Origin: * with Allow-Credentials: true');
  } else if (acao === '*') {
    result.risks.push('CORS: Access-Control-Allow-Origin is wildcard (*)');
  }

  // Calculate severity
  if (result.risks.length >= 4) result.severity = 'suspicious';
  else if (result.risks.some(r => r.includes('CORS misconfiguration') || r.includes('debug'))) result.severity = 'suspicious';
  else if (result.risks.length > 0) result.severity = 'low';

  return result;
}
