// ─── Web Scraper Service ───
// Tools: scrape, crawl, extract

const MAX_CRAWL_DEPTH = 3;
const MAX_CRAWL_PAGES = 20;
const MAX_CONTENT_LENGTH = 2 * 1024 * 1024;

// ─── DOM to Markdown converter (runs in browser context) ───
export const DOM_TO_MD_SCRIPT = `
(function(maxLen) {
  const remove = document.querySelectorAll('script, style, nav, footer, aside, header, [role="banner"], [role="navigation"], .ad, .ads, .sidebar, .cookie-banner, .popup, #cookie-consent');
  remove.forEach(el => el.remove());

  const article = document.querySelector('article, main, [role="main"], .post-content, .entry-content, .article-body') || document.body;

  function escape(s) { return s.replace(/[\\[\\]()]/g, '\\\\$&'); }

  function nodeToMd(node, listDepth) {
    if (node.nodeType === 3) {
      const t = node.textContent.replace(/\\s+/g, ' ');
      return t;
    }
    if (node.nodeType !== 1) return '';
    const tag = node.tagName.toLowerCase();
    if (['script','style','nav','footer','aside','noscript','svg'].includes(tag)) return '';

    const kids = Array.from(node.childNodes).map(c => nodeToMd(c, listDepth)).join('');
    const trimmed = kids.trim();
    if (!trimmed && !['br','hr','img'].includes(tag)) return '';

    switch (tag) {
      case 'h1': return '\\n\\n# ' + trimmed + '\\n\\n';
      case 'h2': return '\\n\\n## ' + trimmed + '\\n\\n';
      case 'h3': return '\\n\\n### ' + trimmed + '\\n\\n';
      case 'h4': return '\\n\\n#### ' + trimmed + '\\n\\n';
      case 'h5': return '\\n\\n##### ' + trimmed + '\\n\\n';
      case 'h6': return '\\n\\n###### ' + trimmed + '\\n\\n';
      case 'p': return '\\n\\n' + trimmed + '\\n\\n';
      case 'br': return '\\n';
      case 'hr': return '\\n\\n---\\n\\n';
      case 'strong': case 'b': return '**' + trimmed + '**';
      case 'em': case 'i': return '*' + trimmed + '*';
      case 'del': case 's': return '~~' + trimmed + '~~';
      case 'a': {
        const href = node.getAttribute('href') || '';
        if (!href || href.startsWith('#') || href.startsWith('javascript:')) return trimmed;
        return '[' + trimmed + '](' + href + ')';
      }
      case 'code': {
        if (node.parentElement && node.parentElement.tagName === 'PRE') return trimmed;
        return '\\u0060' + trimmed + '\\u0060';
      }
      case 'pre': {
        const code = node.querySelector('code');
        const lang = code ? (code.className.match(/language-(\\w+)/) || [])[1] || '' : '';
        const content = code ? code.textContent : node.textContent;
        return '\\n\\n\\u0060\\u0060\\u0060' + lang + '\\n' + content.trim() + '\\n\\u0060\\u0060\\u0060\\n\\n';
      }
      case 'li': {
        const indent = '  '.repeat(Math.max(0, listDepth - 1));
        const parent = node.parentElement;
        const prefix = parent && parent.tagName === 'OL'
          ? (Array.from(parent.children).indexOf(node) + 1) + '. '
          : '- ';
        return indent + prefix + trimmed + '\\n';
      }
      case 'ul': case 'ol': return '\\n' + Array.from(node.childNodes).map(c => nodeToMd(c, (listDepth || 0) + 1)).join('') + '\\n';
      case 'blockquote': return '\\n\\n> ' + trimmed.replace(/\\n/g, '\\n> ') + '\\n\\n';
      case 'img': {
        const alt = node.getAttribute('alt') || '';
        const src = node.getAttribute('src') || '';
        return src ? '![' + alt + '](' + src + ')' : '';
      }
      case 'table': {
        const rows = Array.from(node.querySelectorAll('tr'));
        if (!rows.length) return '';
        let md = '\\n\\n';
        rows.forEach((row, i) => {
          const cells = Array.from(row.querySelectorAll('th, td'));
          md += '| ' + cells.map(c => c.textContent.trim().replace(/\\|/g, '\\\\|')).join(' | ') + ' |\\n';
          if (i === 0) {
            md += '| ' + cells.map(() => '---').join(' | ') + ' |\\n';
          }
        });
        return md + '\\n';
      }
      case 'div': case 'section': case 'article': case 'main': case 'span': case 'figure': case 'figcaption':
        return kids;
      default: return kids;
    }
  }

  const md = nodeToMd(article, 0)
    .replace(/\\n{3,}/g, '\\n\\n')
    .replace(/^\\s+|\\s+$/g, '');

  // Collect links
  const links = [];
  article.querySelectorAll('a[href]').forEach(a => {
    const href = a.getAttribute('href');
    if (href && !href.startsWith('#') && !href.startsWith('javascript:')) {
      links.push({ text: a.textContent.trim().slice(0, 100), href });
    }
  });

  const title = document.title || '';
  const wordCount = md.split(/\\s+/).filter(Boolean).length;
  const truncated = md.length > maxLen ? md.slice(0, maxLen) + '\\n\\n[Content truncated]' : md;

  return { title, markdown: truncated, wordCount, links: links.slice(0, 100) };
})
`;

// ─── Extraction script (runs in browser context) ───
const EXTRACT_SCRIPT = `
(function() {
  // JSON-LD
  const jsonLd = [];
  document.querySelectorAll('script[type="application/ld+json"]').forEach(s => {
    try { jsonLd.push(JSON.parse(s.textContent)); } catch {}
  });

  // Open Graph
  const og = {};
  document.querySelectorAll('meta[property^="og:"]').forEach(m => {
    og[m.getAttribute('property')] = m.getAttribute('content');
  });

  // Twitter Card
  const twitter = {};
  document.querySelectorAll('meta[name^="twitter:"]').forEach(m => {
    twitter[m.getAttribute('name')] = m.getAttribute('content');
  });

  // Meta tags
  const meta = {};
  document.querySelectorAll('meta[name]').forEach(m => {
    const name = m.getAttribute('name');
    if (name && !name.startsWith('twitter:')) {
      meta[name] = m.getAttribute('content');
    }
  });

  // Headings
  const headings = [];
  document.querySelectorAll('h1, h2, h3, h4, h5, h6').forEach(h => {
    headings.push({ level: parseInt(h.tagName[1]), text: h.textContent.trim().slice(0, 200) });
  });

  // Links
  const internal = [], external = [];
  const origin = window.location.origin;
  document.querySelectorAll('a[href]').forEach(a => {
    try {
      const url = new URL(a.href, origin);
      const entry = { text: a.textContent.trim().slice(0, 100), url: url.href };
      if (url.origin === origin) internal.push(entry);
      else external.push(entry);
    } catch {}
  });

  // Images
  const images = [];
  document.querySelectorAll('img').forEach(img => {
    images.push({
      src: img.src || '',
      alt: img.alt || '',
      width: img.naturalWidth || null,
      height: img.naturalHeight || null,
    });
  });

  // Tables
  const tables = [];
  document.querySelectorAll('table').forEach(table => {
    const rows = [];
    table.querySelectorAll('tr').forEach(tr => {
      const cells = Array.from(tr.querySelectorAll('th, td')).map(c => c.textContent.trim());
      rows.push(cells);
    });
    if (rows.length) tables.push(rows);
  });

  return {
    title: document.title,
    url: window.location.href,
    canonical: document.querySelector('link[rel="canonical"]')?.href || null,
    jsonLd,
    openGraph: og,
    twitterCard: twitter,
    meta,
    headings,
    links: { internal: internal.slice(0, 100), external: external.slice(0, 100) },
    images: images.slice(0, 100),
    tables: tables.slice(0, 10),
  };
})()
`;

// ─── Scrape handler ───
export async function scrapeUrl(browser, url, setupSsrfProtection) {
  const page = await browser.newPage();
  await setupSsrfProtection(page);
  await page.setUserAgent('Mozilla/5.0 (compatible; MCPServicesBot/1.0)');
  try {
    await page.goto(url, { waitUntil: 'networkidle2', timeout: 30000 });
    const result = await page.evaluate(`${DOM_TO_MD_SCRIPT}(${MAX_CONTENT_LENGTH})`);
    return { url, ...result };
  } finally {
    await page.close();
  }
}

// ─── Crawl handler ───
export async function crawlSite(browser, startUrl, depth, maxPages, setupSsrfProtection, validateUrl, validateUrlAsync) {
  const clampedDepth = Math.min(Math.max(depth || 1, 1), MAX_CRAWL_DEPTH);
  const clampedMax = Math.min(Math.max(maxPages || 10, 1), MAX_CRAWL_PAGES);

  const startOrigin = new URL(startUrl).origin;
  const visited = new Set();
  const results = [];
  const queue = [{ url: startUrl, currentDepth: 0 }];

  while (queue.length > 0 && results.length < clampedMax) {
    const { url, currentDepth } = queue.shift();
    const normalized = url.split('#')[0].split('?')[0].replace(/\/$/, '');
    if (visited.has(normalized)) continue;
    visited.add(normalized);

    if (!validateUrl(url)) continue;
    try {
      if (!await validateUrlAsync(url)) continue;
    } catch { continue; }

    try {
      const page = await browser.newPage();
      await setupSsrfProtection(page);
      await page.setUserAgent('Mozilla/5.0 (compatible; MCPServicesBot/1.0)');
      await page.goto(url, { waitUntil: 'networkidle2', timeout: 20000 });

      const data = await page.evaluate(`${DOM_TO_MD_SCRIPT}(${MAX_CONTENT_LENGTH})`);
      results.push({ url, title: data.title, markdown: data.markdown, wordCount: data.wordCount });

      // Queue internal links for deeper crawling
      if (currentDepth < clampedDepth) {
        for (const link of (data.links || [])) {
          try {
            const resolved = new URL(link.href, url);
            if (resolved.origin === startOrigin && !visited.has(resolved.href.split('#')[0].split('?')[0].replace(/\/$/, ''))) {
              queue.push({ url: resolved.href, currentDepth: currentDepth + 1 });
            }
          } catch {}
        }
      }

      await page.close();
    } catch (err) {
      // Skip failed pages, continue crawling
      console.error(`[crawl] Failed ${url}: ${err.message}`);
    }
  }

  return { startUrl, depth: clampedDepth, maxPages: clampedMax, pagesScraped: results.length, pages: results };
}

// ─── Extract handler ───
export async function extractData(browser, url, setupSsrfProtection) {
  const page = await browser.newPage();
  await setupSsrfProtection(page);
  await page.setUserAgent('Mozilla/5.0 (compatible; MCPServicesBot/1.0)');
  try {
    await page.goto(url, { waitUntil: 'networkidle2', timeout: 30000 });
    const result = await page.evaluate(EXTRACT_SCRIPT);
    return result;
  } finally {
    await page.close();
  }
}
