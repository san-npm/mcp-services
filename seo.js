// ─── SEO Toolkit Service ───
// Tools: serp, onpage_seo, keywords_suggest

import https from 'https';
import http from 'http';

// ─── SERP scraper (Google) ───
const SERP_SCRIPT = `
(function() {
  const results = [];

  // Organic results
  document.querySelectorAll('#search .g, #rso .g').forEach((el, i) => {
    const titleEl = el.querySelector('h3');
    const linkEl = el.querySelector('a[href]');
    const snippetEl = el.querySelector('[data-sncf], .VwiC3b, [style*="-webkit-line-clamp"]');

    if (titleEl && linkEl) {
      const href = linkEl.getAttribute('href');
      if (href && href.startsWith('http')) {
        results.push({
          position: results.length + 1,
          title: titleEl.textContent.trim(),
          url: href,
          snippet: snippetEl ? snippetEl.textContent.trim() : '',
        });
      }
    }
  });

  // People Also Ask
  const paa = [];
  document.querySelectorAll('[data-q], .related-question-pair, [jsname="Cpkphb"]').forEach(el => {
    const q = el.getAttribute('data-q') || el.querySelector('[role="heading"], .dnXCYb')?.textContent?.trim();
    if (q) paa.push(q);
  });

  // Featured snippet
  let featuredSnippet = null;
  const fsEl = document.querySelector('.xpdopen .hgKElc, [data-attrid="wa:/description"] .kno-rdesc span, .IZ6rdc');
  if (fsEl) featuredSnippet = fsEl.textContent.trim().slice(0, 500);

  // Related searches
  const related = [];
  document.querySelectorAll('#brs a, .k8XOCe, .s75CSd a').forEach(el => {
    const text = el.textContent.trim();
    if (text) related.push(text);
  });

  return {
    organic: results.slice(0, 20),
    peopleAlsoAsk: [...new Set(paa)].slice(0, 8),
    featuredSnippet,
    relatedSearches: [...new Set(related)].slice(0, 10),
    totalResults: document.querySelector('#result-stats')?.textContent?.trim() || null,
  };
})()
`;

export async function serpScrape(browser, keyword, setupSsrfProtection) {
  const encoded = encodeURIComponent(keyword);
  const url = `https://www.google.com/search?q=${encoded}&hl=en&gl=us&num=10`;

  const page = await browser.newPage();
  await setupSsrfProtection(page);
  await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
  await page.setExtraHTTPHeaders({ 'Accept-Language': 'en-US,en;q=0.9' });

  try {
    await page.goto(url, { waitUntil: 'networkidle2', timeout: 30000 });

    // Handle consent page
    const consentBtn = await page.$('button[id="L2AGLb"], form[action*="consent"] button');
    if (consentBtn) {
      await consentBtn.click();
      await page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 10000 }).catch(() => {});
    }

    const result = await page.evaluate(SERP_SCRIPT);
    return { keyword, ...result };
  } finally {
    await page.close();
  }
}

// ─── On-page SEO analysis ───
const ONPAGE_SCRIPT = `
(function() {
  const startTime = performance.now();

  // Title
  const title = document.title || '';
  const titleLength = title.length;

  // Meta description
  const metaDesc = document.querySelector('meta[name="description"]')?.content || '';
  const metaDescLength = metaDesc.length;

  // Headings
  const headings = { h1: [], h2: [], h3: [], h4: [], h5: [], h6: [] };
  for (let i = 1; i <= 6; i++) {
    document.querySelectorAll('h' + i).forEach(h => {
      headings['h' + i].push(h.textContent.trim().slice(0, 200));
    });
  }

  // Word count
  const bodyText = document.body.innerText || '';
  const wordCount = bodyText.split(/\\s+/).filter(Boolean).length;

  // Links
  const origin = window.location.origin;
  let internalLinks = 0, externalLinks = 0, brokenLinks = [];
  document.querySelectorAll('a[href]').forEach(a => {
    try {
      const u = new URL(a.href, origin);
      if (u.origin === origin) internalLinks++;
      else externalLinks++;
      if (!a.textContent.trim() && !a.querySelector('img')) {
        brokenLinks.push({ url: a.href, issue: 'empty anchor text' });
      }
    } catch {}
  });

  // Images
  const totalImages = document.querySelectorAll('img').length;
  const imagesWithAlt = document.querySelectorAll('img[alt]:not([alt=""])').length;
  const imagesMissingAlt = [];
  document.querySelectorAll('img:not([alt]), img[alt=""]').forEach(img => {
    imagesMissingAlt.push(img.src?.slice(0, 200) || 'unknown');
  });

  // Schema / JSON-LD
  const schemas = [];
  document.querySelectorAll('script[type="application/ld+json"]').forEach(s => {
    try {
      const d = JSON.parse(s.textContent);
      schemas.push(d['@type'] || 'unknown');
    } catch {}
  });

  // Canonical
  const canonical = document.querySelector('link[rel="canonical"]')?.href || null;

  // Robots
  const robotsMeta = document.querySelector('meta[name="robots"]')?.content || null;

  // Open Graph completeness
  const ogTags = {};
  document.querySelectorAll('meta[property^="og:"]').forEach(m => {
    ogTags[m.getAttribute('property')] = m.getAttribute('content');
  });
  const ogRequired = ['og:title', 'og:description', 'og:image', 'og:url', 'og:type'];
  const ogPresent = ogRequired.filter(t => ogTags[t]);
  const ogScore = Math.round((ogPresent.length / ogRequired.length) * 100);

  // Viewport
  const hasViewport = !!document.querySelector('meta[name="viewport"]');

  // Lang
  const lang = document.documentElement.lang || null;

  // Load time
  const loadTime = Math.round(performance.now() - startTime);

  // Scoring
  let score = 100;
  const issues = [];

  if (titleLength === 0) { score -= 15; issues.push('Missing title tag'); }
  else if (titleLength < 30) { score -= 5; issues.push('Title too short (< 30 chars)'); }
  else if (titleLength > 60) { score -= 5; issues.push('Title too long (> 60 chars)'); }

  if (metaDescLength === 0) { score -= 15; issues.push('Missing meta description'); }
  else if (metaDescLength < 70) { score -= 5; issues.push('Meta description too short (< 70 chars)'); }
  else if (metaDescLength > 160) { score -= 5; issues.push('Meta description too long (> 160 chars)'); }

  if (headings.h1.length === 0) { score -= 10; issues.push('Missing H1 tag'); }
  else if (headings.h1.length > 1) { score -= 5; issues.push('Multiple H1 tags (' + headings.h1.length + ')'); }

  if (totalImages > 0 && imagesMissingAlt.length > 0) {
    const pct = Math.round((imagesMissingAlt.length / totalImages) * 100);
    score -= Math.min(10, Math.round(pct / 10));
    issues.push(imagesMissingAlt.length + ' images missing alt text (' + pct + '%)');
  }

  if (!canonical) { score -= 5; issues.push('No canonical URL set'); }
  if (ogScore < 100) { score -= 5; issues.push('Incomplete Open Graph tags (' + ogScore + '%)'); }
  if (!hasViewport) { score -= 5; issues.push('Missing viewport meta tag'); }
  if (!lang) { score -= 3; issues.push('No lang attribute on html element'); }
  if (schemas.length === 0) { score -= 5; issues.push('No structured data (JSON-LD) found'); }

  return {
    url: window.location.href,
    score: Math.max(0, score),
    title: { text: title, length: titleLength },
    metaDescription: { text: metaDesc, length: metaDescLength },
    headings: {
      h1: headings.h1,
      h2: headings.h2.slice(0, 20),
      h3: headings.h3.slice(0, 20),
      counts: { h1: headings.h1.length, h2: headings.h2.length, h3: headings.h3.length, h4: headings.h4.length, h5: headings.h5.length, h6: headings.h6.length }
    },
    content: { wordCount },
    links: { internal: internalLinks, external: externalLinks, issues: brokenLinks.slice(0, 10) },
    images: { total: totalImages, withAlt: imagesWithAlt, missingAlt: imagesMissingAlt.slice(0, 10) },
    schema: schemas,
    canonical,
    robotsMeta,
    openGraph: { tags: ogTags, score: ogScore, missing: ogRequired.filter(t => !ogTags[t]) },
    viewport: hasViewport,
    lang,
    loadTimeMs: loadTime,
    issues,
  };
})()
`;

export async function onpageSeo(browser, url, setupSsrfProtection) {
  const page = await browser.newPage();
  await setupSsrfProtection(page);
  await page.setUserAgent('Mozilla/5.0 (compatible; MCPServicesBot/1.0)');
  try {
    const start = Date.now();
    await page.goto(url, { waitUntil: 'networkidle2', timeout: 30000 });
    const serverLoadTime = Date.now() - start;
    const result = await page.evaluate(ONPAGE_SCRIPT);
    result.serverLoadTimeMs = serverLoadTime;
    return result;
  } finally {
    await page.close();
  }
}

// ─── Keyword suggestions via Google Autocomplete ───
function fetchJson(url) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    const req = mod.get(url, { timeout: 5000 }, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch { reject(new Error('Invalid JSON')); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
  });
}

export async function keywordsSuggest(keyword) {
  const encoded = encodeURIComponent(keyword);
  const suggestions = new Set();

  // Base query
  try {
    const data = await fetchJson(`https://suggestqueries.google.com/complete/search?client=firefox&q=${encoded}`);
    if (Array.isArray(data[1])) data[1].forEach(s => suggestions.add(s));
  } catch {}

  // Append a-z for more variations
  const letters = 'abcdefghijklmnopqrstuvwxyz'.split('');
  const batchSize = 5;
  for (let i = 0; i < letters.length; i += batchSize) {
    const batch = letters.slice(i, i + batchSize);
    const promises = batch.map(async (letter) => {
      try {
        const data = await fetchJson(`https://suggestqueries.google.com/complete/search?client=firefox&q=${encoded}+${letter}`);
        if (Array.isArray(data[1])) data[1].forEach(s => suggestions.add(s));
      } catch {}
    });
    await Promise.all(promises);
  }

  // Remove exact match
  suggestions.delete(keyword);

  return {
    keyword,
    suggestions: [...suggestions].slice(0, 100),
    count: suggestions.size,
  };
}
