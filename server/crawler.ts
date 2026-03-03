import * as cheerio from 'cheerio';

export async function crawlWebsite(url: string) {
  const endpoints: any[] = [];
  try {
    const response = await fetch(url);
    const html = await response.text();
    const $ = cheerio.load(html);
    
    $('a').each((i, link) => {
      const href = $(link).attr('href');
      if (href && href.startsWith('http')) {
        endpoints.push({ url: href, methods: ['GET'], params: [] });
      } else if (href && href.startsWith('/')) {
        endpoints.push({ url: new URL(href, url).href, methods: ['GET'], params: [] });
      }
    });

    $('form').each((i, form) => {
      const action = $(form).attr('action') || '';
      const method = ($(form).attr('method') || 'GET').toUpperCase();
      const params: string[] = [];
      $(form).find('input, select, textarea').each((j, input) => {
        const name = $(input).attr('name');
        if (name) params.push(name);
      });
      const formUrl = action.startsWith('http') ? action : new URL(action, url).href;
      endpoints.push({ url: formUrl, methods: [method], params });
    });

    // Deduplicate
    const uniqueEndpoints = Array.from(new Set(endpoints.map(e => JSON.stringify(e)))).map(e => JSON.parse(e));
    return uniqueEndpoints.slice(0, 20); // Limit to 20 for prototype
  } catch (error) {
    console.error('Crawling error:', error);
    return [{ url, methods: ['GET'], params: [] }]; // Fallback
  }
}
