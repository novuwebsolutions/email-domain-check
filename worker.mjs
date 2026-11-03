// The check as a small Cloudflare Worker: GET /?domain=firma.ee&lang=et
// answers with the report as JSON. wrangler.example.jsonc has the settings,
// the README the steps.
//
// It asks only public DNS, so it cannot be used to reach anyone's server. The
// limits keep one visitor from spending your Worker's daily requests: a few
// checks a minute per IP (the IP_LIMIT binding), and a domain checked again
// within ten minutes is answered from the cache.
import { checkEmailDomain, CheckError } from './email-domain-check.mjs';

const CACHE_SECONDS = 600;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (request.method !== 'GET') return json({ error: { code: 'method', message: 'GET only' } }, 405);
    const input = url.searchParams.get('domain') ?? '';
    const lang = url.searchParams.get('lang') === 'en' ? 'en' : 'et';
    if (!input) return json({ error: { code: 'empty', message: 'Add ?domain=firma.ee' } }, 400);

    const cache = globalThis.caches?.default;
    const key = new Request(new URL(`/__cache/${lang}/${encodeURIComponent(input.trim().toLowerCase())}`, url).href);
    const cached = await cache?.match(key);
    if (cached) return cached;

    if (env.IP_LIMIT) {
      const ip = request.headers.get('cf-connecting-ip') ?? 'unknown';
      const { success } = await env.IP_LIMIT.limit({ key: ip });
      if (!success) return json({ error: { code: 'rate-limit', message: 'Too many checks. Try again in a minute.' } }, 429);
    }

    try {
      const report = await checkEmailDomain(input, { lang });
      const response = json(report, 200, CACHE_SECONDS);
      if (cache) ctx.waitUntil(cache.put(key, response.clone()));
      return response;
    } catch (error) {
      if (error instanceof CheckError) return json({ error: { code: error.code, message: error.message } }, 422);
      return json({ error: { code: 'internal', message: 'The check failed.' } }, 500);
    }
  },
};

function json(body, status = 200, maxAge = 0) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': maxAge ? `public, max-age=${maxAge}` : 'no-store',
      'x-robots-tag': 'noindex',
      'x-content-type-options': 'nosniff',
    },
  });
}
