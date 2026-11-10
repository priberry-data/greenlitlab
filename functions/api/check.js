// POST /api/check {url}: the passive Greenlit check, run from the web. It reads only what the site serves
// to every visitor, the same as `npx greenlitlab <url>` without --mine. Database checks never run here,
// because we can't know the person owns the app.
import { siteScan, explainError } from "../../src/grade.mjs";
import { selfProbe, publicTarget, allow, bump, cacheGet, cachePut, servedHere, json } from "../../web/guard.js";

// Enough to fix and re-check all afternoon, even when a whole office or mobile network shares one address.
const PER_HOUR = 30;
// Short, because the whole point is to check again once a fix is live.
const CACHE_SECONDS = 120;
const day = () => new Date().toISOString().slice(0, 10);

export async function onRequestPost({ request, env, waitUntil }) {
  if (!servedHere(request)) return json({ error: "Use https://greenlit.priberry.com" }, 403);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'Send {"url": "myapp.lovable.app"}.' }, 400);
  }
  if (typeof body?.url !== "string") return json({ error: 'Send {"url": "myapp.lovable.app"}.' }, 400);
  const t = publicTarget(body.url.trim().slice(0, 300));
  if (t.error) return json({ error: t.error }, 400);

  // The same site checked again within two minutes gets the saved result, so nobody can use us to hammer a site.
  const cacheKey = `site:${t.url}`;
  const cached = await cacheGet(cacheKey);
  if (cached) return json({ ...cached, cached: true });

  if (!(await allow(request, { key: "check", limit: PER_HOUR }))) {
    waitUntil(bump(env, [`count:fail:limit:${day()}`]));
    return json({ error: `That's ${PER_HOUR} checks this hour. Try again later, or run it on your own computer: npx greenlitlab <address>` }, 429);
  }

  let result;
  try {
    // Smaller limits than the CLI: one web request may make only about 50 fetches on Cloudflare's free plan, and the launch checks need a few of them.
    result = await siteScan(t.url, { mine: false, maxScripts: 36, maxBytes: 3 * 1024 * 1024, maxTotalBytes: 12 * 1024 * 1024, deadlineMs: 25000, scriptTimeoutMs: 6000, ...selfProbe(request, new URL(t.url).host) });
  } catch (e) {
    const message = String(e.message || e);
    // Counted by kind and day, with no address, so we can see when people are hitting a wall.
    const code = (message.match(/\((\d{3})\)$/) || [])[1];
    waitUntil(bump(env, [`count:fail:${code || (/timed out/.test(message) ? "timeout" : "other")}:${day()}`]));
    return json({ error: explainError(message) }, 422);
  }
  // The leaked key's first characters help the owner find it; nobody else needs them.
  for (const f of result.findings) f.why = f.why.replace(/ Found: [^ ]+…$/, "");
  await cachePut(cacheKey, result, CACHE_SECONDS);
  waitUntil(bump(env, [`count:checks:${day()}`]));
  return json(result);
}

export const onRequestGet = () => json({ error: "Use POST." }, 405, { allow: "POST" });
