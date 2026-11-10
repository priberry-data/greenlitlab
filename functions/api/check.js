// POST /api/check {url}: the passive Greenlit check, run from the web. It reads only what the site serves
// to every visitor, the same as `npx greenlitlab <url>` without --mine. Database checks never run here,
// because we can't know the person owns the app.
import { siteScan, explainError } from "../../src/grade.mjs";
import { selfProbe, allowKey, publicTarget, allow, bump, cacheGet, cachePut, servedHere, json } from "../../web/guard.js";

// Enough to fix and re-check all afternoon, even when a whole office or mobile network shares one address.
const PER_HOUR = 30;
// Short, because the whole point is to check again once a fix is live.
const CACHE_SECONDS = 120;
// Smaller than the CLI's: one web request may make about 50 fetches and must answer well inside a minute.
export const WEB_LIMITS = { maxScripts: 30, maxBytes: 3 * 1024 * 1024, maxTotalBytes: 8 * 1024 * 1024, deadlineMs: 18000, scriptTimeoutMs: 5000, pageTimeoutMs: 10000, tailMs: 8000 };
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
    if (Math.random() < 0.2) waitUntil(bump(env, [`count:fail:limit:${day()}`], 5));
    return json({ error: `That's ${PER_HOUR} checks this hour. Try again later, or run it on your own computer: npx greenlitlab <address>` }, 429);
  }

  // Different pages of one site are different checks, so the site itself gets a limit too: nobody can use us to hammer it.
  const host = new URL(t.url).host;
  if (!(await allowKey(`host:${host}`, 10, 600))) {
    // Nobody is locked out by someone else's checks: the latest result for this same address is shown, with its age.
    const last = await cacheGet(`last:${t.url}`);
    return last ? json({ ...last, cached: true }) : json({ error: "That site has been checked many times in the last few minutes. Try again shortly, or run it on your own computer: npx greenlitlab <address>" }, 429);
  }

  let result;
  try {
    // Smaller limits than the CLI: one web request may make only about 50 fetches on Cloudflare's free plan, and the launch checks need a few of them.
    result = await siteScan(t.url, { mine: false, ...WEB_LIMITS, ...selfProbe(request, host) });
  } catch (e) {
    const message = String(e.message || e);
    // Counted by kind and day, with no address, so we can see when people are hitting a wall.
    const code = (message.match(/\((\d{3})\)$/) || [])[1];
    // Sampled like the check counter, so refused or failing requests can't use up the store's daily writes.
    if (Math.random() < 0.2) waitUntil(bump(env, [`count:fail:${code || (/timed out/.test(message) ? "timeout" : "other")}:${day()}`], 5));
    return json({ error: explainError(message) }, 422);
  }
  // The leaked key's first characters help the owner find it; nobody else needs them.
  for (const f of result.findings) f.why = f.why.replace(/ Found: [^ ]+…$/, "");
  result.checkedAt = new Date().toISOString();
  await cachePut(cacheKey, result, CACHE_SECONDS);
  await cachePut(`last:${t.url}`, result, 600);
  // Counted one time in five, five at a time: the count stays right on average and the store's daily write limit lasts.
  if (Math.random() < 0.2) waitUntil(bump(env, [`count:checks:${day()}`], 5));
  return json(result);
}

export const onRequestGet = () => json({ error: "Use POST." }, 405, { allow: "POST" });
