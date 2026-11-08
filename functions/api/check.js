// POST /api/check {url}: the passive Greenlit check, run from the web. It reads only what the site serves
// to every visitor, the same as `npx greenlitlab <url>` without --mine. Database checks never run here,
// because we can't know the person owns the app.
import { siteScan } from "../../src/grade.mjs";
import { publicTarget, allow, bump, cacheGet, cachePut, servedHere, json } from "../../web/guard.js";

const PER_HOUR = 20;
const CACHE_SECONDS = 600;

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

  // The same site checked again within ten minutes gets the saved result, so nobody can use us to hammer a site.
  const cacheKey = `site:${t.url}`;
  const cached = await cacheGet(cacheKey);
  if (cached) return json({ ...cached, cached: true });

  if (!(await allow(request, { key: "check", limit: PER_HOUR })))
    return json({ error: `That's ${PER_HOUR} checks this hour. Try again later, or run it on your own computer: npx greenlitlab <address>` }, 429);

  let result;
  try {
    // Smaller limits than the CLI: the web check runs on a small, shared machine.
    result = await siteScan(t.url, { mine: false, maxScripts: 20, maxBytes: 3 * 1024 * 1024 });
  } catch (e) {
    return json({ error: plainError(String(e.message || e)) }, 422);
  }
  // The leaked key's first characters help the owner find it; nobody else needs them.
  for (const f of result.findings) f.why = f.why.replace(/ Found: [^ ]+…$/, "");
  await cachePut(cacheKey, result, CACHE_SECONDS);
  waitUntil(bump(env, [`count:checks:${new Date().toISOString().slice(0, 10)}`]));
  return json(result);
}

// What went wrong, in words a non-developer can act on.
function plainError(m) {
  const code = Number((m.match(/\((\d{3})\)$/) || [])[1]);
  if (code === 404) return "That address answered \"not found\". Check it's the live address of your app (open it in your browser first).";
  if (code === 401 || code === 403) return "That site turned the check away. It may be private, password-protected, or blocking automated visitors.";
  if (code >= 500) return `That site had an error of its own (${code}). Try again in a few minutes.`;
  if (/timed out/.test(m)) return "That site took too long to answer. Try again in a minute.";
  if (/look like a web address/.test(m)) return "That doesn't look like a web address. Try something like myapp.lovable.app.";
  return "Couldn't reach that site. Check the address and that the app is published.";
}

export const onRequestGet = () => json({ error: "Use POST." }, 405, { allow: "POST" });
