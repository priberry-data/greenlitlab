// POST /api/check {url}: the passive Greenlit check, run from the web. It reads only what the site serves
// to every visitor, the same as `npx greenlitlab <url>` without --mine. Database checks never run here,
// because we can't know the person owns the app.
import { siteScan } from "../../src/grade.mjs";
import { publicTarget, allow, json } from "../../web/guard.js";

const PER_HOUR = 20;
const CACHE_SECONDS = 600;

export async function onRequestPost({ request, env }) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Send {\"url\": \"myapp.lovable.app\"}." }, 400);
  }
  const t = publicTarget(String(body?.url ?? "").trim().slice(0, 300));
  if (t.error) return json({ error: t.error }, 400);

  // The same site checked again within ten minutes gets the saved result, so nobody can use us to hammer a site.
  const cacheKey = `site:${t.url}`;
  const cached = await env.CHECK.get(cacheKey, "json");
  if (cached) return json({ ...cached, cached: true });

  if (!(await allow(env, request, { key: "check", limit: PER_HOUR })))
    return json({ error: `That's ${PER_HOUR} checks this hour. Try again later, or run it on your own machine: npx greenlitlab <url>` }, 429);

  let result;
  try {
    result = await siteScan(t.url, { mine: false, maxScripts: 20 });
  } catch (e) {
    return json({ error: `Couldn't check that site: ${String(e.message || e).replace(/^could not load /, "couldn't load ")}` }, 422);
  }
  // The leaked key's first characters help the owner find it; nobody else needs them.
  for (const f of result.findings) f.why = f.why.replace(/ Found: [^ ]+…$/, "");
  await env.CHECK.put(cacheKey, JSON.stringify(result), { expirationTtl: CACHE_SECONDS });
  const day = new Date().toISOString().slice(0, 10);
  const n = Number((await env.CHECK.get(`count:checks:${day}`)) || 0);
  await env.CHECK.put(`count:checks:${day}`, String(n + 1));
  return json(result);
}

export const onRequestGet = () => json({ error: "Use POST." }, 405, { allow: "POST" });
