// Shared by the web endpoints: which addresses we will fetch, and how often one visitor may ask.

// Only public web addresses: no IP literals, no internal names, no odd ports. The check runs from
// Cloudflare's network, so this is about not being used to probe anything that isn't a public website.
export function publicTarget(input) {
  let u;
  try {
    u = new URL(/^https?:\/\//i.test(input) ? input : `https://${input}`);
  } catch {
    return { error: "That doesn't look like a web address." };
  }
  if (!/^https?:$/.test(u.protocol)) return { error: "Only http and https addresses can be checked." };
  if (u.username || u.password) return { error: "Leave the user name and password out of the address." };
  if (u.port && !["80", "443"].includes(u.port)) return { error: "Only sites on the standard ports can be checked." };
  const h = u.hostname.toLowerCase();
  if (!h.includes(".") || /^[\d.]+$/.test(h) || h.includes(":") || /(^|\.)(localhost|local|internal|intranet|lan|home|corp|test|example|invalid)$/.test(h))
    return { error: "Enter the public address of your app, like myapp.lovable.app." };
  if (/(^|\.)priberry\.com$/.test(h) && !["greenlit.priberry.com", "crumple.priberry.com", "tare.priberry.com", "priberry.com"].includes(h)) return { error: "Enter the public address of your app." };
  return { url: `${u.protocol}//${h}${u.pathname === "/" ? "/" : u.pathname}` };
}

// Short-lived state (cached results, per-visitor counters) lives in Cloudflare's cache, not in KV:
// the free plan allows about 1,000 KV writes a day, which a busy launch day would use up in an hour.
// The cache is per data centre, so limits are approximate. That's fine: a few extra checks don't matter;
// a script asking hundreds of times does.
const slot = (name) => new Request(`https://greenlit.priberry.com/__state/${encodeURIComponent(name)}`);

export async function cacheGet(name) {
  try {
    const r = await caches.default.match(slot(name));
    return r ? await r.json() : null;
  } catch {
    return null;
  }
}

export async function cachePut(name, value, seconds) {
  try {
    await caches.default.put(slot(name), new Response(JSON.stringify(value), { headers: { "content-type": "application/json", "cache-control": `max-age=${seconds}` } }));
  } catch {}
}

// A fixed window per visitor per hour. Only a salted hash of the address is kept, for an hour.
export async function allow(request, { key, limit }) {
  const hour = Math.floor(Date.now() / 3600e3);
  const raw = `${request.headers.get("cf-connecting-ip") || "unknown"}|${hour}|greenlit-v2`;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(raw));
  const id = [...new Uint8Array(digest)].slice(0, 12).map((b) => b.toString(16).padStart(2, "0")).join("");
  const name = `rl:${key}:${id}:${hour}`;
  const n = Number((await cacheGet(name)) || 0);
  if (n >= limit) return false;
  await cachePut(name, n + 1, 3700);
  return true;
}

// Counts for the price test, in KV so they last. Never lets a failed write break the request.
export async function bump(env, keys) {
  for (const k of keys) {
    try {
      await env.CHECK.put(k, String(Number((await env.CHECK.get(k)) || 0) + 1));
    } catch {}
  }
}

// The cache only works on the real address, so the API answers there only (and on a local dev server).
export const servedHere = (request) => /^(greenlit\.priberry\.com|localhost|127\.0\.0\.1)$/.test(new URL(request.url).hostname);

export const json = (body, status = 200, extra = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...extra } });

// A check of Greenlit's own address is a request from this site to itself, which skips the edge's http-to-https
// redirect and would look like a missing one. For that one host the plain-http question isn't asked.
export const selfProbe = (request, host) => (host === new URL(request.url).hostname ? { httpProbe: async () => ({ status: 0 }) } : {});
