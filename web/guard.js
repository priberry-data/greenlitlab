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

// A fixed window per visitor per hour, in KV. Approximate on purpose: KV is eventually consistent, and a
// few extra checks don't matter; a script asking hundreds of times does.
export async function allow(env, request, { key, limit }) {
  // Only a salted hash of the address is kept, for an hour, so the counter can't be turned back into an IP.
  const hour = Math.floor(Date.now() / 3600e3);
  const raw = `${request.headers.get("cf-connecting-ip") || "unknown"}|${hour}|greenlit`;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(raw));
  const id = [...new Uint8Array(digest)].slice(0, 12).map((b) => b.toString(16).padStart(2, "0")).join("");
  const k = `rl:${key}:${id}:${hour}`;
  const n = Number((await env.CHECK.get(k)) || 0);
  if (n >= limit) return false;
  await env.CHECK.put(k, String(n + 1), { expirationTtl: 3700 });
  return true;
}

export const json = (body, status = 200, extra = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...extra } });
