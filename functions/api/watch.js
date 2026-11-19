// POST /api/watch {host, email?}: someone clicked "Tell me when it opens" for weekly re-checks.
// The click is counted. An email is kept only if the person typed one, with the app they checked, so we can write
// once on the day weekly re-checks open. Nothing else about them is kept.
import { allow, bump, servedHere, json } from "../../web/guard.js";
import { cleanHost } from "../../web/report.js";

export const EMAIL = /^[^\s@<>"',;]{1,64}@[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,24}$/i;

export async function onRequestPost({ request, env, waitUntil }) {
  if (!servedHere(request)) return json({ error: "Use https://greenlit.priberry.com" }, 403);
  let body = {};
  try {
    body = (await request.json()) || {};
  } catch {}
  // Five a visitor an hour: enough for anyone, too few to fill the store.
  if (!(await allow(request, { key: "watch", limit: 5 }))) return json({ ok: true, saved: false });
  const day = new Date().toISOString().slice(0, 10);
  if (body.internal !== true) waitUntil(bump(env, ["count:watch:total", `count:watch:${day}`]));
  const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
  if (!email || email.length > 254 || !EMAIL.test(email)) return json({ ok: true, saved: false });
  const host = typeof body.host === "string" ? cleanHost(body.host.slice(0, 300)) : null;
  try {
    const id = crypto.randomUUID().slice(0, 8);
    await env.CHECK.put(`watch:${new Date().toISOString()}:${id}`, JSON.stringify({ email, host: host || null, at: new Date().toISOString(), test: body.internal === true || undefined }));
    return json({ ok: true, saved: true });
  } catch {
    return json({ ok: true, saved: false });
  }
}

export const onRequestGet = () => json({ error: "Use POST." }, 405, { allow: "POST" });
