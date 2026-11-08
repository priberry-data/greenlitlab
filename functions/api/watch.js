// POST /api/watch: someone clicked "Watch my app". We count the click (the price test for the paid monitor)
// and keep nothing about who clicked or which site.
import { allow, json } from "../../web/guard.js";

export async function onRequestPost({ request, env }) {
  if (await allow(env, request, { key: "watch", limit: 5 })) {
    const day = new Date().toISOString().slice(0, 10);
    for (const k of ["count:watch:total", `count:watch:${day}`]) await env.CHECK.put(k, String(Number((await env.CHECK.get(k)) || 0) + 1));
  }
  return json({ ok: true });
}

export const onRequestGet = () => json({ error: "Use POST." }, 405, { allow: "POST" });
