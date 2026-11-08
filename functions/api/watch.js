// POST /api/watch: someone clicked "Watch my app". We count the click (the price test for the paid monitor)
// and keep nothing about who clicked or which site.
import { allow, bump, servedHere, json } from "../../web/guard.js";

export async function onRequestPost({ request, env, waitUntil }) {
  if (!servedHere(request)) return json({ error: "Use https://greenlit.priberry.com" }, 403);
  if (await allow(request, { key: "watch", limit: 5 })) waitUntil(bump(env, ["count:watch:total", `count:watch:${new Date().toISOString().slice(0, 10)}`]));
  return json({ ok: true });
}

export const onRequestGet = () => json({ error: "Use POST." }, 405, { allow: "POST" });
