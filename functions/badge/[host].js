// GET /badge/<host>.svg: the badge for a published report. It shows the date, and goes grey after 30 days.
import { badgeSvg, cleanHost } from "../../web/report.js";

export async function onRequestGet({ params, env }) {
  const host = cleanHost(params.host);
  let report = null;
  try {
    report = host ? JSON.parse((await env.CHECK.get(`report:${host}`)) || "null") : null;
  } catch {}
  return new Response(badgeSvg(report), { headers: { "content-type": "image/svg+xml; charset=utf-8", "cache-control": report ? "public, max-age=3600" : "public, max-age=300", "access-control-allow-origin": "*", "cross-origin-resource-policy": "cross-origin" } });
}
