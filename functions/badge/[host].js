// GET /badge/<host>.svg: the badge for a published report. It shows the date, and goes grey after 30 days.
import { badgeSvg, cleanHost } from "../../web/report.js";
import { allow } from "../../web/guard.js";

export async function onRequestGet({ request, params, env }) {
  // Each view reads the store, which allows about 100,000 reads a day. Views are cached for a while, so a real
  // visitor rarely gets near this; a script asking for thousands of made-up addresses does.
  if (!(await allow(request, { key: "read", limit: 600 }))) return new Response("Too many requests. Try again in an hour.", { status: 429, headers: { "content-type": "text/plain; charset=utf-8", "retry-after": "3600" } });
  const host = cleanHost(params.host);
  let report = null;
  try {
    report = host ? JSON.parse((await env.CHECK.get(`report:${host}`)) || "null") : null;
  } catch {}
  return new Response(badgeSvg(report), { headers: { "content-type": "image/svg+xml; charset=utf-8", "cache-control": report ? "public, max-age=3600" : "public, max-age=300", "access-control-allow-origin": "*", "cross-origin-resource-policy": "cross-origin" } });
}
