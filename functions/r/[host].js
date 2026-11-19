// GET /r/<host>: the dated report an owner published for their app.
import { reportPage, cleanHost } from "../../web/report.js";
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
  return new Response(reportPage(report, host || "that address"), { status: report ? 200 : 404, headers: { "content-type": "text/html; charset=utf-8", "cache-control": report ? "public, max-age=300" : "no-store", "content-security-policy": "default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'", "x-content-type-options": "nosniff", "referrer-policy": "strict-origin-when-cross-origin" } });
}
