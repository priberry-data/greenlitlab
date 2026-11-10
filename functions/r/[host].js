// GET /r/<host>: the dated report an owner published for their app.
import { reportPage, cleanHost } from "../../web/report.js";

export async function onRequestGet({ params, env }) {
  const host = cleanHost(params.host);
  let report = null;
  try {
    report = host ? JSON.parse((await env.CHECK.get(`report:${host}`)) || "null") : null;
  } catch {}
  return new Response(reportPage(report, host || "that address"), { status: report ? 200 : 404, headers: { "content-type": "text/html; charset=utf-8", "cache-control": report ? "public, max-age=300" : "no-store", "content-security-policy": "default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'", "x-content-type-options": "nosniff", "referrer-policy": "strict-origin-when-cross-origin" } });
}
