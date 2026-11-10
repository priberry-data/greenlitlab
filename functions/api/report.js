// POST /api/report {url, step}: an owner publishes a dated public report for their own app.
//   step "start"   -> the tag to add to the app's page (proof the app is theirs)
//   step "publish" -> Greenlit checks the live app, finds the tag, and saves the grade, date and finding titles
// Nothing is published for an app whose page doesn't carry the tag.
import { siteScan, explainError } from "../../src/grade.mjs";
import { selfProbe, publicTarget, allow, servedHere, json } from "../../web/guard.js";
import { toReport, claimTag, hasClaim, cleanHost } from "../../web/report.js";

export async function onRequestPost({ request, env }) {
  if (!servedHere(request)) return json({ error: "Use https://greenlit.priberry.com" }, 403);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Send {\"url\": \"myapp.com\", \"step\": \"start\"}." }, 400);
  }
  const t = publicTarget(String(body?.url || "").trim().slice(0, 300));
  if (t.error) return json({ error: t.error }, 400);
  const host = cleanHost(new URL(t.url).host);
  if (!host) return json({ error: "Enter the public address of your app." }, 400);
  if (!(await allow(request, { key: "report", limit: 10 }))) return json({ error: "That's a lot of reports this hour. Try again later." }, 429);

  // One tag per app, made once and kept, so the owner adds it a single time.
  let token = await env.CHECK.get(`claim:${host}`);
  if (!token) {
    token = [...crypto.getRandomValues(new Uint8Array(10))].map((b) => b.toString(16).padStart(2, "0")).join("");
    await env.CHECK.put(`claim:${host}`, token);
  }
  if (body.step !== "publish") return json({ host, tag: claimTag(token) });

  let result;
  try {
    result = await siteScan(`https://${host}/`, { mine: false, maxScripts: 36, maxBytes: 3 * 1024 * 1024, maxTotalBytes: 12 * 1024 * 1024, deadlineMs: 25000, scriptTimeoutMs: 6000, ...selfProbe(request, host), wantPage: true });
  } catch (e) {
    return json({ error: explainError(String(e.message || e)) }, 422);
  }
  if (!hasClaim(result.page, token)) return json({ error: "Greenlit couldn't find the tag on your live page yet. Add it inside <head>, publish the app, wait a minute and try again.", tag: claimTag(token) }, 409);
  for (const f of result.findings) f.why = "";
  const report = toReport(result);
  await env.CHECK.put(`report:${host}`, JSON.stringify(report));
  return json({ host, report: `/r/${host}`, badge: `/badge/${host}.svg`, grade: report.grade, at: report.at });
}

export const onRequestGet = () => json({ error: "Use POST." }, 405, { allow: "POST" });
