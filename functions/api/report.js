// POST /api/report {url, step}: public, dated reports for apps whose owner has turned them on.
//   step "start"   -> the tag to add to the app's page. Adding it is the owner's proof and consent.
//   step "publish" -> Greenlit checks the live app. With the tag in its <head>, the grade, date and finding
//                     titles are saved. Without it, nothing is published, and an existing report is removed.
// Nothing is stored until a tagged page has been seen, and a report is kept for 90 days at most.
import { siteScan, explainError } from "../../src/grade.mjs";
import { selfProbe, allowKey, publicTarget, allow, servedHere, json } from "../../web/guard.js";
import { toReport, claimTag, claimToken, hasClaim, cleanHost } from "../../web/report.js";
import { WEB_LIMITS } from "./check.js";

const KEEP_SECONDS = 90 * 86400;

// One secret for all tags, made once.
async function salt(env) {
  let s = await env.CHECK.get("secret:report-salt");
  if (!s) {
    s = [...crypto.getRandomValues(new Uint8Array(24))].map((b) => b.toString(16).padStart(2, "0")).join("");
    await env.CHECK.put("secret:report-salt", s);
  }
  return s;
}

export async function onRequestPost({ request, env }) {
  if (!servedHere(request)) return json({ error: "Use https://greenlit.priberry.com" }, 403);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'Send {"url": "myapp.com", "step": "start"}.' }, 400);
  }
  const t = publicTarget(String(body?.url || "").trim().slice(0, 300));
  if (t.error) return json({ error: t.error }, 400);
  const host = cleanHost(new URL(t.url).host);
  if (!host) return json({ error: "Enter the public address of your app." }, 400);
  if (!(await allow(request, { key: "report", limit: 10 }))) return json({ error: "That's a lot of reports this hour. Try again later." }, 429);

  try {
    const token = await claimToken(await salt(env), host);
    if (body.step !== "publish") return json({ host, tag: claimTag(token) });

    if (!(await allowKey(`publish:${host}`, 6, 600))) return json({ error: "That site has been checked several times in the last few minutes. Try again shortly." }, 429);
    let result;
    try {
      result = await siteScan(`https://${host}/`, { mine: false, ...WEB_LIMITS, wantPage: true, ...selfProbe(request, host) });
    } catch (e) {
      return json({ error: explainError(String(e.message || e)) }, 422);
    }
    if (!hasClaim(result.page, token)) {
      // The owner took the tag off: the report comes down.
      if (await env.CHECK.get(`report:${host}`)) {
        await env.CHECK.delete(`report:${host}`);
        return json({ host, removed: true, message: "The tag is no longer on the page, so the public report was removed." });
      }
      return json({ error: "Greenlit couldn't find the tag in the <head> of your live page yet. Add it, publish the app, wait a minute and try again.", tag: claimTag(token) }, 409);
    }
    const report = toReport(result, host);
    // A refresh that changes nothing on the same day isn't written again.
    let old = null;
    try {
      old = JSON.parse((await env.CHECK.get(`report:${host}`)) || "null");
    } catch {}
    const same = old && old.at?.slice(0, 10) === report.at.slice(0, 10) && old.grade === report.grade && old.score === report.score && JSON.stringify(old.findings) === JSON.stringify(report.findings);
    if (same) return json({ host, report: `/r/${host}`, badge: `/badge/${host}.svg`, grade: old.grade, at: old.at });
    await env.CHECK.put(`report:${host}`, JSON.stringify(report), { expirationTtl: KEEP_SECONDS });
    return json({ host, report: `/r/${host}`, badge: `/badge/${host}.svg`, grade: report.grade, at: report.at });
  } catch {
    return json({ error: "Reports can't be saved right now. Try again later." }, 503);
  }
}

export const onRequestGet = () => json({ error: "Use POST." }, 405, { allow: "POST" });
