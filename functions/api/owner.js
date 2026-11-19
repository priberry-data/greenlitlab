// POST /api/owner {url, step, job}: the database check, on the web, for an app's owner.
//   step "start"  -> a private key and the tag made from it, to add to the app's page. Adding it is the proof of ownership.
//   step "verify" -> {url, key}: Greenlit checks the live app the usual way. With the tag in its <head>, a job is opened.
//   step "next"   -> one round of database checks for that job. The page calls it until `done`, then shows the result.
// The checks are the ones `npx greenlitlab <app> --mine` runs: row counts and names only, never data. They run in rounds
// because one request here may make only about 50 fetches. What to check comes from the tagged app's own code, goes only
// to Supabase or Firebase hosts, and stays on the server. Like the CLI, it uses only the public key the app ships. Nothing is stored beyond the job, which expires in 15 minutes.
import { siteScan, explainError, dbScan, gradeOf } from "../../src/grade.mjs";
import { selfProbe, allowKey, publicTarget, allow, bump, cacheGet, cachePut, servedHere, json } from "../../web/guard.js";
import { claimTag, claimToken, hasClaim, cleanHost } from "../../web/report.js";
import { WEB_LIMITS } from "./check.js";
import { salt } from "./report.js";

const JOB_SECONDS = 900;
// Fetches per round, with room left for redirects and the job's own reads and writes.
const ROUND_FETCHES = 30;
const MAX_ROUNDS = 40;
const hex = (n) => [...crypto.getRandomValues(new Uint8Array(n))].map((b) => b.toString(16).padStart(2, "0")).join("");
const day = () => new Date().toISOString().slice(0, 10);

// Checks go only to a database host: a standard Supabase project address, and Google's own Firebase hosts. Anything
// else in the code (a custom domain, or a forged key naming another site) is refused, so nobody can aim the checks at a
// third party. Returns whether something had to be dropped.
export function safePlan(plan) {
  let dropped = false;
  if (plan.supabase && !/^https:\/\/[a-z0-9]{20}\.supabase\.co$/.test(plan.supabase.url)) (plan.supabase = null), (dropped = true);
  if (plan.firebase && !/^[a-z0-9-]{4,40}$/.test(plan.firebase.project)) (plan.firebase = null), (dropped = true);
  if (plan.firebase?.db && !/^https:\/\/[a-z0-9-]+(\.[a-z0-9-]+)?\.(firebaseio\.com|firebasedatabase\.app)$/.test(plan.firebase.db)) plan.firebase.db = null;
  if (plan.firebase?.key && !/^[A-Za-z0-9_-]{20,60}$/.test(plan.firebase.key)) plan.firebase.key = null;
  return dropped;
}

// The public result with the database findings added, graded again as an owner's check.
// The database findings go where `--mine` adds them (after the notes about the database), so fixes are numbered the same.
export function combine(site, flags, d) {
  const before = new Set(["db:skipped", "supabase:functions", "db:not-found"]);
  let at = 0;
  site.findings.forEach((f, i) => before.has(f.id) && (at = i + 1));
  const findings = [...site.findings.slice(0, at), ...d.findings, ...site.findings.slice(at)].filter((f) => f.id !== "db:skipped");
  const { score, grade, verdict } = gradeOf(findings, { ...flags, mine: true, tablesUntested: d.stats.tablesUntested, dbBlind: d.stats.dbBlind });
  const s = d.stats;
  return {
    ...site,
    score,
    grade,
    verdict,
    mine: true,
    owner: true,
    findings,
    supabase: site.supabase ? { ...site.supabase, checked: Boolean(s.tables && !s.dbBlind && !s.keyRejected), tablesTested: s.tablesTested, tablesUntested: s.tablesUntested, tablesListed: s.tablesListed, readable: s.tables } : null,
    firebase: site.firebase ? { ...site.firebase, checked: true, readable: s.firebaseOpen } : null,
  };
}

export async function onRequestPost({ request, env, waitUntil }) {
  if (!servedHere(request)) return json({ error: "Use https://greenlit.priberry.com" }, 403);
  // Off unless OWNER_DB is "on". The tag proves who controls the page, but the database to check is read from that same
  // page, so anyone could copy another app's public Supabase or Firebase details onto a page they control and have
  // Greenlit check that database. It stays off until the owner can prove control of the database itself.
  if (env.OWNER_DB !== "on") return json({ error: `The database check runs on your own computer for now: npx greenlitlab <your app> --mine`, off: true }, 503);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'Send {"url": "myapp.com", "step": "start"}.' }, 400);
  }

  if (body?.step === "next") {
    const id = String(body.job || "");
    if (!/^[0-9a-f]{32}$/.test(id)) return json({ error: "Start the check again." }, 400);
    if (!(await allow(request, { key: "owner-next", limit: 400 }))) return json({ error: "That's a lot of database checks this hour. Try again later." }, 429);
    const job = await cacheGet(`owner:job:${id}`);
    if (!job) return json({ error: "This check was lost or expired. Press the button again to restart it." }, 410);
    if (job.final) return json({ done: true, result: job.final });
    // One round at a time per job: parallel calls would each run the same round.
    if (job.busy && Date.now() - job.busy < 30000) return json({ error: "This check is already running. Wait a moment." }, 429);
    job.busy = Date.now();
    await cachePut(`owner:job:${id}`, job, JOB_SECONDS);
    if (++job.rounds > MAX_ROUNDS) return json({ error: "The database check took too long. Try again later, or run it on your own computer: npx greenlitlab " + job.host + " --mine" }, 422);
    let d;
    try {
      d = await dbScan(job.plan, { maxBytes: WEB_LIMITS.maxBytes, maxFetches: ROUND_FETCHES, state: job.state });
    } catch {
      job.busy = 0;
      await cachePut(`owner:job:${id}`, job, JOB_SECONDS);
      return json({ error: "The database check failed. Try again." }, 503);
    }
    job.state = d.state;
    job.busy = 0;
    if (d.done) {
      job.final = { ...combine(job.site, job.flags, d), checkedAt: new Date().toISOString() };
      job.state = null;
    }
    await cachePut(`owner:job:${id}`, job, JOB_SECONDS);
    return d.done ? json({ done: true, result: job.final }) : json({ done: false, step: d.state.step, of: 6 });
  }

  const t = publicTarget(String(body?.url || "").trim().slice(0, 300));
  if (t.error) return json({ error: t.error }, 400);
  const host = cleanHost(new URL(t.url).host);
  if (!host) return json({ error: "Enter the public address of your app." }, 400);
  if (!(await allow(request, { key: "owner", limit: 12 }))) return json({ error: "That's a lot of database checks this hour. Try again later." }, 429);

  try {
    // The tag is made from a key only this owner's browser holds. Anyone can read the tag on the page, but without the
    // key they can't run the check, so leaving the tag up shows nobody else what's open. It doesn't turn on public reports.
    if (body.step !== "verify") {
      const key = hex(16);
      return json({ host, key, tag: claimTag(await claimToken(await salt(env), `${host}|owner|${key}`)) });
    }
    const key = String(body.key || "");
    if (!/^[0-9a-f]{32}$/.test(key)) return json({ error: "Start again to get your tag." }, 400);
    const token = await claimToken(await salt(env), `${host}|owner|${key}`);

    if (!(await allowKey(`owner:${host}`, 4, 600))) return json({ error: "That app's database has been checked several times in the last few minutes. Try again shortly." }, 429);
    let result;
    try {
      result = await siteScan(`https://${host}/`, { mine: false, ...WEB_LIMITS, wantPage: true, wantPlan: true, ...selfProbe(request, host) });
    } catch (e) {
      return json({ error: explainError(String(e.message || e)) }, 422);
    }
    if (!hasClaim(result.page, token)) return json({ error: "Greenlit couldn't find the tag in the <head> of your live page yet. Add it, publish the app, wait a minute and try again.", tag: claimTag(token) }, 409);
    const { page, plan, flags, ...site } = result;
    if (safePlan(plan)) return json({ error: `On the website Greenlit checks only databases at a standard Supabase (…supabase.co) or Firebase address, and this app's code points somewhere else. Run it on your own computer instead: npx greenlitlab ${host} --mine` }, 422);
    // The same database can sit behind many addresses, so it gets its own limit.
    const db = plan.supabase?.url || plan.firebase?.project;
    if (db && !(await allowKey(`owner:db:${db}`, 4, 600))) return json({ error: "That database has been checked several times in the last few minutes. Try again shortly." }, 429);
    const id = hex(16);
    await cachePut(`owner:job:${id}`, { host, plan, flags, site, state: null, rounds: 0, busy: 0, final: null }, JOB_SECONDS);
    waitUntil(bump(env, [`count:owner:${day()}`], 1));
    return json({ host, job: id, database: Boolean(plan.supabase || plan.firebase) });
  } catch {
    return json({ error: "The database check can't run right now. Try again later." }, 503);
  }
}

export const onRequestGet = () => json({ error: "Use POST." }, 405, { allow: "POST" });
