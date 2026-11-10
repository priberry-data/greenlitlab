import test from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { codeScan } from "../src/scan.mjs";
import { fromAdvisor } from "../src/advisor.mjs";
import { QUESTIONS, advise } from "../src/questions.mjs";
import { renderList } from "../src/plain.mjs";

const project = (files) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "greenlit-scan-"));
  for (const [name, text] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
    fs.writeFileSync(path.join(dir, name), text);
  }
  return dir;
};

test("scan: the launch mistakes that live in the project's files are found, by name and line", () => {
  const dir = project({
    "package.json": "{}",
    "supabase/migrations/001.sql": 'create table public.profiles (id uuid);\ncreate table orders (id bigint);\nalter table public.orders enable row level security;\ncreate policy "all" on public.orders for all using (true) with check (true);\ncreate policy "read" on products for select to authenticated using (true);\ncreate policy "own" on public.orders for select using (auth.uid() = user_id);\ndrop table old_stuff;\n',
    "supabase/config.toml": "[functions.ai-chat]\nverify_jwt = false\n[functions.ok]\nverify_jwt = true\n",
    "supabase/functions/stripe-webhook/index.ts": 'import Stripe from "stripe";\nexport default async (req) => grant(await req.json());\n',
    ".env": "VITE_SUPABASE_URL=x\nVITE_STRIPE_SECRET_KEY=sk_value_that_must_not_appear\n",
    ".mcp.json": '{"mcpServers":{"supabase":{"command":"npx","args":["@supabase/mcp-server-supabase"]}}}',
    "node_modules/x/bad.sql": 'create policy "p" on t for all using (true);',
  });
  const r = codeScan(dir);
  const ids = r.findings.map((f) => f.id);
  for (const id of ["scan:public-secret:VITE_STRIPE_SECRET_KEY", "scan:verify-jwt:ai-chat", "scan:policy-true:orders:all", "scan:policy-true:products:select", "scan:no-rls:profiles", "scan:agent-db:.mcp.json", "scan:no-lockfile"]) assert.ok(ids.includes(id), id);
  assert.ok(ids.some((id) => id.startsWith("scan:webhook:")) && ids.some((id) => id.startsWith("scan:destructive:")));
  assert.ok(!ids.includes("scan:no-rls:orders") && !ids.includes("scan:verify-jwt:ok") && !ids.includes("scan:policy-true:t:all"), "protected tables, checked functions and dependencies are left alone");
  assert.equal(r.findings.find((f) => f.id === "scan:policy-true:products:select").severity, "medium", "a public read is a question, not an alarm");
  assert.equal(r.findings[0].severity, "critical");
  assert.ok(!JSON.stringify(r).includes("sk_value_that_must_not_appear"), "values in .env files are never read out");
  assert.ok(r.findings.every((f) => f.prompt.length > 80));
  fs.rmSync(dir, { recursive: true });
});

test("scan: a careful project comes back clean, and a missing folder is a clear error", () => {
  const dir = project({ "package.json": "{}", "package-lock.json": "{}", "supabase/migrations/1.sql": "create table notes (id int);\nalter table notes enable row level security;\ncreate policy own on notes for all using (auth.uid() = user_id);\n", "supabase/functions/stripe-webhook/index.ts": 'const e = stripe.webhooks.constructEvent(body, req.headers.get("stripe-signature"), secret);', ".env": "VITE_SUPABASE_URL=x\nSTRIPE_SECRET_KEY=y\n" });
  assert.deepEqual(codeScan(dir).findings, []);
  assert.throws(() => codeScan(path.join(dir, "nope")), /isn't a folder/);
  fs.rmSync(dir, { recursive: true });
});

test("advisor: Supabase's lints become plain findings, worst first, in any wrapping", () => {
  const lints = [
    { name: "unindexed_foreign_keys", title: "Unindexed foreign keys", level: "INFO", categories: ["PERFORMANCE"], detail: "Table \\`public.orders\\` has a foreign key without a covering index.", metadata: { name: "orders" } },
    { name: "rls_policy_always_true", title: "RLS Policy Always True", level: "WARN", categories: ["SECURITY"], detail: "Table \\`public.orders\\` has a policy that allows unrestricted access.", metadata: { name: "orders" } },
    { name: "rls_disabled_in_public", title: "RLS Disabled in Public", level: "ERROR", categories: ["SECURITY"], detail: "Table \\`public.profiles\\` is public, but RLS has not been enabled.", remediation: "https://supabase.com/docs/guides/database/database-linter?lint=0013", metadata: { name: "profiles" } },
    { name: "brand_new_lint", title: "Something New", level: "ERROR", categories: ["SECURITY"], detail: "New thing." },
  ];
  for (const input of [lints, { lints }, { result: { lints } }, JSON.stringify(lints)]) {
    const r = fromAdvisor(input);
    assert.deepEqual(r.findings.map((f) => f.severity), ["critical", "high", "high", "low"]);
    assert.match(r.findings[0].title, /read and change "profiles"/);
    assert.ok(!/[`\\]/.test(r.findings[0].why + r.findings[0].prompt), "SQL escaping is cleaned out");
    assert.match(r.findings.find((f) => f.id.includes("brand_new_lint")).title, /Something New/);
  }
  assert.throws(() => fromAdvisor({ lints: "no" }), /doesn't look like Supabase advisor output/);
  assert.match(renderList("Advisor", fromAdvisor(lints).findings, { color: false }), /1\. CRITICAL/);
});

test("questions: seven, each gap has a fact and a prompt, and answers are only the owner's word", () => {
  assert.equal(QUESTIONS.length, 7);
  for (const q of QUESTIONS) {
    assert.ok(q.options.some((o) => o.ok) && q.options.some((o) => !o.ok), q.id);
    for (const o of q.options.filter((o) => !o.ok)) assert.ok(o.note.length > 40 && o.prompt.length > 60, `${q.id}/${o.key}`);
  }
  const told = advise({ backup: "no", spend: "yes", nonsense: "x" });
  assert.equal(told.find((a) => a.id === "backup").ok, false);
  assert.match(told.find((a) => a.id === "backup").note, /no automatic backups/);
  assert.equal(told.find((a) => a.id === "spend").ok, true);
  assert.equal(told.find((a) => a.id === "plan").ok, null, "an unanswered question is neither");
});

import { toReport, reportPage, badgeSvg, hasClaim, claimTag, claimToken, cleanHost, isFresh } from "../web/report.js";

test("report: only a tagged app can be published, and what is kept has no prompts or reasons", () => {
  const tag = claimTag("abc123");
  assert.ok(hasClaim(`<head>${tag}</head>`, "abc123") && hasClaim('<meta content="abc123" name="greenlit">', "abc123"));
  assert.ok(!hasClaim('<meta name="greenlit" content="other">', "abc123") && !hasClaim("", "abc123"));
  const r = toReport({ url: "https://shop.example", grade: "B", score: 80, verdict: "No open doors, a few loose ends.", builder: null, scripts: 4, findings: [{ id: "csp", severity: "low", title: "No <b>CSP</b>", why: "secret detail", prompt: "long prompt" }] }, "shop.example", "2026-11-10T00:00:00Z");
  assert.deepEqual(Object.keys(r.findings[0]), ["severity", "title"]);
  assert.equal(cleanHost("Shop.Example.svg"), "shop.example");
  assert.equal(cleanHost("../etc/passwd"), null);
  assert.equal(cleanHost("a b.com"), null);
});

test("report: the page and badge show the date, escape everything, and expire after 30 days", () => {
  const r = toReport({ url: "https://shop.example", grade: "A", score: 99, verdict: 'Fine <script>alert(1)</script>', builder: null, scripts: 4, findings: [{ severity: "low", title: "No <b>CSP</b>" }, { severity: "info", title: "Database wasn't checked" }] }, "shop.example", "2026-11-10T00:00:00Z");
  const now = Date.parse("2026-11-20T00:00:00Z");
  const page = reportPage(r, "shop.example", now);
  assert.match(page, /checked 10 Nov 2026/);
  assert.ok(!page.includes("<script>alert") && !page.includes("<b>CSP"), "nothing from a result is put on the page as HTML");
  assert.match(page, /not a security audit or a guarantee/);
  assert.match(page, /what this check could not see/);
  assert.match(page, /Anyone can refresh/);
  assert.match(badgeSvg(r, now), /A · 10 Nov 2026/);
  const later = Date.parse("2026-12-25T00:00:00Z");
  assert.equal(isFresh(r, later), false);
  assert.match(reportPage(r, "shop.example", later), /out of date/);
  assert.ok(!/class="grade g-A"/.test(reportPage(r, "shop.example", later)), "an old result shows no grade");
  assert.match(badgeSvg(r, later), /out of date/);
  assert.match(badgeSvg(null), /no report/);
  assert.match(reportPage(null, "x.example"), /No report has been published/);
});

// --- review fixes (10 November 2026) ---
test("scan: Supabase's own SQL format, comments, private schemas and service-role policies are read correctly", () => {
  const safe = project({ "package.json": "{}", "package-lock.json": "{}", "supabase/migrations/1.sql": [
    'CREATE TABLE IF NOT EXISTS "public"."profiles" ("id" uuid);',
    'CREATE TABLE IF NOT EXISTS "public"."orders" ("id" uuid);',
    'ALTER TABLE "public"."profiles" ENABLE ROW LEVEL SECURITY;',
    'ALTER TABLE "public"."orders" ENABLE ROW LEVEL SECURITY;',
    'CREATE POLICY "own" ON "public"."profiles" USING (("auth"."uid"() = "id"));',
    'create policy "service role full access" on public.orders for all to service_role using (true);',
    "create table private.secrets (id int);",
    "-- create table old_idea (id int);",
    "/* create table also_old (id int); */",
  ].join("\n"), "src/config.ts": "const min = import.meta.env.VITE_PASSWORD_MIN_LENGTH; const on = process.env.NEXT_PUBLIC_ENABLE_PASSWORD_LOGIN; const hook = import.meta.env.VITE_STRIPE_WEBHOOK_URL;" });
  assert.deepEqual(codeScan(safe).findings, []);
  fs.rmSync(safe, { recursive: true });

  const open = project({ "package.json": "{}", "package-lock.json": "{}", "supabase/migrations/1.sql": [
    'CREATE TABLE IF NOT EXISTS "public"."profiles" ("id" uuid);',
    "create table authors (id int);",
    'CREATE TABLE "public"."orders" ("id" uuid);',
    'ALTER TABLE "public"."orders" ENABLE ROW LEVEL SECURITY;',
    'CREATE POLICY "Enable read access on all users" ON "public"."orders" FOR ALL USING (true);',
  ].join("\n"), ".env.example": "VITE_DB_PASSWORD=\nNEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=\n" });
  const ids = codeScan(open).findings.map((f) => f.id).sort();
  assert.deepEqual(ids, ["scan:no-rls:authors", "scan:no-rls:profiles", "scan:policy-true:orders:all", "scan:public-secret:NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY", "scan:public-secret:VITE_DB_PASSWORD"]);
  fs.rmSync(open, { recursive: true });
});

test("advisor: an error message or an empty object is refused, never called clean", () => {
  for (const bad of [{ message: "Unauthorized" }, {}, null, { error: "project not found" }, "not json"]) assert.throws(() => fromAdvisor(bad), /advisor output|isn't JSON/);
  assert.match((() => { try { fromAdvisor({ message: "Unauthorized" }); } catch (e) { return e.message; } })(), /It says: Unauthorized/);
  const nameless = fromAdvisor([{ title: "RLS Disabled in Public", level: "ERROR", metadata: { name: "profiles" } }, 42]);
  assert.equal(nameless.findings.length, 1);
  assert.equal(nameless.findings[0].severity, "critical");
  assert.equal(nameless.skipped, 1);
  const two = fromAdvisor([
    { name: "rls_policy_always_true", level: "WARN", detail: "policy a", metadata: { name: "orders", schema: "public" } },
    { name: "rls_policy_always_true", level: "WARN", detail: "policy b", metadata: { name: "orders", schema: "public" } },
    { name: "rls_policy_always_true", level: "WARN", detail: "policy a", metadata: { name: "orders", schema: "app" } },
  ]);
  assert.equal(two.findings.length, 3, "separate policies and schemas stay separate");
  assert.equal(fromAdvisor([]).findings.length, 0, "a real, empty list is a real clean result");
});

test("report: the owner's tag counts only in the page's head", () => {
  const tag = claimTag("abc123");
  assert.ok(hasClaim(`<html><head><title>x</title>${tag}</head><body></body></html>`, "abc123"));
  for (const fake of [`<head></head><body><p>${tag}</p></body>`, `<head><!-- ${tag} --></head>`, `<head><script>var c={"comment":"<meta name='greenlit' content='abc123'>"}</script></head>`, `<head></head><body><textarea>${tag}</textarea></body>`]) assert.ok(!hasClaim(fake, "abc123"), fake.slice(0, 40));
  assert.equal(cleanHost("xn--e1afmkfd.xn--p1ai"), "xn--e1afmkfd.xn--p1ai");
});

// The report endpoint itself, with a pretend store and a pretend internet.
import { onRequestPost as report } from "../functions/api/report.js";
const fakeKv = () => {
  const data = new Map();
  const writes = [];
  return { data, writes, get: async (k) => data.get(k) ?? null, put: async (k, v, o) => (writes.push(k), data.set(k, v), o), delete: async (k) => (writes.push(`-${k}`), data.delete(k)) };
};
const ask = (env, body, ip = "1.1.1.1") => report({ request: new Request("http://localhost/api/report", { method: "POST", headers: { "content-type": "application/json", "cf-connecting-ip": ip }, body: JSON.stringify(body) }), env }).then(async (r) => ({ status: r.status, body: await r.json() }));

test("report endpoint: nothing is stored for strangers, a tagged app publishes, and removing the tag removes the report", async () => {
  const env = { CHECK: fakeKv() };
  const real = globalThis.fetch;
  let head = "";
  globalThis.fetch = async (url) => {
    const u = new URL(url);
    if (u.hostname === "cloudflare-dns.com") return new Response(JSON.stringify({ Status: 0, Answer: [{ type: 16, data: '"v=DMARC1; p=none"' }] }));
    if (u.protocol === "http:") return Response.redirect(String(url).replace("http://", "https://"), 301);
    return new Response(`<html><head><title>Shop</title>${head}</head><body><a href="/privacy">p</a></body></html>`, { headers: { "content-type": "text/html", "content-security-policy": "frame-ancestors 'none'" } });
  };
  try {
    for (const h of ["a.example-shop.com", "b.example-shop.com", "c.example-shop.com"]) assert.equal((await ask(env, { url: h, step: "start" })).status, 200);
    assert.deepEqual(env.CHECK.writes, ["secret:report-salt"], "handing out tags stores nothing per app");
    const { body: start } = await ask(env, { url: "shop.example-shop.com", step: "start" });
    assert.equal((await ask(env, { url: "shop.example-shop.com", step: "start" }, "2.2.2.2")).body.tag, start.tag, "the same app always gets the same tag");
    assert.notEqual((await ask(env, { url: "other.example-shop.com", step: "start" })).body.tag, start.tag);
    const no = await ask(env, { url: "shop.example-shop.com", step: "publish" });
    assert.equal(no.status, 409);
    assert.ok(!env.CHECK.data.has("report:shop.example-shop.com"));
    head = start.tag;
    const yes = await ask(env, { url: "shop.example-shop.com", step: "publish" });
    assert.equal(yes.status, 200);
    assert.equal(yes.body.report, "/r/shop.example-shop.com");
    const saved = JSON.parse(env.CHECK.data.get("report:shop.example-shop.com"));
    assert.equal(saved.host, "shop.example-shop.com");
    assert.ok(!JSON.stringify(saved).includes("<html>") && saved.findings.every((f) => Object.keys(f).join() === "severity,title"), "no page content, prompts or reasons are kept");
    assert.ok(!("page" in yes.body));
    head = "";
    const gone = await ask(env, { url: "shop.example-shop.com", step: "publish" });
    assert.equal(gone.body.removed, true);
    assert.ok(!env.CHECK.data.has("report:shop.example-shop.com"));
    assert.equal((await ask(env, { url: "127.0.0.1.nip.io", step: "start" })).status, 400);
    env.CHECK.put = async () => { throw new Error("quota"); };
    env.CHECK.data.delete("secret:report-salt");
    assert.equal((await ask(env, { url: "shop.example-shop.com", step: "start" })).status, 503, "a full store is an error message, not a crash");
  } finally {
    globalThis.fetch = real;
  }
});

// --- second review (10 November 2026) ---
import { allowKey } from "../web/guard.js";
import { onRequestPost as check } from "../functions/api/check.js";

// A pretend Cloudflare cache, so the limiters really count under test.
const fakeCaches = () => {
  const store = new Map();
  return { store, default: { match: async (req) => (store.has(req.url) ? new Response(store.get(req.url)) : undefined), put: async (req, res) => void store.set(req.url, await res.text()) } };
};

test("limits: a fixed window, and other people's checks never lock an owner out", async () => {
  globalThis.caches = fakeCaches();
  const realFetch = globalThis.fetch;
  const realNow = Date.now;
  let scans = 0;
  globalThis.fetch = async (url) => {
    const u = new URL(url);
    if (u.hostname === "cloudflare-dns.com") return new Response(JSON.stringify({ Status: 0, Answer: [{ type: 16, data: '"v=DMARC1; p=none"' }] }));
    if (u.protocol === "http:") return Response.redirect(String(url).replace("http://", "https://"), 301);
    scans++;
    return new Response('<html><head><title>Shop</title></head><body><a href="/privacy">p</a></body></html>', { headers: { "content-type": "text/html", "content-security-policy": "frame-ancestors 'none'" } });
  };
  const env = { CHECK: fakeKv() };
  const run = (url, ip) => check({ request: new Request("http://localhost/api/check", { method: "POST", headers: { "content-type": "application/json", "cf-connecting-ip": ip }, body: JSON.stringify({ url }) }), env, waitUntil: () => {} }).then(async (r) => ({ status: r.status, body: await r.json() }));
  try {
    for (let i = 0; i < 4; i++) assert.equal(await allowKey("t", 3, 600), i < 3, `use ${i + 1}`);
    Date.now = () => realNow() + 601e3;
    assert.equal(await allowKey("t", 3, 600), true, "the window ends ten minutes after its first use");
    Date.now = realNow;
    const first = await run("busy-shop.com", "7.7.7.7");
    assert.equal(first.status, 200);
    for (let i = 0; i < 9; i++) assert.equal((await run(`busy-shop.com/p${i}`, "9.9.9.9")).status, 200);
    const before = scans;
    // The two-minute copy has gone; only the ten-minute "last result for this address" is left.
    for (const k of [...globalThis.caches.store.keys()]) if (k.includes(encodeURIComponent("site:"))) globalThis.caches.store.delete(k);
    const owner = await run("busy-shop.com", "7.7.7.7");
    assert.equal(owner.status, 200, "the owner still gets a result");
    assert.equal(owner.body.cached, true);
    assert.ok(owner.body.checkedAt, "with the time it was checked");
    assert.equal(owner.body.url, "https://busy-shop.com", "and it is this address's own result");
    assert.equal(scans, before, "and the site was not fetched again");
    assert.equal((await run("busy-shop.com/never-checked", "7.7.7.7")).status, 429, "another address's result is never shown in its place");
    assert.ok(env.CHECK.writes.filter((w) => w.startsWith("count:fail:limit")).length <= 1, "refusals barely touch the store");
  } finally {
    globalThis.fetch = realFetch;
    Date.now = realNow;
    delete globalThis.caches;
  }
});

test("report: unquoted tags count, a tag quoted inside another tag does not", () => {
  assert.ok(!hasClaim(`<head><link rel="x" title="<meta name=greenlit content=abc123>"></head>`, "abc123"));
  assert.ok(hasClaim("<head><meta name=greenlit content=abc123></head>", "abc123"));
  assert.ok(hasClaim("<head><meta content='abc123' name='greenlit'/></head>", "abc123"));
  assert.ok(!hasClaim(`<head><meta name="description" content="<meta name='greenlit' content='abc123'>"></head>`, "abc123"));
  assert.ok(!hasClaim("<head><meta name=greenlit content=abc1234></head>", "abc123"));
});

test("advisor: a list with nothing usable in it is refused", () => {
  assert.throws(() => fromAdvisor([42, "x"]), /none of those items/);
});

test("scan: text in quotes is not SQL, and a paid service's key behind a public prefix is a leak", () => {
  const dir = project({ "package.json": "{}", "package-lock.json": "{}", "supabase/migrations/1.sql": [
    "create table notes (note text default '-- not a comment'); alter table notes enable row level security;",
    "create function f() returns void as $$ begin execute 'create table tmp_x (id int)'; end $$ language plpgsql;",
    "create unlogged table logs (id int);",
    'create policy "p" on notes for all using ((true));',
    'create policy "q" on private.audit for all using (true);',
    'create policy "r" on storage.objects for select using (true);',
  ].join("\n"), "src/ai.ts": "const k = import.meta.env.VITE_OPENAI_API_KEY; const m = import.meta.env.VITE_GOOGLE_MAPS_API_KEY;" });
  assert.deepEqual(codeScan(dir).findings.map((f) => f.id).sort(), ["scan:no-rls:logs", "scan:policy-true:notes:all", "scan:policy-true:storage.objects:select", "scan:public-secret:VITE_OPENAI_API_KEY"]);
  fs.rmSync(dir, { recursive: true });
  // An apostrophe in a policy's name must not swallow the statements after it.
  const apostrophe = project({ "package.json": "{}", "package-lock.json": "{}", "supabase/migrations/1.sql": `create table a(id int); create policy "Users can't see others" on a for select using (auth.uid() = id); alter table a enable row level security; comment on table a is 'ok'; create policy "It's open" on a for all using (true);` });
  assert.deepEqual(codeScan(apostrophe).findings.map((f) => f.id), ["scan:policy-true:a:all"]);
  fs.rmSync(apostrophe, { recursive: true });
});
