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

import { toReport, reportPage, badgeSvg, hasClaim, claimTag, cleanHost, isFresh } from "../web/report.js";

test("report: only a tagged app can be published, and what is kept has no prompts or reasons", () => {
  const tag = claimTag("abc123");
  assert.ok(hasClaim(`<head>${tag}</head>`, "abc123") && hasClaim('<meta content="abc123" name="greenlit">', "abc123"));
  assert.ok(!hasClaim('<meta name="greenlit" content="other">', "abc123") && !hasClaim("", "abc123"));
  const r = toReport({ url: "https://shop.example", grade: "B", score: 80, verdict: "No open doors, a few loose ends.", builder: null, scripts: 4, findings: [{ id: "csp", severity: "low", title: "No <b>CSP</b>", why: "secret detail", prompt: "long prompt" }] }, "2026-11-10T00:00:00Z");
  assert.deepEqual(Object.keys(r.findings[0]), ["severity", "title"]);
  assert.equal(cleanHost("Shop.Example.svg"), "shop.example");
  assert.equal(cleanHost("../etc/passwd"), null);
  assert.equal(cleanHost("a b.com"), null);
});

test("report: the page and badge show the date, escape everything, and expire after 30 days", () => {
  const r = toReport({ url: "https://shop.example", grade: "A", score: 99, verdict: 'Fine <script>alert(1)</script>', builder: null, scripts: 4, findings: [{ severity: "low", title: "No <b>CSP</b>" }, { severity: "info", title: "Database wasn't checked" }] }, "2026-11-10T00:00:00Z");
  const now = Date.parse("2026-11-20T00:00:00Z");
  const page = reportPage(r, "shop.example", now);
  assert.match(page, /checked 10 Nov 2026/);
  assert.ok(!page.includes("<script>alert") && !page.includes("<b>CSP"), "nothing from a result is put on the page as HTML");
  assert.match(page, /not a security audit or a guarantee/);
  assert.match(page, /What this check could not see/);
  assert.match(badgeSvg(r, now), /A · 10 Nov 2026/);
  const later = Date.parse("2026-12-25T00:00:00Z");
  assert.equal(isFresh(r, later), false);
  assert.match(reportPage(r, "shop.example", later), /out of date/);
  assert.ok(!/class="grade g-A"/.test(reportPage(r, "shop.example", later)), "an old result shows no grade");
  assert.match(badgeSvg(r, later), /out of date/);
  assert.match(badgeSvg(null), /no report/);
  assert.match(reportPage(null, "x.example"), /No report has been published/);
});
