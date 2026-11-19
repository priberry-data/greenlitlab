import test from "node:test";
import assert from "node:assert";
import { siteScan, dbScan } from "../src/grade.mjs";
import { combine, onRequestPost, safePlan } from "../functions/api/owner.js";

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (payload) => `${b64({ alg: "HS256", typ: "JWT" })}.${b64(payload)}.${"s".repeat(20)}`;
const SB = "https://abcdefghijklmnopqrst.supabase.co";
const anon = jwt({ iss: "supabase", ref: "abcdefghijklmnopqrst", role: "anon" });
const HOST = "shop.example.com";

// An app with something open at every step: tables (one big enough to time out), a sensitive column, a public .env,
// open sign-up, a bucket that lists files, and an open Firebase database.
function fakeApp({ head = "" } = {}) {
  const calls = [];
  const res = (status, text = "", headers = {}) => ({ status, url: undefined, headers: new Headers(headers), text: async () => text });
  const fetcher = async (url, opts = {}) => {
    if (url.startsWith("http://")) return { status: 200, url: url.replace("http://", "https://"), headers: new Headers(), text: async () => "" };
    calls.push(url);
    if (url === `https://${HOST}/`) return { ...res(200, `<html><head>${head.value || ""}</head><body><script type="module" src="/assets/index.js"></script></body></html>`), url };
    if (url === `https://${HOST}/assets/index.js`)
      return res(200, `const s="${SB}",k="${anon}";supabase.from("orders").select();supabase.from("invoices_big").select();storage.from("receipts");initializeApp({apiKey:"AIzaaB3dE6gH9jK2mN5pQ8sT1vW4xY7zC0fRaB3",authDomain:"demo-app.firebaseapp.com",databaseURL:"https://demo-app-default-rtdb.firebaseio.com",projectId:"demo-app"})`);
    if (url === `https://${HOST}/.env.local`) return res(200, "SECRET_THING=abc\n");
    if (url === `${SB}/rest/v1/`) return res(200, JSON.stringify({ paths: { "/profiles": {}, "/posts": {} } }));
    if (url === `${SB}/auth/v1/settings`) return res(200, JSON.stringify({ disable_signup: false, mailer_autoconfirm: true }));
    if (url.startsWith(`${SB}/rest/v1/profiles?select=`) && !/select=(\*|email|password)$/.test(url)) return res(400);
    if (url.startsWith(`${SB}/rest/v1/profiles`)) return res(206, "", { "content-range": "0-0/1234" });
    if (url.startsWith(`${SB}/rest/v1/posts`)) return res(200, "", { "content-range": "*/0" });
    if (url.startsWith(`${SB}/rest/v1/orders?select=`) && !/select=\*$/.test(url)) return res(400);
    if (url.startsWith(`${SB}/rest/v1/orders`)) return res(206, "", { "content-range": "0-0/7" });
    if (url.startsWith(`${SB}/rest/v1/invoices_big`)) return opts.headers?.prefer === "count=planned" ? res(206, "", { "content-range": "0-0/90000" }) : res(500);
    if (url === `${SB}/storage/v1/object/list/receipts`) return res(200, JSON.stringify([{ name: "a.pdf" }]));
    if (url.startsWith("https://demo-app-default-rtdb.firebaseio.com/.json")) return res(200, '{"users":true}');
    if (url.includes("/documents/")) return res(403, "{}");
    return res(404);
  };
  return { fetcher, calls };
}

const view = (r) => ({ grade: r.grade, score: r.score, verdict: r.verdict, findings: r.findings.map((f) => [f.id, f.severity, f.title]), readable: r.supabase?.readable, fb: r.firebase?.readable });

test("owner rounds: checking in small rounds gives exactly the result of one --mine run", async () => {
  const { fetcher } = fakeApp();
  const whole = await siteScan(HOST, { fetcher, mine: true });
  const { plan, flags, ...site } = await siteScan(HOST, { fetcher, wantPlan: true });
  assert.ok(site.findings.some((f) => f.id === "db:skipped"));
  for (const budget of [2, 3, 7]) {
    let d = { done: false, state: null };
    let rounds = 0;
    while (!d.done) {
      // The state goes through JSON between rounds, as it does in the website's cache.
      d = await dbScan(JSON.parse(JSON.stringify(plan)), { fetcher, maxFetches: budget, state: d.state && JSON.parse(JSON.stringify(d.state)) });
      assert.ok(++rounds < 500);
    }
    assert.deepEqual(view(combine(site, flags, d)), view(whole), `budget ${budget}`);
  }
  const ids = whole.findings.map((f) => f.id);
  for (const id of ["supabase:table:profiles", "supabase:table:orders", "supabase:table:invoices_big", "exposed:/.env.local", "supabase:open-signup", "supabase:storage:receipts", "firebase:rtdb"]) assert.ok(ids.includes(id), id);
});

test("owner rounds: a round never makes more fetches than its budget", async () => {
  const { fetcher, calls } = fakeApp();
  const { plan } = await siteScan(HOST, { fetcher, wantPlan: true });
  let d = { done: false, state: null };
  while (!d.done) {
    const before = calls.length;
    d = await dbScan(plan, { fetcher, maxFetches: 5, state: d.state });
    assert.ok(calls.length - before <= 5);
  }
});

// The website flow, with Cloudflare's cache and KV replaced by maps.
function cloudflare(fetcher) {
  const store = new Map();
  globalThis.caches = { default: { match: async (r) => (store.has(r.url) ? new Response(store.get(r.url)) : undefined), put: async (r, res) => store.set(r.url, await res.text()) } };
  globalThis.fetch = fetcher;
  const kv = new Map();
  const env = { OWNER_DB: "on", CHECK: { get: async (k) => kv.get(k) ?? null, put: async (k, v) => kv.set(k, v), delete: async (k) => kv.delete(k) } };
  const call = async (body, ip = "1.1.1.1") => {
    const request = new Request("http://localhost/api/owner", { method: "POST", headers: { "content-type": "application/json", "cf-connecting-ip": ip }, body: JSON.stringify(body) });
    const r = await onRequestPost({ request, env, waitUntil: () => {} });
    return { status: r.status, data: await r.json() };
  };
  return { call };
}

test("owner web flow: tag, verify, rounds, full result; a stranger with the tag but not the key gets nothing", async () => {
  const realFetch = globalThis.fetch;
  try {
    const head = { value: "" };
    const { fetcher } = fakeApp({ head });
    const { call } = cloudflare(fetcher);
    const s = await call({ url: HOST, step: "start" });
    assert.equal(s.status, 200);
    assert.match(s.data.key, /^[0-9a-f]{32}$/);

    const early = await call({ url: HOST, step: "verify", key: s.data.key });
    assert.equal(early.status, 409, "no tag on the page yet");

    head.value = s.data.tag;
    const stranger = await call({ url: HOST, step: "verify", key: "0".repeat(32) }, "2.2.2.2");
    assert.equal(stranger.status, 409, "the tag alone, without its key, proves nothing");

    const v = await call({ url: HOST, step: "verify", key: s.data.key });
    assert.equal(v.status, 200);
    assert.equal(v.data.database, true);
    let n;
    let rounds = 0;
    do n = await call({ step: "next", job: v.data.job });
    while (n.status === 200 && !n.data.done && ++rounds < 40);
    assert.equal(n.status, 200);
    assert.ok(n.data.done);
    const r = n.data.result;
    assert.equal(r.owner, true);
    assert.equal(r.grade, "F");
    assert.ok(!r.findings.some((f) => f.id === "db:skipped"));
    assert.ok(r.findings.some((f) => f.id === "supabase:table:profiles"));
    assert.ok(!("plan" in r) && !("page" in r) && !JSON.stringify(r).includes(anon), "the key and the plan stay on the server");
    assert.ok(r.supabase.checked);

    const bad = await call({ step: "next", job: "f".repeat(32) });
    assert.equal(bad.status, 410);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("owner web: a database address that isn't a standard Supabase or Firebase host is refused", () => {
  const forged = { supabase: { url: "https://victim-site.org/x#.supabase.co", anon: "k" }, firebase: null };
  assert.equal(safePlan(forged), true);
  assert.equal(forged.supabase, null);
  const custom = { supabase: { url: "https://db.myapp.com", anon: "k" }, firebase: null };
  assert.equal(safePlan(custom), true);
  const ok = { supabase: { url: SB, anon }, firebase: { project: "demo-app", db: "https://evil.com/x?.firebaseio.com", key: null } };
  assert.equal(safePlan(ok), false);
  assert.equal(ok.supabase.url, SB);
  assert.equal(ok.firebase.db, null, "a database address that isn't Google's is dropped");
});

test("an editor or private preview link gets told what to paste instead, before anything is fetched", async () => {
  const { siteScan, explainError } = await import("../src/grade.mjs");
  let fetched = 0;
  const fetcher = async () => { fetched++; throw new Error("no network"); };
  for (const [u, word] of [["https://lovable.dev/projects/abc", "Lovable editor"], ["id-preview--1234.lovable.app", "private preview"], ["bolt.new/~/sb1-x", "Bolt editor"], ["https://v0.app/chat/abc", "v0 chat"], ["replit.com/@me/app", "Replit"]]) {
    await assert.rejects(siteScan(u, { fetcher }), (e) => explainError(e.message).includes(word));
  }
  assert.equal(fetched, 0);
});

test("owner web: the database check is off unless OWNER_DB is on", async () => {
  const request = new Request("http://localhost/api/owner", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ url: HOST, step: "start" }) });
  const r = await onRequestPost({ request, env: {}, waitUntil: () => {} });
  assert.equal(r.status, 503);
  const data = await r.json();
  assert.equal(data.off, true);
  assert.match(data.error, /--mine/);
  assert.ok(!data.key && !data.tag, "no tag is handed out while it's off");
});
