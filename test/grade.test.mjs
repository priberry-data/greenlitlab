import test from "node:test";
import assert from "node:assert";
import { siteScan } from "../src/grade.mjs";

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (payload) => `${b64({ alg: "HS256", typ: "JWT" })}.${b64(payload)}.${"s".repeat(20)}`;
const SB = "https://abcdefghijklmnopqrst.supabase.co";
const anon = jwt({ iss: "supabase", ref: "abcdefghijklmnopqrst", role: "anon" });

// A fake vibe-coded app: a leaked Stripe key, the anon key, one open table and one locked one.
function fakeSite({ serviceRole = false } = {}) {
  const calls = [];
  const res = (status, text = "", headers = {}) => ({ status, url: undefined, headers: new Headers(headers), text: async () => text });
  const fetcher = async (url, opts) => {
    if (url.startsWith("http://")) return { status: 200, url: url.replace("http://", "https://"), headers: new Headers(), text: async () => "" };
    calls.push({ url, method: opts.method, headers: opts.headers });
    if (url === "https://app.example/") return { ...res(200, '<script type="module" src="/assets/index.js"></script>'), url };
    if (url === "https://app.example/assets/index.js")
      return res(200, `const s="${SB}",k="${anon}";const stripe="sk_live_${"a".repeat(24)}";${serviceRole ? `const admin="${jwt({ iss: "supabase", role: "service_role" })}";` : ""}\n//# sourceMappingURL=index.js.map`);
    if (url === "https://app.example/assets/index.js.map") return res(200, JSON.stringify({ version: 3, sources: ["src/App.tsx"], mappings: "AAAA" }));
    if (url === `${SB}/rest/v1/`) return res(200, JSON.stringify({ paths: { "/": {}, "/profiles": {}, "/posts": {}, "/rpc/do_thing": {} } }));
    // Asked whether a column exists: this table has an email column and none of the others.
    if (url.startsWith(`${SB}/rest/v1/profiles?select=`) && !/select=(\*|email)$/.test(url)) return res(400);
    if (url.startsWith(`${SB}/rest/v1/profiles`)) return res(206, "", { "content-range": "0-0/1234" });
    if (url.startsWith(`${SB}/rest/v1/posts`)) return res(200, "", { "content-range": "*/0" });
    return res(404);
  };
  return { fetcher, calls };
}

test("site: leaked keys and source maps are found from what every visitor downloads", async () => {
  const { fetcher, calls } = fakeSite({ serviceRole: true });
  const r = await siteScan("app.example", { fetcher });
  const titles = r.findings.map((f) => f.title);
  assert.ok(titles.some((t) => /live secret key for payments/.test(t)));
  assert.ok(titles.some((t) => /service_role key is in the browser/.test(t)));
  assert.ok(titles.some((t) => /Source maps are public/.test(t)));
  assert.ok(titles.some((t) => /database wasn.t checked/.test(t)), "without --mine the database is not touched");
  assert.ok(!calls.some((c) => c.url.includes("/rest/v1/")));
  assert.equal(r.grade, "F");
});

test("site --mine: counts readable rows with HEAD requests and never asks for rows", async () => {
  const { fetcher, calls } = fakeSite();
  const r = await siteScan("https://app.example", { fetcher, mine: true });
  const open = r.findings.filter((f) => /Anyone on the internet can read/.test(f.title));
  assert.equal(open.length, 1);
  assert.match(open[0].title, /1,234 rows of "profiles", including email/);
  assert.equal(open[0].severity, "critical", "a table of people is critical");
  const tableCalls = calls.filter((c) => /\/rest\/v1\/\w/.test(c.url));
  assert.ok(tableCalls.filter((c) => c.url.endsWith("select=*")).length === 2 && tableCalls.every((c) => c.method === "HEAD"), "rows are counted and columns are asked about with HEAD only");
  assert.deepEqual(r.supabase.readable, [{ table: "profiles", rows: 1234, sensitive: ["email"] }]);
});

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { compare, renderSite, detectBuilder } from "../src/grade.mjs";
import { saveRun, loadLast } from "../src/history.mjs";

test("site: every finding a person can fix has a paste-in prompt, and the key never appears in it", async () => {
  const { fetcher } = fakeSite({ serviceRole: true });
  const r = await siteScan("app.example", { fetcher, mine: true });
  for (const f of r.findings.filter((f) => f.severity !== "info")) {
    assert.ok(f.prompt && f.prompt.length > 80, `${f.id} has a prompt`);
    assert.ok(!f.prompt.includes("sk_live_"), "the leaked key is never repeated in the prompt");
  }
  const stripe = r.findings.find((f) => f.id === "secret:stripe");
  assert.match(stripe.first, /Revoke/);
  assert.match(stripe.prompt, /STRIPE_SECRET_KEY/);
  const table = r.findings.find((f) => f.id === "supabase:table:profiles");
  assert.match(table.prompt, /Row Level Security for "profiles"/);
  assert.match(table.sql, /enable row level security/);
  assert.equal(r.pasteInto, "your AI app builder or coding agent");
});

test("site: knows the app builder from the address, so the prompt says where to paste", () => {
  assert.equal(detectBuilder("myapp.lovable.app"), "Lovable");
  assert.equal(detectBuilder("x.bolt.host"), "Bolt");
  assert.equal(detectBuilder("x.replit.app"), "Replit");
  assert.equal(detectBuilder("x.emergent.host"), "Emergent");
  assert.equal(detectBuilder("example.com", '<meta name="author" content="Lovable" />'), "Lovable");
  assert.equal(detectBuilder("example.com"), null);
});

test("site --mine: an open Firebase database is found by names only, never data", async () => {
  const calls = [];
  const res = (status, text = "") => ({ status, headers: new Headers(), text: async () => text });
  const fetcher = async (url, opts) => {
    if (url.startsWith("http://")) return { status: 200, url: url.replace("http://", "https://"), headers: new Headers(), text: async () => "" };
    calls.push(url);
    if (url === "https://fb.example/") return { ...res(200, '<script src="/main.js"></script>'), url };
    if (url === "https://fb.example/main.js") return res(200, `initializeApp({apiKey:"AIza${"b".repeat(35)}",authDomain:"demo-app.firebaseapp.com",databaseURL:"https://demo-app-default-rtdb.firebaseio.com",projectId:"demo-app"}) // firebase`);
    if (url.startsWith("https://demo-app-default-rtdb.firebaseio.com/.json?shallow=true")) return res(200, '{"users":true,"posts":true}');
    if (url.includes("/documents/users?")) return res(200, JSON.stringify({ documents: [{ name: "projects/demo-app/databases/(default)/documents/users/abc" }] }));
    if (url.includes("/documents/")) return res(403, '{"error":{"status":"PERMISSION_DENIED"}}');
    return res(404);
  };
  const r = await siteScan("fb.example", { fetcher, mine: true });
  const ids = r.findings.map((f) => f.id);
  assert.ok(ids.includes("firebase:rtdb"));
  assert.ok(ids.includes("firebase:firestore:users"));
  assert.ok(!ids.includes("firebase:firestore:posts"), "a collection that refuses is not reported");
  assert.ok(calls.filter((u) => u.includes("firestore")).every((u) => u.includes("pageSize=1") && u.includes("mask.fieldPaths=")));
  assert.equal(r.firebase.project, "demo-app");

  const passive = await siteScan("fb.example", { fetcher });
  assert.ok(passive.findings.some((f) => f.id === "db:skipped" && /Firebase/.test(f.why)));
});

test("site: a re-check shows what got fixed, and history keeps no keys", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "greenlit-"));
  const before = await siteScan("app.example", { fetcher: fakeSite({ serviceRole: true }).fetcher });
  saveRun(before, dir);
  assert.ok(!fs.readFileSync(fs.readdirSync(dir).map((f) => path.join(dir, f))[0], "utf8").includes("sk_live"));
  const after = await siteScan("app.example", { fetcher: fakeSite().fetcher });
  const change = compare(loadLast(after.url, false, dir), after);
  assert.deepEqual(change.fixed, ["Your Supabase service_role key is in the browser code"]);
  assert.equal(change.new.length, 0);
  assert.ok(change.after.score > change.before.score);
  const text = renderSite(after, change, { color: false });
  assert.match(text, /✓ fixed {2}Your Supabase service_role key/);
  assert.match(text, /Then paste this into your AI app builder or coding agent:/);
  assert.equal(loadLast(after.url, true, dir), null, "runs with and without --mine are compared separately");
});

// Hosts like Lovable, Netlify and Vercel answer any missing file with the home page. That must not count.
function spaHost({ script = 'console.log(1)\n//# sourceMappingURL=index.js.map', html = '<script type="module" src="/assets/index.js"></script>' } = {}) {
  const page = (u) => ({ status: 200, url: u, headers: new Headers({ "content-type": "text/html" }), text: async () => html });
  return async (url) => {
    if (url.startsWith("http://")) return { status: 200, url: url.replace("http://", "https://"), headers: new Headers(), text: async () => "" };
    if (url === "https://spa.example/") return page(url);
    if (url === "https://spa.example/assets/index.js") return { status: 200, url, headers: new Headers({ "content-type": "application/javascript" }), text: async () => script };
    return page(url); // the SPA fallback: every other path is the home page, with 200
  };
}

test("site: a host that serves the home page for missing files is not reported as leaking source maps", async () => {
  const r = await siteScan("spa.example", { fetcher: spaHost() });
  assert.ok(!r.findings.some((f) => f.id === "sourcemaps"), "no source-map finding");
  assert.equal(r.scripts, 1, "the fallback page is not counted as a script");
});

test("site: a broken script address in the page doesn't stop the check", async () => {
  const r = await siteScan("spa.example", { fetcher: spaHost({ html: '<script src="http://[broken"></script><script type="module" src="/assets/index.js"></script>' }) });
  assert.equal(r.scripts, 1);
});

test("site: using a database is a note, not a problem, and costs no points", async () => {
  const anonKey = `${Buffer.from('{"alg":"HS256"}').toString("base64url")}.${Buffer.from(JSON.stringify({ iss: "supabase", ref: "abcdefghijklmnopqrst", role: "anon" })).toString("base64url")}.${"s".repeat(20)}`;
  const script = `const u="https://abcdefghijklmnopqrst.supabase.co",k="${anonKey}";`;
  const html = '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'"><script type="module" src="/assets/index.js"></script>';
  const r = await siteScan("spa.example", { fetcher: spaHost({ script, html }) });
  const note = r.findings.find((f) => f.id === "db:skipped");
  assert.equal(note?.severity, "info");
  // Only the missing frame protection costs a point (a meta tag can't set frame-ancestors); the database note costs nothing.
  assert.deepEqual(r.findings.filter((f) => f.severity !== "info").map((f) => f.id), ["framing"]);
  assert.equal(r.score, 99);
  assert.equal(r.grade, "A");
});

test("site: an address that isn't a web address gets a clear error", async () => {
  await assert.rejects(() => siteScan("not a url", { fetcher: spaHost() }), /doesn't look like a web address/);
});

test("site: only the first part of a huge file is read", async () => {
  let pulled = 0;
  const big = new ReadableStream({
    pull(c) {
      pulled++;
      if (pulled > 1000) return c.close();
      c.enqueue(new Uint8Array(64 * 1024).fill(97));
    },
  });
  const fetcher = async (url) => ({ status: 200, url, headers: new Headers({ "content-type": "text/html" }), body: big, text: async () => { throw new Error("must stream"); } });
  const r = await siteScan("huge.example", { fetcher, maxBytes: 256 * 1024 });
  assert.ok(pulled < 20, `read ${pulled} chunks`);
  assert.equal(r.grade, "A");
});
