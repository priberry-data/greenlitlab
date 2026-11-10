import test from "node:test";
import assert from "node:assert";
import { siteScan, explainError, renderSite } from "../src/grade.mjs";
import { SEVERITY } from "../src/severity.mjs";

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const anon = `${b64({ alg: "HS256" })}.${b64({ iss: "supabase", ref: "abcdefghijklmnopqrst", role: "anon" })}.${"s".repeat(20)}`;
const SB = "https://abcdefghijklmnopqrst.supabase.co";

// A small fake host. `files` maps a path to [status, body, content-type]; anything else gets the home page,
// the way Lovable, Netlify and Vercel answer missing files.
function host({ script = "", files = {}, headers = {}, supabase = {} } = {}) {
  const calls = [];
  const html = '<script type="module" src="/assets/index.js"></script>';
  const res = (url, status, body, type = "text/html", extra = {}) => ({ status, url, headers: new Headers({ "content-type": type, ...extra }), text: async () => body });
  const fetcher = async (url, opts = {}) => {
    calls.push({ url, method: opts.method || "GET", body: opts.body });
    if (url.startsWith(SB)) {
      const path = url.slice(SB.length).split("?")[0];
      if (path in supabase) return res(url, 200, JSON.stringify(supabase[path]), "application/json");
      return res(url, 404, "{}", "application/json");
    }
    const path = new URL(url).pathname;
    if (path === "/") return res(url, 200, html, "text/html", headers);
    if (path === "/assets/index.js") return res(url, 200, script, "application/javascript");
    if (path in files) return res(url, files[path][0], files[path][1], files[path][2] || "text/plain");
    return res(url, 200, html); // the SPA fallback
  };
  return { fetcher, calls };
}

const keyIds = async (script) => (await siteScan("app.example", { fetcher: host({ script }).fetcher })).findings.filter((f) => f.id.startsWith("secret:")).map((f) => f.id);

test("keys: new kinds of leaked keys are found", async () => {
  const ids = await keyIds(
    [
      `a="sb_secret_${"A".repeat(30)}"`,
      `b="sk-or-v1-${"a1".repeat(32)}"`,
      `c="123456789:AA${"b".repeat(33)}"`,
      `d="hf_${"c".repeat(34)}"`,
      `e="-----BEGIN PRIVATE KEY-----\\n${"M".repeat(64)}"`,
      `f={"type": "service_account", "project_id": "x", "private_key": "..."}`,
    ].join(";"),
  );
  for (const id of ["supabase-secret", "openrouter", "telegram", "huggingface", "private-key", "gcp-service-account"]) assert.ok(ids.includes(`secret:${id}`), `finds ${id}: ${ids}`);
});

test("keys: library code that only mentions key formats is not a leak", async () => {
  const ids = await keyIds('const H="-----BEGIN PRIVATE KEY-----";const t=type==="service_account";const pk="pk.eyJabc";const k="key-"+id;');
  assert.deepEqual(ids, []);
});

test("framing: a site that forbids framing isn't flagged; one that doesn't is", async () => {
  const safe = await siteScan("app.example", { fetcher: host({ headers: { "x-frame-options": "DENY" } }).fetcher });
  assert.ok(!safe.findings.some((f) => f.id === "framing"));
  const viaCsp = await siteScan("app.example", { fetcher: host({ headers: { "content-security-policy": "frame-ancestors 'self'" } }).fetcher });
  assert.ok(!viaCsp.findings.some((f) => f.id === "framing"));
  const open = await siteScan("app.example", { fetcher: host().fetcher });
  assert.ok(open.findings.some((f) => f.id === "framing"));
});

test("--mine: a real .env file and .git folder are found; the home page served for those paths is not", async () => {
  const leaky = await siteScan("app.example", { mine: true, fetcher: host({ files: { "/.env": [200, "STRIPE_SECRET_KEY=sk_test_x\nDB_URL=postgres://x"], "/.git/config": [200, "[core]\n\trepositoryformatversion = 0"] } }).fetcher });
  assert.ok(leaky.findings.some((f) => f.id === "exposed:/.env" && f.severity === "critical"));
  assert.ok(leaky.findings.some((f) => f.id === "exposed:git"));
  const spa = await siteScan("app.example", { mine: true, fetcher: host().fetcher });
  assert.ok(!spa.findings.some((f) => f.id.startsWith("exposed:")), "SPA fallback is not a leak");
});

test("--web: unlinked files like .env are never requested without --mine", async () => {
  const { fetcher, calls } = host();
  await siteScan("app.example", { fetcher });
  assert.ok(!calls.some((c) => /\.env|\.git/.test(c.url)));
});

test("--mine: open sign-up without email confirmation is flagged; confirmed sign-up is not", async () => {
  const script = `const u="${SB}",k="${anon}";`;
  const open = await siteScan("app.example", { mine: true, fetcher: host({ script, supabase: { "/auth/v1/settings": { disable_signup: false, mailer_autoconfirm: true } } }).fetcher });
  assert.ok(open.findings.some((f) => f.id === "supabase:open-signup" && f.prompt));
  const closed = await siteScan("app.example", { mine: true, fetcher: host({ script, supabase: { "/auth/v1/settings": { disable_signup: false, mailer_autoconfirm: false } } }).fetcher });
  assert.ok(!closed.findings.some((f) => f.id === "supabase:open-signup"));
});

test("--mine: a storage bucket that lists files to anyone is found, asking for one name only", async () => {
  const script = `const u="${SB}",k="${anon}";`;
  const { fetcher, calls } = host({ script, supabase: { "/storage/v1/object/list/receipts": [{ name: "a.pdf" }] } });
  const r = await siteScan("app.example", { mine: true, fetcher });
  const f = r.findings.find((x) => x.id === "supabase:storage:receipts");
  assert.equal(f?.severity, "critical");
  const listCall = calls.find((c) => c.url.endsWith("/storage/v1/object/list/receipts"));
  assert.equal(JSON.parse(listCall.body).limit, 1);
  assert.ok(!calls.some((c) => /\/storage\/v1\/object\/(public|authenticated|sign)\//.test(c.url)), "never downloads a file");
});

// --- coverage, grades and dead addresses (9 November 2026) ---
const site = (files, { page = '<script type="module" src="/assets/index.js"></script>', headers = {}, status = 200 } = {}) => {
  const calls = [];
  const fetcher = async (url) => {
    calls.push(url);
    const u = new URL(url);
    const r = (s, body, type) => ({ status: s, url, headers: new Headers({ "content-type": type, ...(type === "text/html" ? headers : {}) }), text: async () => body });
    if (u.pathname === "/" && u.hostname === "app.example") return r(status, page, "text/html");
    if (url in files) return r(200, files[url], "application/javascript");
    if (u.pathname in files) return r(200, files[u.pathname], "application/javascript");
    return r(200, page, "text/html"); // the SPA fallback
  };
  return { fetcher, calls };
};
const LEAK = `const k="sk_live_${"a".repeat(24)}";`;

test("coverage: a key on a lazy-loaded page is found through Vite's list of chunks", async () => {
  const { fetcher } = site({
    "/assets/index.js": 'const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["assets/Admin-abc.js","assets/x.css"])))=>i.map(i=>d[i]);',
    "/assets/Admin-abc.js": LEAK,
  });
  const r = await siteScan("app.example", { fetcher });
  assert.ok(r.findings.some((f) => f.id === "secret:stripe"));
});

test("coverage: chains deeper than two levels, and side-effect imports, are followed", async () => {
  const { fetcher } = site({ "/assets/index.js": 'import"./a.js";', "/assets/a.js": 'import("./b.js")', "/assets/b.js": 'export*from"./c.js"', "/assets/c.js": LEAK });
  const r = await siteScan("app.example", { fetcher });
  assert.equal(r.scripts, 4);
  assert.ok(r.findings.some((f) => f.id === "secret:stripe"));
});

test("coverage: scripts on the app's own CDN are read, other companies' scripts aren't", async () => {
  const { fetcher, calls } = site({ "https://static.app.example/main.js": LEAK }, { page: '<script src="https://static.app.example/main.js"></script><script src="https://js.stripe.com/v3/"></script>' });
  const r = await siteScan("app.example", { fetcher });
  assert.ok(r.findings.some((f) => f.id === "secret:stripe"));
  assert.ok(!calls.some((c) => c.includes("stripe.com")));
});

test("coverage: a check that stops early says so, and the verdict doesn't overclaim", async () => {
  const files = { "/assets/index.js": Array.from({ length: 10 }, (_, i) => `import("./c${i}.js");`).join("") };
  for (let i = 0; i < 10; i++) files[`/assets/c${i}.js`] = "1";
  const { fetcher } = site(files, { headers: { "content-security-policy": "frame-ancestors 'none'" } });
  const r = await siteScan("app.example", { fetcher, maxScripts: 4 });
  const note = r.findings.find((f) => f.id === "coverage:partial");
  assert.match(note.title, /7 of this app's scripts weren't read/);
  assert.equal(r.scriptsUnread, 7);
  assert.match(r.verdict, /wasn't read/);
});

test("coverage: when no code could be read there is no grade", async () => {
  const { fetcher } = site({}, { page: '<script src="https://other-assets.net/app.js"></script>', headers: { "content-security-policy": "frame-ancestors 'none'" } });
  const r = await siteScan("app.example", { fetcher });
  assert.equal(r.grade, "?");
  assert.equal(r.score, null);
  assert.match(renderSite(r, null, { color: false }), /Not graded/);
});

test("grades: one critical is an F, one high is C at best", async () => {
  const crit = await siteScan("app.example", { fetcher: site({ "/assets/index.js": LEAK }, { headers: { "content-security-policy": "frame-ancestors 'none'" } }).fetcher });
  assert.equal(crit.grade, "F");
  assert.ok(crit.score <= 39);
  assert.equal(SEVERITY.critical >= 41, true);
  assert.equal(100 - SEVERITY.high < 75, true);
});

test("dead addresses: a builder's not-found page with status 200 isn't graded", async () => {
  const { fetcher } = site({}, { page: "<html><title>Website Not Found - Bolt</title></html>" });
  await assert.rejects(() => siteScan("app.example", { fetcher }), /\(404\)/);
});

test("non-pages: a file or API address gets a clear error", async () => {
  const fetcher = async (url) => ({ status: 200, url, headers: new Headers({ "content-type": "application/pdf" }), text: async () => "%PDF" });
  await assert.rejects(() => siteScan("app.example/a.pdf", { fetcher }), (e) => /isn't a web page/.test(explainError(e.message)));
});

test("errors: each failure gets words someone can act on", () => {
  assert.match(explainError("could not load https://x.example/ (530)"), /Nothing answers/);
  assert.match(explainError("could not load https://x.example/ (429)"), /turned the check away/);
  assert.match(explainError("could not load https://x.example/ (404)"), /not found/);
  assert.match(explainError("could not load https://x.example/ (502)"), /error of its own/);
  assert.match(explainError("could not load https://x.example/ (fetch failed)"), /Couldn't reach/);
});

test("verdict: a good grade with an unchecked database says so, with a prompt for people with no terminal", async () => {
  const script = `const u="${SB}",k="${anon}";`;
  const r = await siteScan("app.example", { fetcher: site({ "/assets/index.js": script }, { headers: { "content-security-policy": "frame-ancestors 'none'" } }).fetcher });
  assert.equal(r.grade, "A");
  assert.match(r.verdict, /database still needs checking/);
  assert.match(r.findings.find((f) => f.id === "db:skipped").checkPrompt, /Row Level Security/);
});

test("coverage: a script that won't load counts as unread, after one retry", async () => {
  const tries = {};
  const fetcher = async (url) => {
    const path = new URL(url).pathname;
    tries[path] = (tries[path] || 0) + 1;
    const r = (s, body, type) => ({ status: s, url, headers: new Headers({ "content-type": type }), text: async () => body });
    if (path === "/") return r(200, '<script src="/a.js"></script><script src="/flaky.js"></script><script src="/down.js"></script>', "text/html");
    if (path === "/down.js") return r(503, "", "text/plain");
    if (path === "/flaky.js") return tries[path] === 1 ? r(502, "", "text/plain") : r(200, LEAK, "application/javascript");
    return r(200, "1", "application/javascript");
  };
  const r = await siteScan("app.example", { fetcher });
  assert.equal(tries["/down.js"], 2);
  assert.ok(r.findings.some((f) => f.id === "secret:stripe"), "the retry found the key");
  assert.equal(r.scriptsUnread, 1);
  assert.ok(r.findings.some((f) => f.id === "coverage:partial"));
});

// --- Phase 0 (10 November 2026): Supabase no longer lists tables for the public key ---
// A project that refuses the table list, the way Supabase answers the public key since 2026.
const modernSupabase = (tables, script, extra = {}) => {
  const calls = [];
  const fetcher = async (url, opts = {}) => {
    calls.push({ url, method: opts.method || "GET" });
    const r = (status, body, type = "application/json", headers = {}) => ({ status, url, headers: new Headers({ "content-type": type, ...headers }), text: async () => body });
    if (url.startsWith(SB)) {
      const path = url.slice(SB.length).split("?")[0];
      if (path === "/rest/v1/") return r(401, '{"message":"Invalid API key","hint":"Only the `service_role` API key can be used for this endpoint."}');
      if (path.startsWith("/rest/v1/")) {
        const t = decodeURIComponent(path.slice(9));
        if (!(t in tables)) return r(404, "");
        return tables[t] === "closed" ? r(401, "") : r(tables[t] ? 206 : 200, "", "application/json", { "content-range": tables[t] ? `0-0/${tables[t]}` : "*/0" });
      }
      if (path in extra) return r(200, JSON.stringify(extra[path]));
      return r(404, "{}");
    }
    const path = new URL(url).pathname;
    if (path === "/assets/index.js") return r(200, script, "application/javascript");
    return r(200, '<script type="module" src="/assets/index.js"></script>', "text/html", new URL(url).pathname === "/" ? { "content-security-policy": "frame-ancestors 'none'" } : {});
  };
  return { fetcher, calls };
};
const client = `const u="${SB}",k="${anon}";`;

test("--mine: table names come from the app's code when Supabase refuses to list them", async () => {
  const script = `${client}db.from("profiles").select();db.from('orders').select();Array.from("ghost");db.storage.from("kyc-docs").list();db.rpc("promote_user");`;
  const { fetcher, calls } = modernSupabase({ profiles: 1234, orders: "closed" }, script, { "/storage/v1/object/list/kyc-docs": [{ name: "passport.pdf" }] });
  const r = await siteScan("app.example", { fetcher, mine: true });
  assert.ok(r.findings.some((f) => f.id === "supabase:table:profiles" && /1,234 rows/.test(f.title)));
  assert.equal(r.supabase.tablesTested, 2, "profiles and orders exist; ghost and kyc-docs answered not found");
  assert.equal(r.supabase.checked, true);
  assert.ok(!r.findings.some((f) => f.id === "db:no-tables"));
  assert.ok(r.findings.some((f) => f.id === "supabase:storage:kyc-docs"), "a bucket named in the code is checked too");
  assert.deepEqual(r.supabase.functions, ["promote_user"]);
  assert.ok(!calls.some((c) => c.url.includes("/rpc/")), "functions are listed, never called");
  assert.ok(calls.filter((c) => c.url.includes("/rest/v1/") && !c.url.endsWith("/rest/v1/")).every((c) => c.method === "HEAD"));
  assert.match(renderSite(r, null, { color: false }), /2 tables tested with the public key, 1 readable by anyone\. Only tables named in your app's code/);
  assert.equal(r.supabase.tablesListed, false);
});

test("--mine: a check that tested no tables says so instead of reporting nothing open", async () => {
  const { fetcher } = modernSupabase({}, client);
  const r = await siteScan("app.example", { fetcher, mine: true });
  assert.equal(r.supabase.checked, false);
  assert.equal(r.supabase.tablesTested, 0);
  assert.ok(r.findings.some((f) => f.id === "db:no-tables" && f.checkPrompt));
  assert.match(r.verdict, /database tables weren't checked/);
  assert.match(renderSite(r, null, { color: false }), /no tables were tested/);
});

test("Supabase address without its key: the database is reported as not checked", async () => {
  const { fetcher } = modernSupabase({}, `const u="${SB}";`);
  const r = await siteScan("app.example", { fetcher });
  assert.ok(r.findings.some((f) => f.id === "db:not-found"));
  assert.match(r.verdict, /weren't checked/);
});

test("grades: small things take 20 points at most, so headers alone never fail an app", async () => {
  const maps = Object.fromEntries(Array.from({ length: 1 }, () => ["/x", ""]));
  const { fetcher } = modernSupabase(Object.fromEntries(Array.from({ length: 12 }, (_, i) => [`list${i}`, 5])), client + Array.from({ length: 12 }, (_, i) => `db.from("list${i}");`).join(""));
  const r = await siteScan("app.example", { fetcher, mine: true });
  assert.equal(r.findings.filter((f) => f.severity === "medium").length, 12);
  assert.equal(r.score, 80);
  assert.equal(r.grade, "B");
  assert.ok(maps);
});

test("fairness: on a lovable.app address, frame protection is shown but costs nothing", async () => {
  const fetcher = async (url) => ({ status: 200, url, headers: new Headers({ "content-type": new URL(url).pathname === "/" ? "text/html" : "application/javascript" }), text: async () => (new URL(url).pathname === "/" ? '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'"><script src="/a.js"></script>' : "1") });
  const hosted = await siteScan("myapp.lovable.app", { fetcher });
  assert.equal(hosted.findings.find((f) => f.id === "framing").severity, "info");
  assert.equal(hosted.score, 100);
  const own = await siteScan("myapp.example", { fetcher });
  assert.equal(own.findings.find((f) => f.id === "framing").severity, "low");
});
