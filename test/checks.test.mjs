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
    if (url.startsWith("http://")) return { status: 200, url: url.replace("http://", "https://"), headers: new Headers(), text: async () => "" };
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
      `a="sb_\u0073ecret_aB3dE6gH9jK2mN5pQ8sT1vW4xY7zC0"`,
      `b="sk-\u006fr-v1-a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"`,
      `c="8213746590\u003aAAaB3dE6gH9jK2mN5pQ8sT1vW4xY7zC0fRa"`,
      `d="h\u0066_aB3dE6gH9jK2mN5pQ8sT1vW4xY7zC0fRaB"`,
      `e="-----BEGIN PRIV\u0041TE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj"`,
      `f={"type": "service_account", "project_id": "x", "private_key": "..."}`,
    ].join(";"),
  );
  for (const id of ["supabase-secret", "openrouter", "telegram", "huggingface", "private-key", "gcp-service-account"]) assert.ok(ids.includes(`secret:${id}`), `finds ${id}: ${ids}`);
});

test("keys: library code that only mentions key formats is not a leak", async () => {
  const ids = await keyIds('const H="-----BEGIN PRIV\u0041TE KEY-----";const t=type==="service_account";const pk="pk.eyJabc";const k="key-"+id;');
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
    if (url.startsWith("http://")) return { status: 200, url: url.replace("http://", "https://"), headers: new Headers(), text: async () => "" };
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
const LEAK = `const k="sk_\u006cive_aB3dE6gH9jK2mN5pQ8sT1vW4";`;

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
    if (url.startsWith("http://")) return { status: 200, url: url.replace("http://", "https://"), headers: new Headers(), text: async () => "" };
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
    if (url.startsWith("http://")) return { status: 200, url: url.replace("http://", "https://"), headers: new Headers(), text: async () => "" };
    calls.push({ url, method: opts.method || "GET" });
    const r = (status, body, type = "application/json", headers = {}) => ({ status, url, headers: new Headers({ "content-type": type, ...headers }), text: async () => body });
    if (url.startsWith(SB)) {
      const path = url.slice(SB.length).split("?")[0];
      if (path === "/rest/v1/") return r(401, '{"message":"Invalid API key","hint":"Only the `service_role` API key can be used for this endpoint."}');
      if (path.startsWith("/rest/v1/")) {
        const t = decodeURIComponent(path.slice(9));
        if (!(t in tables)) return r(404, "");
        const col = new URL(url).searchParams.get("select");
        if (col !== "*" && !(extra.columns || []).includes(col)) return r(400, "");
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
  const { fetcher } = modernSupabase(Object.fromEntries(Array.from({ length: 12 }, (_, i) => [`list${i}`, 5])), client + Array.from({ length: 12 }, (_, i) => `db.from("list${i}");`).join(""));
  const r = await siteScan("app.example", { fetcher, mine: true });
  assert.equal(r.findings.filter((f) => f.severity === "medium").length, 12);
  assert.equal(r.score, 80);
  assert.equal(r.grade, "B");
});

test("fairness: on a lovable.app address, frame protection is shown but costs nothing", async () => {
  const fetcher = async (url) => ({ status: 200, url: url.replace("http://", "https://"), headers: new Headers({ "content-type": new URL(url).pathname === "/" ? "text/html" : "application/javascript" }), text: async () => (new URL(url).pathname === "/" ? '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'"><a href="/privacy">Privacy</a><script src="/a.js"></script>' : "1") });
  const hosted = await siteScan("myapp.lovable.app", { fetcher });
  assert.ok(!hosted.findings.some((f) => f.id === "framing"), "not a finding the owner could act on");
  assert.match(hosted.findings.find((f) => f.id === "domain:builder").why, /only the host can change that/);
  assert.equal(hosted.score, 100);
  const own = await siteScan("myapp.example", { fetcher });
  assert.equal(own.findings.find((f) => f.id === "framing").severity, "low");
});

// --- Phases 1 to 3 (10 November 2026): launch basics, email records, deeper owner check ---
// One page and one script, with switches for what the host and the DNS answer.
const launchSite = ({ page = "", script = "1", pageHeaders = {}, cookies = [], dns = {}, httpStays = false, cors = false } = {}) => {
  const calls = [];
  const fetcher = async (url, opts = {}) => {
    calls.push(url);
    const u = new URL(url);
    const r = (status, body, headers = {}, finalUrl = url) => ({ status, url: finalUrl, headers: new Headers(headers), text: async () => body });
    if (u.hostname === "cloudflare-dns.com") {
      const name = u.searchParams.get("name");
      if (!(name in dns)) return r(200, JSON.stringify({ Status: 3 }));
      return r(200, JSON.stringify({ Status: 0, Answer: dns[name].map((data) => ({ type: 16, data: `"${data}"` })) }));
    }
    if (u.protocol === "http:") return r(200, "", {}, httpStays ? url : url.replace("http://", "https://"));
    if (u.pathname === "/") {
      const h = new Headers({ "content-type": "text/html", "content-security-policy": "frame-ancestors 'none'", ...pageHeaders });
      for (const c of cookies) h.append("set-cookie", c);
      if (cors && opts.headers?.origin) (h.set("access-control-allow-origin", opts.headers.origin), h.set("access-control-allow-credentials", "true"));
      return { status: 200, url, headers: h, text: async () => `<title>Shop</title><a href="/privacy">Privacy</a>${page}<script src="/a.js"></script>` };
    }
    return r(200, script, { "content-type": "application/javascript" });
  };
  return { fetcher, calls };
};
const ids = (r) => r.findings.map((f) => f.id);
const GOOD_DNS = { "_dmarc.shop.example": ["v=DMARC1; p=none"], "shop.example": ["v=spf1 include:_spf.resend.com ~all"] };

test("launch: a clean app on its own domain with good email records gets nothing new", async () => {
  const r = await siteScan("shop.example", { fetcher: launchSite({ dns: GOOD_DNS }).fetcher });
  assert.deepEqual(ids(r), []);
  assert.equal(r.score, 100);
});

test("launch: leftovers that stop a live app working are found in what was already downloaded", async () => {
  const script = `fetch("http://localhost:3000/api/items");const pk="pk_\u0074est_aB3dE6gH9jK2mN5pQ8sT1vW4";fetch("https://api.openai.com/v1/chat/completions");send({from:"onboarding@resend.dev"});`;
  const r = await siteScan("shop.example", { fetcher: launchSite({ script, dns: GOOD_DNS, page: '<meta name="robots" content="noindex"><script src="http://cdn.other.example/x.js"></script>' }).fetcher });
  for (const id of ["launch:localhost", "launch:test-payments", "launch:ai-direct", "launch:test-sender", "launch:noindex", "launch:mixed"]) assert.ok(ids(r).includes(id), id);
  assert.equal(r.findings.find((f) => f.id === "launch:localhost").severity, "low", "a mention in code is only worth checking");
  assert.ok(r.findings.every((f) => f.severity === "info" || f.prompt), "each has a fix prompt");
  assert.ok(r.score >= 80, "small things can't fail an app");
});

test("launch: a bare localhost address in an allow-list is not a leftover; a fallback is", async () => {
  const allow = await siteScan("shop.example", { fetcher: launchSite({ dns: GOOD_DNS, script: 'const ok=["https://lovable.dev","http://localhost:3000"];const auth="http://localhost:9999";' }).fetcher });
  assert.deepEqual(ids(allow), []);
  const fallback = await siteScan("shop.example", { fetcher: launchSite({ dns: GOOD_DNS, script: 'const api=import.meta.env.VITE_API||"http://localhost:5000";' }).fetcher });
  assert.deepEqual(ids(fallback), ["launch:localhost"]);
});

test("launch: a page that loads from localhost is a real break; a default title is flagged", async () => {
  const fetcher = async (url) => ({ status: 200, url: url.replace("http://", "https://"), headers: new Headers({ "content-type": new URL(url).pathname === "/" ? "text/html" : "application/javascript" }), text: async () => (new URL(url).pathname === "/" ? '<title>Lovable App</title><script src="http://localhost:5173/src/main.tsx"></script><script src="/a.js"></script>' : "privacy") });
  const r = await siteScan("shop.example", { fetcher });
  assert.equal(r.findings.find((f) => f.id === "launch:localhost").severity, "high");
  assert.ok(ids(r).includes("launch:default-title"));
});

test("launch: new secret shapes, an unlocked session cookie, no https redirect and open CORS", async () => {
  const script = `const db="postgresql://app:${"s3cretPass"}@db.abcdefgh.supabase.co:5432/postgres";const w="whse\u0063_aB3dE6gH9jK2mN5pQ8sT1vW4xY7zC0fR";`;
  const r = await siteScan("shop.example", { fetcher: launchSite({ script, dns: GOOD_DNS, cookies: ["__cf_bm=x; path=/", "session_id=abc; Path=/"], httpStays: true, cors: true }).fetcher });
  for (const id of ["secret:database-url", "secret:stripe-webhook", "launch:cookie:session_id", "launch:no-https-redirect", "launch:cors"]) assert.ok(ids(r).includes(id), id);
  assert.ok(!ids(r).some((id) => id.includes("__cf_bm")), "the host's own cookies are ignored");
  assert.equal(r.grade, "F");
});

test("email: a custom domain with no DMARC or a broken SPF record is flagged; a failed lookup is not", async () => {
  const none = await siteScan("app.shop.example", { fetcher: launchSite({ dns: { "shop.example": ["v=spf1 +all"] } }).fetcher });
  assert.ok(ids(none).includes("email:no-dmarc") && ids(none).includes("email:spf-broken"));
  assert.match(none.findings.find((f) => f.id === "email:no-dmarc").first, /_dmarc\.shop\.example/);
  const down = launchSite({});
  const failing = async (url, opts) => (new URL(url).hostname === "cloudflare-dns.com" ? { status: 503, url, headers: new Headers(), text: async () => "busy" } : down.fetcher(url, opts));
  const unknown = await siteScan("shop.example", { fetcher: failing });
  assert.deepEqual(ids(unknown), ["launch:unchecked"], "a lookup that failed is said, and is not a finding");
  assert.match(unknown.findings[0].why, /email records for shop\.example/);
  assert.equal(unknown.score, 100);
});

test("email: on a builder's address the domain checks are skipped and said so", async () => {
  const { fetcher, calls } = launchSite({});
  const r = await siteScan("shop.vercel.app", { fetcher });
  assert.ok(ids(r).includes("domain:builder"));
  assert.ok(!calls.some((c) => c.includes("cloudflare-dns.com")));
  assert.equal(r.score, 100);
});

test("--mine: an email column makes a readable table serious, a secret column critical, and functions are never called", async () => {
  const script = `${client}db.from("items").select();db.functions.invoke("send-invoice");fetch(u+"/functions/v1/ai-chat");db.rpc("promote_user");`;
  const { fetcher, calls } = modernSupabase({ items: 40 }, script, { columns: ["email", "phone"] });
  const r = await siteScan("app.example", { fetcher, mine: true });
  const t = r.findings.find((f) => f.id === "supabase:table:items");
  assert.equal(t.severity, "high", "emails in a table that may be a public directory: serious, not an automatic F");
  assert.match(t.title, /including email, phone/);
  const secret = await siteScan("app.example", { fetcher: modernSupabase({ items: 40 }, script, { columns: ["api_key"] }).fetcher, mine: true });
  assert.equal(secret.findings.find((f) => f.id === "supabase:table:items").severity, "critical");
  const plain = await siteScan("app.example", { fetcher: modernSupabase({ stores: 40, leaderboard: 9, border_styles: 3, subscription_plans: 4 }, `${client}db.from("stores");db.from("leaderboard");db.from("border_styles");db.from("subscription_plans");`, { columns: ["phone", "address"] }).fetcher, mine: true });
  assert.ok(plain.findings.filter((f) => f.id.startsWith("supabase:table:")).every((f) => f.severity === "medium"), "public-looking tables are a question, not an F");
  assert.equal(plain.grade, "B");
  const fn = r.findings.find((f) => f.id === "supabase:functions");
  assert.match(fn.why, /send-invoice, ai-chat, promote_user/);
  assert.match(fn.checkPrompt, /send-invoice/);
  assert.ok(!calls.some((c) => c.url.includes("/functions/v1/") || c.url.includes("/rpc/")));
  assert.ok(calls.filter((c) => c.url.startsWith(SB + "/rest/v1/items")).every((c) => c.method === "HEAD"));
});

// --- review fixes (10 November 2026) ---
import { looksReal } from "../src/grade.mjs";

test("keys: example values in library text and docs are never reported as leaks", async () => {
  const docs = [
    'help="postgresql://postgres:[YOUR-PASSWORD]@db.abcdefghijklmnopqrst.supabase.co:5432/postgres"',
    'm="mongodb+srv://<username>:<password>@cluster0.mongodb.net/"',
    'e="postgres://user:password@db.example.com:5432/mydb"',
    "t=`postgresql://${user}:${password}@aws-0-us-east-1.pooler.supabase.com:6543/postgres`",
    'w="whse\u0063_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"',
    'k="sk_\u006cive_aaaaaaaaaaaaaaaaaaaaaaaa"',
  ].join(";");
  const r = await siteScan("shop.example", { fetcher: launchSite({ script: docs, dns: GOOD_DNS }).fetcher });
  assert.deepEqual(ids(r), []);
  assert.equal(r.grade, "A");
  // A real one after an example in the same file is still found.
  const mixed = await siteScan("shop.example", { fetcher: launchSite({ script: `${docs};real="postgresql://app:Zx81kqPw93LmNs2@db.prodhost.io:5432/app"`, dns: GOOD_DNS }).fetcher });
  assert.deepEqual(ids(mixed), ["secret:database-url"]);
  assert.equal(looksReal("whse\u0063_aB3dE6gH9jK2mN5pQ8sT1vW4xY7zC0fR"), true);
});

test("launch: plain links load nothing, CSRF cookies are left alone, and an http-only app is said to be http", async () => {
  const page = '<a href="http://localhost:3000">run it locally</a><link rel="canonical" href="http://shop.example/"><link rel="profile" href="http://gmpg.org/xfn/11"><a href="http://localhost.example.com/">x</a>';
  const r = await siteScan("shop.example", { fetcher: launchSite({ page, dns: GOOD_DNS, cookies: ["XSRF-TOKEN=abc; Secure; SameSite=Lax", "csrftoken=abc; Secure", "consid=1; Secure"] }).fetcher });
  assert.deepEqual(ids(r), []);
  const loads = await siteScan("shop.example", { fetcher: launchSite({ page: '<link rel="stylesheet" href="http://cdn.other.example/a.css">', dns: GOOD_DNS }).fetcher });
  assert.deepEqual(ids(loads), ["launch:mixed"]);
  const httpOnly = async (url) => ({ status: 200, url, headers: new Headers({ "content-type": new URL(url).pathname === "/" ? "text/html" : "application/javascript", "content-security-policy": "frame-ancestors 'none'" }), text: async () => (new URL(url).pathname === "/" ? '<a href="/privacy">p</a><script src="/a.js"></script>' : "1") });
  // Typed as http, and https answers too: the gap is the missing redirect, the same finding as typing the bare name.
  const both = await siteScan("http://shop.vercel.app", { fetcher: httpOnly });
  assert.ok(ids(both).includes("launch:no-https-redirect") && !ids(both).includes("launch:no-https"));
  // No https at all.
  const noHttps = async (url, o) => (url.startsWith("https://shop.vercel.app") ? { status: 0, url, headers: new Headers(), text: async () => "" } : httpOnly(url, o));
  const off = async (url) => { if (url.startsWith("https://shop.vercel.app")) throw new Error("connect refused"); return httpOnly(url); };
  const plain = await siteScan("http://shop.vercel.app", { fetcher: off });
  assert.ok(ids(plain).includes("launch:unchecked") || ids(plain).includes("launch:no-https"));
  const refused = async (url) => (url.startsWith("https://shop.vercel.app") ? { status: 526, url, headers: new Headers(), text: async () => "" } : httpOnly(url));
  assert.equal((await siteScan("http://shop.vercel.app", { fetcher: refused })).findings.find((f) => f.id === "launch:no-https").severity, "high");
  assert.ok(noHttps);
});

test("domains: the owner's domain is found on country domains, and shared hosts are nobody's to fix", async () => {
  const seen = [];
  const fetcher = (host) => async (url, opts) => {
    const u = new URL(url);
    if (u.hostname === "cloudflare-dns.com") seen.push(u.searchParams.get("name"));
    return launchSite({}).fetcher(url, opts);
  };
  for (const host of ["shop.ne.jp", "app.shop.or.jp", "shop.me.uk", "www.shop.com.au"]) await siteScan(host, { fetcher: fetcher(host) });
  assert.deepEqual([...new Set(seen)].sort(), ["_dmarc.shop.com.au", "_dmarc.shop.me.uk", "_dmarc.shop.ne.jp", "_dmarc.shop.or.jp", "shop.com.au", "shop.me.uk", "shop.ne.jp", "shop.or.jp"]);
  seen.length = 0;
  for (const host of ["myapp.herokuapp.com", "myapp.azurewebsites.net", "myapp.v0.app"]) assert.ok(ids(await siteScan(host, { fetcher: fetcher(host) })).includes("domain:builder"));
  assert.deepEqual(seen, [], "no DNS lookups for a host the owner doesn't control");
});

test("coverage: another tenant's script on a shared host, or an odd port, is not the app's own", async () => {
  const calls = [];
  const fetcher = async (url) => {
    calls.push(url);
    const u = new URL(url);
    return { status: 200, url: url.replace("http://", "https://"), headers: new Headers({ "content-type": u.pathname === "/" ? "text/html" : "application/javascript" }), text: async () => (u.pathname === "/" ? '<a href="/privacy">p</a><script src="https://other.lovable.app/x.js"></script><script src="https://mine.lovable.app:8443/y.js"></script><script src="https://ec2-1-2-3-4.compute-1.amazonaws.com/z.js"></script><script src="/a.js"></script>' : "1") };
  };
  const r = await siteScan("mine.lovable.app", { fetcher });
  assert.equal(r.scripts, 1);
  assert.ok(!calls.some((c) => /other\.lovable|:8443|amazonaws/.test(c)));
});

test("--mine: the key names the real project, a refused key is said, and a table that times out is not called closed", async () => {
  const realRef = "abcdefghijklmnopqrst";
  const script = `const old="https://zzzzzzzzzzzzzzzzzzzz.supabase.co";${client}db.from("profiles");db.from("events");`;
  const calls = [];
  const make = ({ settings = 200, events = 503 } = {}) => async (url, opts = {}) => {
    calls.push(url);
    const r = (status, body = "", headers = {}) => ({ status, url, headers: new Headers(headers), text: async () => body });
    if (url.startsWith("http://")) return r(200, "");
    if (url.includes(".supabase.co")) {
      if (!url.startsWith(`https://${realRef}.supabase.co`)) return r(401);
      const path = new URL(url).pathname;
      if (path === "/auth/v1/settings") return r(settings, "{}");
      if (path === "/rest/v1/profiles") return new URL(url).searchParams.get("select") === "*" ? r(206, "", { "content-range": "0-0/999" }) : r(400);
      if (path === "/rest/v1/events") return r(events);
      return r(path === "/rest/v1/" ? 401 : 404);
    }
    return { status: 200, url, headers: new Headers({ "content-type": new URL(url).pathname === "/" ? "text/html" : "application/javascript" }), text: async () => (new URL(url).pathname === "/" ? '<script src="/a.js"></script>' : script) };
  };
  const r = await siteScan("app.example", { fetcher: make(), mine: true });
  assert.ok(ids(r).includes("supabase:table:profiles"), "the old address in the code didn't win");
  assert.ok(!calls.some((c) => c.includes("zzzzzzzz") && c.includes("/rest/")));
  assert.match(r.findings.find((f) => f.id === "db:tables-untested").why, /events/);
  assert.equal(r.supabase.tablesTested, 1);
  const refused = await siteScan("app.example", { fetcher: make({ settings: 401 }), mine: true });
  assert.ok(ids(refused).includes("db:key-rejected") && !ids(refused).includes("supabase:table:profiles"));
  assert.equal(refused.supabase.checked, false);
  assert.match(refused.verdict, /weren't checked/);
});

// --- second review (10 November 2026): bugs the first round of fixes introduced ---
test("keys: a real password with odd characters, or a weak one, is still a leak", async () => {
  for (const leak of [
    "postgresql://postgres:Tr0ub4dor$3xQ@db.abcdefghijklmnopqrst.supabase.co:5432/postgres",
    "postgres://app:postgres@db.examplecorp.io:5432/app",
    "mysql://root:12345678@mysql.prodhost.io/shop",
    "postgres://your-team:p{ss}w[o]rd<1>@pg.prodhost.io/db",
  ]) {
    const r = await siteScan("shop.example", { fetcher: launchSite({ script: `const u="${leak}";`, dns: GOOD_DNS }).fetcher });
    assert.deepEqual(ids(r), ["secret:database-url"], leak);
  }
  const twilio = await siteScan("shop.example", { fetcher: launchSite({ script: `const c={sid:"AC${"4f9a07c2e81b3d65".repeat(2)}"};const t="${"b7e2049c5a1f83d6".repeat(2)}";`, dns: GOOD_DNS }).fetcher });
  assert.deepEqual(ids(twilio), ["secret:twilio"]);
});

test("--mine: an estimated row count is not proof that rows are readable", async () => {
  const make = (planned) => async (url, opts = {}) => {
    const r = (status, headers = {}) => ({ status, url, headers: new Headers(headers), text: async () => "{}" });
    if (url.startsWith("http://")) return { status: 200, url: url.replace("http://", "https://"), headers: new Headers(), text: async () => "" };
    if (url.startsWith(SB)) {
      const u = new URL(url);
      if (u.pathname === "/rest/v1/profiles") {
        if (u.searchParams.get("select") !== "*") return r(200);
        return /exact/.test(opts.headers?.prefer || "") ? r(500) : r(200, { "content-range": planned });
      }
      return r(u.pathname === "/auth/v1/settings" ? 200 : 404);
    }
    return { status: 200, url, headers: new Headers({ "content-type": new URL(url).pathname === "/" ? "text/html" : "application/javascript" }), text: async () => (new URL(url).pathname === "/" ? '<script src="/a.js"></script>' : `${client}db.from("profiles");`) };
  };
  const closed = await siteScan("app.example", { fetcher: make("*/48213"), mine: true });
  assert.ok(!ids(closed).some((id) => id.startsWith("supabase:table:")), "a protected big table is not reported as open");
  assert.equal(closed.supabase.tablesTested, 1);
  const open = await siteScan("app.example", { fetcher: make("0-0/48213"), mine: true });
  const f = open.findings.find((x) => x.id === "supabase:table:profiles");
  assert.equal(f.severity, "critical");
  assert.match(f.title, /can read rows of "profiles"/, "the estimate is not quoted as a row count");
});

test("--mine: the first key in the code is the app's, other projects are named, and an untested table qualifies the verdict", async () => {
  const stale = `${b64({ alg: "HS256" })}.${b64({ iss: "supabase", ref: "zzzzzzzzzzzzzzzzzzzz", role: "anon" })}.${"s".repeat(20)}`;
  const script = `${client}db.from("profiles");db.from("events");const legacy={u:"https://zzzzzzzzzzzzzzzzzzzz.supabase.co",k:"${stale}"};`;
  const calls = [];
  const fetcher = async (url) => {
    calls.push(url);
    const r = (status, headers = {}) => ({ status, url, headers: new Headers(headers), text: async () => "{}" });
    if (url.startsWith("http://")) return { status: 200, url: url.replace("http://", "https://"), headers: new Headers(), text: async () => "" };
    if (url.includes(".supabase.co")) {
      const u = new URL(url);
      if (u.pathname === "/rest/v1/profiles") return r(401);
      if (u.pathname === "/rest/v1/events") return r(503);
      return r(u.pathname === "/auth/v1/settings" ? 200 : 404);
    }
    return { status: 200, url, headers: new Headers({ "content-type": new URL(url).pathname === "/" ? "text/html" : "application/javascript" }), text: async () => (new URL(url).pathname === "/" ? '<script src="/a.js"></script>' : script) };
  };
  const r = await siteScan("app.example", { fetcher, mine: true });
  assert.ok(calls.some((c) => c.startsWith(SB + "/rest/v1/profiles")) && !calls.some((c) => c.includes("zzzzzzzz")), "the real project was tested, the leftover one wasn't touched");
  assert.match(r.findings.find((f) => f.id === "db:several-projects").why, /zzzzzzzzzzzzzzzzzzzz/);
  assert.equal(r.supabase.tablesUntested, 1);
  assert.match(r.verdict, /Some database tables couldn't be checked/);
});

test("domains: ordinary names that look like suffixes stay whole, and keep their own scripts", async () => {
  const seen = [];
  const fetcher = async (url) => {
    const u = new URL(url);
    if (u.hostname === "cloudflare-dns.com") return (seen.push(u.searchParams.get("name")), { status: 200, url, headers: new Headers(), text: async () => JSON.stringify({ Status: 0, Answer: [{ type: 16, data: '"v=DMARC1; p=none"' }] }) });
    return { status: 200, url: url.replace("http://", "https://"), headers: new Headers({ "content-type": u.pathname === "/" ? "text/html" : "application/javascript" }), text: async () => (u.pathname === "/" ? '<a href="/privacy">p</a><script src="https://static.web.de/app.js"></script>' : "1") };
  };
  const r = await siteScan("www.web.de", { fetcher });
  assert.equal(r.scripts, 1, "static.web.de belongs to web.de");
  for (const host of ["app.id.me", "www.ad.nl", "shop.art.co", "shop.web.za", "shop.com.co"]) await siteScan(host, { fetcher });
  assert.deepEqual([...new Set(seen.filter((n) => n.startsWith("_dmarc.")))].sort(), ["_dmarc.ad.nl", "_dmarc.art.co", "_dmarc.id.me", "_dmarc.shop.com.co", "_dmarc.shop.web.za", "_dmarc.web.de"]);
});

test("names: per-user tables are personal, shared lists of kinds are not", async () => {
  const tables = { user_settings: 5, account_status: 5, waitlist: 5, clients: 5, subscription_plans: 5, order_types: 5 };
  const r = await siteScan("app.example", { fetcher: modernSupabase(tables, client + Object.keys(tables).map((t) => `db.from("${t}");`).join("")).fetcher, mine: true });
  const level = (t) => r.findings.find((f) => f.id === `supabase:table:${t}`).severity;
  for (const t of ["user_settings", "account_status", "waitlist", "clients"]) assert.equal(level(t), "critical", t);
  for (const t of ["subscription_plans", "order_types"]) assert.equal(level(t), "medium", t);
});

// --- third review (10 November 2026) ---
test("keys: documentation keys and input-field hints are not leaks, real keys next to them still are", async () => {
  const hints = [
    "postgres://postgres:your-super-secret-and-long-postgres-password@db.abcdefghijklmnopqrst.supabase.co:5432/postgres",
    "postgresql://postgres:YOUR_PASSWORD_HERE@db.abcdefghijklmnopqrst.supabase.co/postgres",
    "mysql://root:example-password@mysql.prodhost.io/shop",
    "postgres://user:%PASSWORD%@pg.prodhost.io/db",
    "AKI\u0041IOSFODNN7EXAMPLE",
    "sk-\u0061nt-api03-your-api-key-here",
    "sk-\u0070roj-your-openai-api-key-here",
    "xox\u0062-your-bot-token-here",
    "github_\u0070at_your_personal_access_token",
    "S\u0047.your_sendgrid_api_key_here.put_the_rest_of_the_key_here",
    "sb_\u0073ecret_your_service_role_key_here",
  ];
  const quiet = await siteScan("shop.example", { fetcher: launchSite({ script: hints.map((h, i) => `const h${i}="${h}";`).join(""), dns: GOOD_DNS }).fetcher });
  assert.deepEqual(ids(quiet), []);
  for (const real of ["AKI\u0041Z7QW3RT8YH2KLM9P", "postgresql://postgres:Tr0ub4dor$3xQ@db.abcdefghijklmnopqrst.supabase.co:5432/postgres", "postgres://app:password123@pg.prodhost.io/db"])
    assert.equal((await siteScan("shop.example", { fetcher: launchSite({ script: `const a="AKI\u0041IOSFODNN7EXAMPLE";const k="${real}";`, dns: GOOD_DNS }).fetcher })).grade, "F", real);
});

test("domains: www.gov.uk is gov.uk's own site, and Austrian second levels are known", async () => {
  const seen = [];
  const fetcher = async (url, opts) => {
    const u = new URL(url);
    if (u.hostname === "cloudflare-dns.com") seen.push(u.searchParams.get("name"));
    return launchSite({}).fetcher(url, opts);
  };
  for (const host of ["www.gov.uk", "app.shop.or.at", "www.shop.co.uk"]) await siteScan(host, { fetcher });
  assert.deepEqual([...new Set(seen.filter((n) => n.startsWith("_dmarc.")))].sort(), ["_dmarc.gov.uk", "_dmarc.shop.co.uk", "_dmarc.shop.or.at"]);
});

test("launch: typed http where https only bounces back to http is the serious case; a 403 over https still means https exists", async () => {
  const base = (url) => ({ status: 200, url, headers: new Headers({ "content-type": new URL(url).pathname === "/" ? "text/html" : "application/javascript", "content-security-policy": "frame-ancestors 'none'" }), text: async () => (new URL(url).pathname === "/" ? '<a href="/privacy">p</a><script src="/a.js"></script>' : "1") });
  const bounce = async (url) => (url.startsWith("https://shop.vercel.app") ? base(url.replace("https://", "http://")) : base(url));
  assert.ok(ids(await siteScan("http://shop.vercel.app", { fetcher: bounce })).includes("launch:no-https"));
  const forbidden = async (url) => (url.startsWith("https://shop.vercel.app") ? { ...base(url), status: 403 } : base(url));
  const r = await siteScan("http://shop.vercel.app", { fetcher: forbidden });
  assert.ok(ids(r).includes("launch:no-https-redirect") && !ids(r).includes("launch:no-https"));
});

// --- fourth review (10 November 2026) ---
test("keys: typed-in fake keys are not leaks; a real password that merely contains a word still is", async () => {
  const fakes = [
    "s\u006b-1234567890abcdef1234567890abcdef1234567890abcdef", "sk_\u006cive_1234567890abcdefghijklmn", "sk_\u006cive_abcdefghijklmnopqrstuvwx", "sk-\u0070roj-abcdefghijklmnopqrstuvwxyz123456",
    "sk-\u0061nt-api03-abc123def456ghi789jkl", "gh\u0070_1234567890abcdefghijklmnopqrstuvwxyz", "AKI\u00411234567890ABCDEF", "whse\u0063_1234567890abcdefghijklmnop",
    "xox\u0062-123456789012-1234567890123-abcdefghijklmnopqrstuvwx", "sk-\u0070roj-REPLACE_WITH_REAL_KEY_VALUE", "sk-\u0061nt-api03-replace-with-real-key", "sb_\u0073ecret_REPLACE_ME_REPLACE_ME_REPLACE",
    "gh\u0070_YourGitHubPersonalAccessTokenHere12", "sk_\u006cive_YourStripeSecretKeyGoesHere", "postgres://postgres:REPLACE_ME@db.myhost.io", "postgres://postgres:DB_PASSWORD@db.myhost.io",
    "postgres://user:••••••••@db.myhost.io", "postgres://postgres:insert-password@db.myhost.io",
  ];
  fakes.push('{"type": "service_account", "project_id": "your-project-id", "private_key_id": "key-id", "private_key": "-----BEGIN PRIV\u0041TE KEY-----\\nYOUR_PRIVATE_KEY_HERE\\n-----END PRIVATE KEY-----\\n"}'.replace(/"/g, "'"));
  for (const fake of fakes) assert.deepEqual(ids(await siteScan("shop.example", { fetcher: launchSite({ script: `const k="${fake}";`, dns: GOOD_DNS }).fetcher })), [], fake);
  const reals = [
    "postgres://app:Example123!@db.shop.io/app", "postgres://app:Summer2024!@db.shop.io/app", "postgres://app:mysecretpassword@db.shop.io/app",
    "sk_\u006cive_51NqX8aLk2mVp9RtY4wZc7HbD", "sk-\u0061nt-api03-Qm8xT2vLp9Rk4Wz7YbN3cJ6hF1dG5sA0", "gh\u0070_R7kQ2mX9vT4pL8wZ3yB6nJ1cH5dG0sFaE2uY", "AKI\u0041Z7QW3RT8YH2KLM9P", "whse\u0063_Xk29LmQp84ZrTv61YwBn37HcJd50",
  ];
  for (const real of reals) assert.equal((await siteScan("shop.example", { fetcher: launchSite({ script: `const k="${real}";`, dns: GOOD_DNS }).fetcher })).grade, "F", real);
});
