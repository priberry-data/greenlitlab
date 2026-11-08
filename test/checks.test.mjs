import test from "node:test";
import assert from "node:assert";
import { siteScan } from "../src/grade.mjs";

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
