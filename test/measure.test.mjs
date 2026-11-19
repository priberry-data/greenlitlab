import test from "node:test";
import assert from "node:assert";
import { onRequestPost as check } from "../functions/api/check.js";
import { onRequestPost as watch, EMAIL } from "../functions/api/watch.js";
import { onRequestGet as badge } from "../functions/badge/[host].js";

// Cloudflare's cache and KV replaced by maps; waitUntil work is awaited so the counts can be read.
function cloudflare() {
  const store = new Map();
  globalThis.caches = { default: { match: async (r) => (store.has(r.url) ? new Response(store.get(r.url)) : undefined), put: async (r, res) => void store.set(r.url, await res.text()) } };
  const kv = new Map();
  const env = { CHECK: { get: async (k) => kv.get(k) ?? null, put: async (k, v) => void kv.set(k, v), delete: async (k) => void kv.delete(k) } };
  const pending = [];
  const post = async (fn, path, body, ip = "1.1.1.1") => {
    const request = new Request(`http://localhost${path}`, { method: "POST", headers: { "content-type": "application/json", "cf-connecting-ip": ip }, body: JSON.stringify(body) });
    const r = await fn({ request, env, waitUntil: (p) => pending.push(p) });
    await Promise.all(pending.splice(0));
    return { status: r.status, data: await r.json() };
  };
  return { kv, env, post, clear: () => store.clear() };
}

const site = async (url) => ({ status: 200, url, headers: new Headers({ "content-type": "text/html" }), text: async () => "<html><head><title>Shop</title></head><body>hi</body></html>" });

test("measure: repeat checks are counted, our own test checks are not", async () => {
  const real = globalThis.fetch;
  const realRandom = Math.random;
  globalThis.fetch = site;
  Math.random = () => 0; // every sampled count lands
  try {
    const { kv, post, clear } = cloudflare();
    const day = new Date().toISOString().slice(0, 10);
    const r1 = await post(check, "/api/check", { url: "shop.lovable.app" });
    assert.equal(r1.status, 200);
    assert.equal(kv.get(`count:checks:${day}`), "5");
    assert.equal(kv.get(`count:grade:${r1.data.grade}:${day.slice(0, 7)}`), "5");
    clear();
    await post(check, "/api/check", { url: "shop.lovable.app", again: "same" }, "2.2.2.2");
    clear();
    await post(check, "/api/check", { url: "shop.lovable.app", again: "later" }, "3.3.3.3");
    assert.equal(kv.get(`count:again:same:${day}`), "1");
    assert.equal(kv.get(`count:again:later:${day}`), "1");
    clear();
    await post(check, "/api/check", { url: "shop.lovable.app", again: "later", internal: true }, "4.4.4.4");
    assert.equal(kv.get(`count:checks:${day}`), "15", "the internal check adds nothing");
    assert.equal(kv.get(`count:again:later:${day}`), "1");
    // Anything else in "again" is ignored rather than written as a new key.
    clear();
    await post(check, "/api/check", { url: "shop.lovable.app", again: "x".repeat(50) }, "5.5.5.5");
    assert.ok(![...kv.keys()].some((k) => k.includes("xxx")));
  } finally {
    globalThis.fetch = real;
    Math.random = realRandom;
    delete globalThis.caches;
  }
});

test("watch: an email is kept only when typed and valid, with a clean host", async () => {
  try {
    const { kv, post } = cloudflare();
    const none = await post(watch, "/api/watch", { host: "shop.lovable.app" });
    assert.deepEqual(none.data, { ok: true, saved: false });
    assert.equal(kv.get("count:watch:total"), "1");
    const bad = await post(watch, "/api/watch", { host: "shop.lovable.app", email: "not an email" }, "2.2.2.2");
    assert.equal(bad.data.saved, false);
    const good = await post(watch, "/api/watch", { host: "<b>shop</b>", email: " Ana@Example.COM " }, "3.3.3.3");
    assert.equal(good.data.saved, true);
    const saved = [...kv.entries()].filter(([k]) => k.startsWith("watch:"));
    assert.equal(saved.length, 1);
    const v = JSON.parse(saved[0][1]);
    assert.equal(v.email, "ana@example.com");
    assert.equal(v.host, null, "a host that isn't a host name is dropped");
    const mine = await post(watch, "/api/watch", { host: "shop.lovable.app", email: "me@priberry.com", internal: true }, "4.4.4.4");
    assert.equal(mine.data.saved, true);
    assert.equal(kv.get("count:watch:total"), "3", "the internal click isn't counted");
    // Five a visitor an hour.
    for (let i = 0; i < 5; i++) await post(watch, "/api/watch", { email: `a${i}@b.co` }, "9.9.9.9");
    const sixth = await post(watch, "/api/watch", { email: "a6@b.co" }, "9.9.9.9");
    assert.equal(sixth.data.saved, false);
    // A request from another site is refused.
    const request = new Request("https://greenlit.priberry.com/api/watch", { method: "POST", headers: { "content-type": "application/json", origin: "https://evil.example" }, body: "{}" });
    assert.equal((await watch({ request, env: {}, waitUntil() {} })).status, 403);
  } finally {
    delete globalThis.caches;
  }
});

test("watch: the email pattern accepts real addresses, rejects junk, and stays fast", () => {
  for (const ok of ["a@b.co", "first.last+tag@sub.domain.org", "x_y@a-b.io"]) assert.ok(EMAIL.test(ok), ok);
  for (const no of ["a@b", "@b.co", "a b@c.co", "a@b.c", "<a>@b.co", "a@b..co"]) assert.ok(!EMAIL.test(no), no);
  const t = performance.now();
  EMAIL.test("a@" + "b.".repeat(120) + "!");
  EMAIL.test("a@" + "b-".repeat(120) + "!");
  assert.ok(performance.now() - t < 50);
});

test("badge: one visitor asking for thousands of addresses is cut off before the store", async () => {
  const store = new Map();
  globalThis.caches = { default: { match: async (r) => (store.has(r.url) ? new Response(store.get(r.url)) : undefined), put: async (r, res) => void store.set(r.url, await res.text()) } };
  let reads = 0;
  const env = { CHECK: { get: async () => (reads++, null) } };
  try {
    const ask = (i) => badge({ request: new Request(`https://greenlit.priberry.com/badge/a${i}.example.org.svg`, { headers: { "cf-connecting-ip": "7.7.7.7" } }), params: { host: `a${i}.example.org.svg` }, env });
    for (let i = 0; i < 600; i++) assert.equal((await ask(i)).status, 200);
    assert.equal((await ask(601)).status, 429);
    assert.equal(reads, 600);
  } finally {
    delete globalThis.caches;
  }
});
