// Leak simulator. Each switch is one Launch Blockers pattern. "Let the stranger try" plays what the public
// write-ups describe, step by step, against the switches that are open, and shows the doors that held.
// Everything is made up: names use example.test, amounts are illustrative, nothing leaves this page.
(() => {
  "use strict";
  const P = window.PATTERNS || {};

  // id: the pattern id in data/patterns.json. node: where it happens on the map.
  // open: the steps when the setting is left open. held: the one step when it's locked down.
  const S = [
    {
      id: "no-rls", node: "db", what: "profiles table: Row Level Security", on: "on", off: "off",
      hint: "Off: the app's public key can read every row.",
      open: [
        ["browser", "opens the app and copies the database address and public key from its JavaScript (they're meant to be public)"],
        ["db", "asks for every row of profiles with that public key"],
        ["db", "gets 2,418 rows back: names, emails, phone numbers", { rows: 2418 }, true],
        ["db", 'first row: "Ana R. · ana.r@example.test · +44 7700 900118"', null, true],
      ],
      held: ["db", "asks for every row of profiles: 0 rows. Row Level Security only shows a user their own row."],
    },
    {
      id: "open-policy", node: "db", what: "messages table: who can read", on: "the owner", off: "everyone (true)",
      hint: 'A rule whose condition is just "true" checks nothing.',
      open: [
        ["db", "asks for every row of messages. Row Level Security is on, but the rule says using (true)"],
        ["db", "gets 18,904 private messages between users", { rows: 18904 }, true],
      ],
      held: ["db", "asks for every row of messages: the rule compares auth.uid() with the sender, so 0 rows."],
    },
    {
      id: "firebase-open-rules", node: "firebase", what: "Firestore rules", on: "signed-in owner", off: "if true",
      hint: "Test-mode rules let anyone read and write.",
      open: [
        ["browser", "copies the Firebase config from the page (meant to be public)"],
        ["firebase", "lists the chats collection: allow read, write: if true"],
        ["firebase", "downloads 51,200 chat histories, and could delete them too", { rows: 51200 }, true],
      ],
      held: ["firebase", "lists chats: permission denied. Rules only let a signed-in user read their own chats."],
    },
    {
      id: "public-storage", node: "storage", what: "id-photos bucket", on: "private", off: "public",
      hint: "Public: anyone with a file's address can download it.",
      open: [
        ["storage", "guesses the bucket address from an avatar link: .../storage/v1/object/public/id-photos/"],
        ["storage", "lists the bucket and downloads 640 ID photos and selfies", { files: 640 }, true],
      ],
      held: ["storage", "tries .../public/id-photos/: not found. The bucket is private; owners get short-lived signed links."],
    },
    {
      id: "secret-in-frontend", node: "browser", what: "OpenAI key name", on: "OPENAI_API_KEY (server)", off: "VITE_OPENAI_API_KEY",
      hint: "A VITE_ or NEXT_PUBLIC_ name is copied into the browser code.",
      open: [
        ["browser", "searches the JavaScript bundle for sk-proj- and finds the OpenAI key"],
        ["browser", "uses it from their own script all weekend: about $1,900 of your credit (illustrative)", { money: 1900 }, true],
      ],
      held: ["browser", "searches the JavaScript bundle for keys: only the public database key is there."],
    },
    {
      id: "service-role-in-frontend", node: "browser", what: "Supabase key in the browser", on: "anon (public) key", off: "service_role key",
      hint: "service_role skips every Row Level Security rule.",
      open: [
        ["browser", "finds a key in the bundle whose role is service_role"],
        ["db", "reads and edits every table with it: every rule is skipped", { rows: 24940 }, true],
        ["db", "could also delete everything. The stranger stops at reading.", null, true],
      ],
      held: ["browser", "finds only the anon key, which Row Level Security still limits."],
    },
    {
      id: "env-committed", node: "repo", what: ".env file", on: "in .gitignore", off: "committed to git",
      hint: "Committed keys stay in the history forever.",
      open: [
        ["repo", "finds the public repository and reads .env from the history"],
        ["repo", "gets STRIPE_SECRET_KEY and the database password", { keys: 2 }, true],
      ],
      held: ["repo", "reads the repository: .env was never committed, only .env.example with names."],
    },
    {
      id: "unauthenticated-function", node: "fn", what: "ai-chat function: sign-in check", on: "on", off: "verify_jwt = false",
      hint: "Off: anyone on the internet can call it.",
      open: [
        ["fn", "calls ai-chat with no login, from a loop: 40,000 requests"],
        ["fn", "each one runs your paid AI model: about $640 (illustrative)", { money: 640 }, true],
      ],
      held: ["fn", "calls ai-chat with no login: 401. The function only answers signed-in users."],
    },
    {
      id: "webhook-unverified", node: "webhook", what: "payment webhook", on: "checks Stripe's signature", off: "believes any request",
      hint: 'Anyone can send "payment succeeded".',
      open: [
        ["webhook", 'sends a hand-written "checkout.session.completed" for their own account'],
        ["webhook", "the app upgrades them to the paid plan for free", { plans: 1 }, true],
      ],
      held: ["webhook", "sends a fake payment message: 400. It has no valid Stripe-Signature header."],
    },
    {
      id: "hardcoded-auth-secret", node: "auth", what: "login signing secret", on: "random, in an env variable", off: '"supersecretkey" in code',
      hint: "Whoever knows it can make a login for any user.",
      open: [
        ["repo", 'finds JWT_SECRET = "supersecretkey" in the code (a string Invicti found in 1,182 AI-generated apps)'],
        ["auth", 'signs their own token with role "admin"'],
        ["auth", "the app accepts it: they're signed in as an admin", { accounts: 1 }, true],
      ],
      held: ["auth", "tries the usual secrets (supersecretkey, secret, changeme): every token is rejected."],
    },
    {
      id: "rls-user-metadata", node: "db", what: "admin_notes rule checks", on: "app_metadata (server only)", off: "user_metadata",
      hint: "Users can change their own user_metadata.",
      open: [
        ["auth", "signs up, then calls updateUser({ data: { role: 'admin' } }) on their own account"],
        ["db", "the rule on admin_notes checks user_metadata.role, so it lets them in"],
        ["db", "reads 312 internal notes about customers", { rows: 312 }, true],
      ],
      held: ["db", "sets role: admin in their own user_metadata: no effect, the rule checks app_metadata, which only the server sets."],
    },
    {
      id: "definer-skips-rls", node: "db", what: "leaderboard view", on: "security_invoker = on", off: "default (creator's rights)",
      hint: "A view runs with its creator's rights unless told otherwise.",
      open: [
        ["db", "notices a leaderboard view in the API next to the protected profiles table"],
        ["db", "the view runs with its creator's rights, so it skips the table's rules: 2,418 emails", { rows: 2418 }, true],
      ],
      held: ["db", "reads the leaderboard view: only display names and scores, the table's rules still apply."],
    },
  ];
  const byId = Object.fromEntries(S.map((s) => [s.id, s]));
  const PRESETS = {
    typical: ["open-policy", "public-storage", "secret-in-frontend", "unauthenticated-function", "webhook-unverified"],
    locked: [],
    all: S.map((s) => s.id),
  };

  const $ = (q, el = document) => el.querySelector(q);
  const esc = (t) => String(t).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
  const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const open = new Set();
  let running = false;

  // ---- state in the address, so a setup can be shared: #open=no-rls,public-storage
  function readHash() {
    const m = location.hash.match(/open=([\w,-]*)/);
    const p = location.hash.match(/(?:^#|&)p=([\w-]+)/);
    open.clear();
    if (p && byId[p[1]]) open.add(p[1]);
    else if (m) m[1].split(",").filter((id) => byId[id]).forEach((id) => open.add(id));
    else PRESETS.typical.forEach((id) => open.add(id));
  }
  function writeHash() {
    const h = `#open=${S.filter((s) => open.has(s.id)).map((s) => s.id).join(",")}`;
    history.replaceState(null, "", h);
  }

  // ---- switches
  function renderSwitches() {
    $("#switches").innerHTML = S.map((s) => {
      const pat = P[s.id] || {};
      const isOpen = open.has(s.id);
      return `<li class="sw${isOpen ? " open" : ""}" data-id="${s.id}">
        <span class="num">#${pat.n ?? "?"}</span>
        <span class="what">${esc(s.what)}<small>${esc(isOpen ? s.hint : `locked: ${s.on}`)}</small></span>
        <button type="button" class="tog" aria-pressed="${isOpen}" aria-label="${esc(s.what)}: ${esc(isOpen ? s.off : s.on)}. Press to change.">${esc(isOpen ? s.off : s.on)}</button>
      </li>`;
    }).join("");
  }
  $("#switches").addEventListener("click", (e) => {
    const b = e.target.closest(".tog");
    if (!b || running) return;
    const id = b.closest(".sw").dataset.id;
    open.has(id) ? open.delete(id) : open.add(id);
    writeHash();
    renderSwitches();
    $(`.sw[data-id="${id}"] .tog`).focus();
  });
  document.querySelectorAll("[data-preset]").forEach((b) =>
    b.addEventListener("click", () => {
      if (running) return;
      open.clear();
      PRESETS[b.dataset.preset].forEach((id) => open.add(id));
      writeHash();
      renderSwitches();
      resetStage();
    }),
  );

  // ---- the run
  const sleep = (ms) => new Promise((r) => setTimeout(r, $("#fast").checked || reduced ? Math.min(ms, 60) : ms));
  const nodeEl = (n) => $(`.node[data-node="${n}"]`);
  const tally = { rows: 0, files: 0, money: 0, keys: 0, accounts: 0, plans: 0 };
  function renderTally() {
    const parts = [];
    if (tally.rows) parts.push(`<span>rows read <b>${tally.rows.toLocaleString("en")}</b></span>`);
    if (tally.files) parts.push(`<span>files taken <b>${tally.files.toLocaleString("en")}</b></span>`);
    if (tally.money) parts.push(`<span>your bill <b>$${tally.money.toLocaleString("en")}</b></span>`);
    if (tally.keys) parts.push(`<span>secret keys <b>${tally.keys}</b></span>`);
    if (tally.accounts) parts.push(`<span>admin logins forged <b>${tally.accounts}</b></span>`);
    if (tally.plans) parts.push(`<span>paid plans given away <b>${tally.plans}</b></span>`);
    $("#tally").innerHTML = parts.length ? parts.join("") + `<span class="dim">(simulated)</span>` : "";
  }
  function resetStage() {
    document.querySelectorAll(".node").forEach((n) => n.classList.remove("leak", "held", "active"));
    Object.keys(tally).forEach((k) => (tally[k] = 0));
    renderTally();
    $("#log").innerHTML = '<span class="dim">Press "let the stranger try".</span>';
    $("#report").hidden = true;
  }
  function log(html) {
    const l = $("#log");
    l.insertAdjacentHTML("beforeend", html + "\n");
    l.scrollTop = l.scrollHeight;
  }
  async function fly(to, quick) {
    const a = nodeEl("stranger").getBoundingClientRect();
    const b = nodeEl(to).getBoundingClientRect();
    const pk = $("#packet");
    if (reduced || $("#fast").checked || !pk.animate) return;
    const x0 = a.left + a.width / 2, y0 = a.top + a.height / 2, x1 = b.left + b.width / 2, y1 = b.top + b.height / 2;
    const duration = quick ? 380 : 650;
    const anim = pk.animate([{ transform: `translate(${x0}px,${y0}px)`, opacity: 1 }, { transform: `translate(${x1}px,${y1}px)`, opacity: 1 }, { transform: `translate(${x1}px,${y1}px)`, opacity: 0 }], { duration, easing: "ease-in-out" });
    // A hidden tab may never finish an animation: never let the run wait on it longer than it should take.
    await Promise.race([anim.finished.catch(() => {}), new Promise((r) => setTimeout(r, duration + 80))]);
    anim.cancel();
  }
  async function step(node, text, add, isLeak, cls) {
    const el = nodeEl(node);
    el.classList.add("active");
    await fly(node, cls === "held");
    if (add) for (const [k, v] of Object.entries(add)) tally[k] += v;
    renderTally();
    if (isLeak) el.classList.add("leak");
    if (cls === "held" && !el.classList.contains("leak")) el.classList.add("held");
    log(`<span class="who">stranger →</span> <span class="dim">${esc(node)}</span>  <span class="${isLeak ? "leakline" : cls === "held" ? "heldline" : ""}">${esc(text)}</span>`);
    await sleep(isLeak ? 700 : cls === "held" ? 200 : 450);
    el.classList.remove("active");
  }

  async function run() {
    if (running) return;
    running = true;
    $("#run").disabled = true;
    resetStage();
    $("#log").innerHTML = "";
    log('<span class="dim">A stranger finds your app. No account, no special tools: a browser and the public write-ups.</span>');
    await sleep(500);
    const leaked = [];
    for (const s of S) {
      const sw = $(`.sw[data-id="${s.id}"]`);
      sw?.classList.remove("hit");
      void sw?.offsetWidth;
      sw?.classList.add("hit");
      if (open.has(s.id)) {
        log(`\n<span class="dim">#${P[s.id]?.n} ${esc(P[s.id]?.title || s.what)}</span>`);
        for (const [node, text, add, isLeak] of s.open) await step(node, text, add, isLeak);
        leaked.push(s.id);
      } else {
        await step(s.held[0], s.held[1], null, false, "held");
      }
    }
    log(leaked.length ? `\n<span class="leakline">${leaked.length > 1 ? `${leaked.length} ways in. Every one is a setting, not a hack.` : "1 way in. It's a setting, not a hack."}</span>` : `\n<span class="heldline">Every door held. That's what "CLEAR" looks like.</span>`);
    renderReport(leaked);
    running = false;
    $("#run").disabled = false;
  }
  $("#run").addEventListener("click", run);

  // ---- report: what leaked, the dated incident behind it, and the prompt that fixes it
  function renderReport(ids) {
    const body = $("#report-body");
    if (!ids.length) {
      body.innerHTML = `<p class="allclear">Nothing leaked in this setup. Now check that your real app matches it: <code>npx launch-blockers check</code>.</p>`;
    } else {
      const all = ids.map((id) => P[id]?.fix).filter(Boolean).join("\n\n");
      body.innerHTML =
        `<div class="report-head"><span>${ids.length} leak${ids.length > 1 ? "s" : ""}, each one on the public record:</span><button type="button" data-copytext="${esc(all)}">copy all ${ids.length} fix prompt${ids.length > 1 ? "s" : ""}</button></div>` +
        ids.map((id) => {
          const p = P[id];
          if (!p) return "";
          const src = p.source;
          const record = src.date ? `<b>${esc(src.date)}</b> · <a href="${esc(src.url)}" rel="noopener">${esc(src.title)}</a> (${esc(src.name)})${src.what ? `. ${esc(src.what)}` : ""}` : `The platform's own rule: <a href="${esc(src.url)}" rel="noopener">${esc(src.name)}</a>.`;
          return `<article class="finding">
            <h3>#${p.n} ${esc(p.title)}<span class="sev sev-${esc(p.severity)}">${esc(p.severity)}</span></h3>
            <p>${esc(p.why)}</p>
            <p class="dim">On the record: ${record}</p>
            <p>Paste this into your builder:</p>
            <pre class="prompt">${esc(p.fix)}</pre>
            <button type="button" data-copytext="${esc(p.fix)}">copy fix prompt</button> <a href="${esc(p.anchor)}" rel="noopener">full pattern</a>
          </article>`;
        }).join("");
    }
    $("#report").hidden = false;
  }

  // ---- copying
  function toast(t) {
    const d = document.createElement("div");
    d.className = "toast";
    d.textContent = t;
    document.body.append(d);
    setTimeout(() => d.remove(), 1600);
  }
  async function copy(text, what) {
    try {
      await navigator.clipboard.writeText(text);
      toast(`copied ${what}`);
    } catch {
      toast("couldn't copy: select the text instead");
    }
  }
  document.addEventListener("click", (e) => {
    const b = e.target.closest("[data-copytext]");
    if (b) copy(b.dataset.copytext, b.textContent.includes("all") ? "all fix prompts" : "fix prompt");
    const c = e.target.closest("[data-copy]");
    if (c) copy(c.textContent, "command");
  });
  $("#share").addEventListener("click", () => {
    writeHash();
    copy(location.href, "link to this setup");
  });

  window.addEventListener("hashchange", () => {
    if (running) return;
    readHash();
    renderSwitches();
    resetStage();
  });
  readHash();
  writeHash();
  renderSwitches();
})();
