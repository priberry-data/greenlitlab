// The web check: send the address to /api/check and show the grade, the reasons and the fix prompts.
// Everything from the server is put on the page as text, never as HTML.
(() => {
  const f = document.getElementById("f");
  const input = document.getElementById("u");
  const go = document.getElementById("go");
  const out = document.getElementById("out");

  const el = (tag, cls, text) => {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  };

  // Progress and errors appear right under the box, where the person is already looking. Below the hero they'd be off screen.
  const status = document.getElementById("status");
  const say = (text, kind = "") => {
    status.textContent = text || "";
    status.className = `status ${kind}`;
    status.hidden = !text;
  };

  // The same wording as allPrompts() in src/grade.mjs, so the web and the CLI give the same combined prompt.
  const allPrompts = (list) =>
    [`My app has ${list.length} security problems to fix. Work through them in this order, one at a time. After each one, tell me what you changed before moving on. Don't change anything unrelated.`, ...list.map((f, i) => `${i + 1}. ${f.title}.\n${f.prompt}`)].join("\n\n");

  const copyButton = (text, label = "Copy") => {
    const b = el("button", "copy", label);
    b.type = "button";
    b.addEventListener("click", async () => {
      // The clipboard API needs focus and permission; the old way works almost everywhere else.
      let ok = false;
      try {
        await navigator.clipboard.writeText(text);
        ok = true;
      } catch {
        const t = document.createElement("textarea");
        t.value = text;
        t.setAttribute("readonly", "");
        t.style.position = "fixed";
        t.style.opacity = "0";
        document.body.append(t);
        t.select();
        try {
          ok = document.execCommand("copy");
        } catch {}
        t.remove();
      }
      b.textContent = ok ? "Copied" : "Select the text to copy";
      setTimeout(() => (b.textContent = label), 1800);
    });
    return b;
  };

  function render(r) {
    const card = el("div", "card");
    out.replaceChildren(card);
    const host = (() => {
      try {
        return new URL(r.url).host;
      } catch {
        return r.url;
      }
    })();
    const head = el("div", "r-head");
    const text = el("div");
    text.append(el("p", "r-verdict", r.verdict), el("p", "r-meta", `${host}${r.builder ? ` · built with ${r.builder}` : ""}${r.score == null ? "" : ` · ${r.score}/100`} · ${r.scripts} script${r.scripts === 1 ? "" : "s"} read${r.cached ? " · checked in the last 2 minutes" : ""}`));
    head.append(el("span", `grade ${r.grade === "?" ? "g-none" : `g-${r.grade}`}`, r.grade), text);
    card.append(head);
    if (!r.findings.length) card.append(el("p", "ok", "Nothing found that a stranger could use against you."));

    // What this check couldn't see comes first: a good grade means little until you've read it.
    for (const x of r.findings.filter((x) => x.severity === "info")) {
      const box = el("div", "unseen");
      box.append(el("h3", null, x.title), el("p", null, x.why));
      if (x.id === "db:skipped") box.append(el("p", "next", `On your computer, for your own app: npx greenlitlab ${host} --mine`));
      else if (x.fix) box.append(el("p", "next", x.fix));
      if (x.checkPrompt) {
        const p = el("div", "r-prompt");
        const bar = el("div", "r-prompt-bar");
        bar.append(el("span", null, `No terminal? Paste into ${r.pasteInto} to have it check`), copyButton(x.checkPrompt));
        p.append(bar, el("pre", null, x.checkPrompt));
        box.append(p);
      }
      card.append(box);
    }

    const fixes = r.findings.filter((x) => x.prompt);
    if (fixes.length > 1) {
      const all = el("div", "all-fixes");
      all.append(el("span", null, `${fixes.length} fixes. Paste them one at a time, or all at once:`), copyButton(allPrompts(fixes), "Copy all fixes"));
      card.append(all);
    }
    let n = 0;
    for (const x of r.findings.filter((x) => x.severity !== "info")) {
      const box = el("div", "finding");
      const h = el("h3");
      h.append(el("i", `dot ${x.severity}`), document.createTextNode(x.title), el("span", "sev", x.severity));
      box.append(h, el("p", null, x.why));
      if (x.first) box.append(el("p", "first", `Do this yourself first: ${x.first}`));
      if (x.prompt) {
        n++;
        const p = el("div", "r-prompt");
        const bar = el("div", "r-prompt-bar");
        bar.append(el("span", null, `Fix ${n} · paste into ${r.pasteInto}`), copyButton(x.prompt));
        p.append(bar, el("pre", null, x.prompt));
        box.append(p);
      } else if (x.fix) box.append(el("p", "next", x.fix));
      card.append(box);
    }
    const red = r.findings.some((x) => x.severity === "critical" || x.severity === "high");
    if (n) card.append(el("p", "note", `${red ? "Fix the red items first, one prompt at a time. " : ""}When a fix is live, check again here. A new result is ready after two minutes.`));

    // A dated public report, for an owner who wants to show the result. The app must carry the owner's tag first.
    if (r.grade !== "?") {
      const share = el("div", "share");
      const start = el("button", "copy", "Publish a dated report");
      start.type = "button";
      const post = async (step) => {
        const res = await fetch("/api/report", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ url: r.url, step }) });
        return { ok: res.ok, data: await res.json().catch(() => ({ error: "Something went wrong. Try again in a minute." })) };
      };
      start.addEventListener("click", async () => {
        start.disabled = true;
        const { ok, data } = await post("start");
        if (!ok) return share.replaceChildren(el("p", "err-line", data.error));
        const prompt = `Add this exact tag inside the <head> of my app's main HTML page (index.html, or the root layout), then publish the app:\n${data.tag}`;
        const box = el("div", "r-prompt");
        const bar = el("div", "r-prompt-bar");
        bar.append(el("span", null, `Step 1 · paste into ${r.pasteInto}, then publish your app`), copyButton(prompt));
        box.append(bar, el("pre", null, prompt));
        const go2 = el("button", "copy", "Step 2 · I've published it, check now");
        go2.type = "button";
        const msg = el("p", "note");
        go2.addEventListener("click", async () => {
          go2.disabled = true;
          msg.textContent = "Checking your live app for the tag…";
          const done = await post("publish");
          go2.disabled = false;
          if (!done.ok) return (msg.textContent = done.data.error);
          const link = el("a", null, `${location.origin}${done.data.report}`);
          link.href = done.data.report;
          const embed = `<a href="${location.origin}${done.data.report}"><img src="${location.origin}${done.data.badge}" alt="Greenlit report" height="22"></a>`;
          const p = el("p", "note", "Published. Your report: ");
          p.append(link);
          const b2 = el("div", "r-prompt");
          const bar2 = el("div", "r-prompt-bar");
          bar2.append(el("span", null, "A badge for your site. It shows the date and expires after 30 days."), copyButton(embed));
          b2.append(bar2, el("pre", null, embed));
          share.replaceChildren(p, b2);
        });
        share.replaceChildren(el("p", null, "This proves the app is yours. The tag is harmless and visitors never see it."), box, go2, msg);
      });
      share.append(el("p", null, "Want to show this result? Publish a dated report page and a badge for your own app. Free. It shows the date, and expires after 30 days."), start);
      card.append(share);
    }

    // The paid monitor doesn't exist yet. This button counts how many people want it, and keeps nothing about them.
    const w = el("div", "watch");
    w.append(el("p", null, "Your builder rewrites code with every prompt, so a fix can quietly break later. Want Greenlit to re-check this app every week and after every change, and tell you the moment something opens up?"));
    const b = el("button", null, "Watch my app · $19/month");
    b.type = "button";
    b.addEventListener("click", async () => {
      b.disabled = true;
      try {
        await fetch("/api/watch", { method: "POST" });
      } catch {}
      const p = el("p");
      p.append(document.createTextNode("Thank you. Watching isn't open yet, and you haven't been charged. Email "));
      const a = el("a", null, "crumple@priberry.com");
      a.href = `mailto:crumple@priberry.com?subject=${encodeURIComponent("Greenlit early access")}&body=${encodeURIComponent(`App: ${host}\n`)}`;
      p.append(a, document.createTextNode(" with the subject \"Greenlit early access\" and we'll tell you the day it opens."));
      w.replaceChildren(p);
    });
    w.append(b);
    card.append(w);
    const calm = matchMedia("(prefers-reduced-motion: reduce)").matches;
    out.scrollIntoView({ behavior: calm ? "auto" : "smooth", block: "start" });
  }

  // What no check can see. The answers stay in this browser and never change the grade.
  let questions = null;
  async function ask(pasteInto) {
    try {
      questions = questions || (await (await fetch("/api/questions")).json());
    } catch {
      return;
    }
    const card = el("div", "card asks");
    card.append(el("h2", null, "Seven things only you know"), el("p", "asks-lede", "No check can see these, so Greenlit asks. Your answers stay in your browser and don't change the grade above."));
    const tally = el("p", "note");
    const state = {};
    const count = () => {
      const done = Object.values(state);
      tally.textContent = done.length ? `${done.filter(Boolean).length} of ${questions.length} in place${done.length < questions.length ? `, ${questions.length - done.length} not answered` : ""}.` : "";
    };
    for (const [i, q] of questions.entries()) {
      const box = el("div", "finding");
      const id = `q-${q.id}`;
      const label = el("label", null, `${i + 1}. ${q.ask}`);
      label.htmlFor = id;
      const pick = document.createElement("select");
      pick.id = id;
      pick.append(new Option("Choose an answer…", ""));
      for (const o of q.options) pick.append(new Option(o.label, o.key));
      const answer = el("div");
      pick.addEventListener("change", () => {
        const o = q.options.find((o) => o.key === pick.value);
        answer.replaceChildren();
        if (!o) delete state[q.id];
        else {
          state[q.id] = o.ok;
          if (o.ok) answer.append(el("p", "ok", "In place."));
          else {
            answer.append(el("p", "first", o.note));
            const p = el("div", "r-prompt");
            const bar = el("div", "r-prompt-bar");
            bar.append(el("span", null, `Paste into ${pasteInto}`), copyButton(o.prompt));
            p.append(bar, el("pre", null, o.prompt));
            answer.append(p);
          }
        }
        count();
      });
      box.append(label, pick, answer);
      card.append(box);
    }
    card.append(tally);
    out.append(card);
  }

  async function check(url) {
    go.disabled = true;
    go.textContent = "Checking…";
    out.replaceChildren();
    say(`Looking at ${url} the way a stranger would…`, "wait");
    const slow = setTimeout(() => say("Still reading. Bigger apps can take up to thirty seconds.", "wait"), 8000);
    const stop = new AbortController();
    const limit = setTimeout(() => stop.abort(), 60000);
    const fail = (text) => {
      say(text, "err");
      input.focus({ preventScroll: true });
      // The whole message must be on screen, even on a short laptop window or above a phone keyboard.
      status.scrollIntoView({ block: "nearest" });
    };
    try {
      const res = await fetch("/api/check", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ url }), signal: stop.signal });
      const data = await res.json().catch(() => null);
      if (!data) fail(`The check couldn't finish this time. Try again, or run it on your computer: npx greenlitlab ${url}`);
      else if (!res.ok || data.error) fail(data.error || "Something went wrong. Try again in a minute.");
      else {
        say("");
        render(data);
        ask(data.pasteInto);
      }
    } catch (e) {
      fail(e.name === "AbortError" ? `That took too long. Try again, or run it on your computer: npx greenlitlab ${url}` : "Couldn't reach Greenlit. Check your connection and try again.");
    } finally {
      clearTimeout(slow);
      clearTimeout(limit);
      go.disabled = false;
      go.textContent = "Run check";
    }
  }

  f.addEventListener("submit", (e) => {
    e.preventDefault();
    const url = input.value.trim();
    if (!url) {
      say("Enter your app's address first, like myapp.lovable.app.", "err");
      status.scrollIntoView({ block: "nearest" });
      return input.focus({ preventScroll: true });
    }
    history.replaceState(null, "", `?url=${encodeURIComponent(url)}`);
    check(url);
  });

  // A link like /?url=myapp.lovable.app fills the box; the visitor still presses the button.
  const pre = new URLSearchParams(location.search).get("url");
  if (pre) input.value = pre.slice(0, 300);
})();
