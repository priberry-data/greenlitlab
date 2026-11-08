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

  const wrapCard = (child) => {
    const c = el("div", "card");
    c.append(child);
    return c;
  };

  const copyButton = (text) => {
    const b = el("button", "copy", "Copy");
    b.type = "button";
    b.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(text);
        b.textContent = "Copied";
      } catch {
        b.textContent = "Select and copy";
      }
      setTimeout(() => (b.textContent = "Copy"), 1800);
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
    text.append(el("p", "r-verdict", r.verdict), el("p", "r-meta", `${host}${r.builder ? ` · built with ${r.builder}` : ""} · ${r.score}/100${r.cached ? " · checked in the last 10 minutes" : ""}`));
    head.append(el("span", `grade g-${r.grade}`, r.grade), text);
    card.append(head);
    if (!r.findings.length) card.append(el("p", "ok", "Nothing found that a stranger could use against you."));

    let n = 0;
    for (const x of r.findings) {
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
      } else if (x.id === "db:skipped") {
        box.append(el("p", "next", `Your app? Check the database too: npx greenlitlab ${host} --mine`));
      } else if (x.fix) box.append(el("p", "next", x.fix));
      card.append(box);
    }
    const red = r.findings.some((x) => x.severity === "critical" || x.severity === "high");
    if (n) card.append(el("p", "note", `${red ? "Fix the red items first, one prompt at a time. " : ""}When a fix is live, check again here. A new result is ready after ten minutes.`));

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
      p.append(document.createTextNode("Thank you. Watching isn't open yet, and you haven't been charged. "));
      const a = el("a", null, "Email us");
      a.href = `mailto:hello@priberry.com?subject=${encodeURIComponent("Greenlit early access")}&body=${encodeURIComponent(`App: ${host}\n`)}`;
      p.append(a, document.createTextNode(" and we'll tell you the day it opens."));
      w.replaceChildren(p);
    });
    w.append(b);
    card.append(w);
    out.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  async function check(url) {
    go.disabled = true;
    out.replaceChildren(wrapCard(el("p", "wait", `Looking at ${url} the way a stranger would…`)));
    try {
      const res = await fetch("/api/check", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ url }) });
      const data = await res.json().catch(() => ({ error: "Something went wrong. Try again in a minute." }));
      if (!res.ok || data.error) out.replaceChildren(wrapCard(el("p", "err", data.error || "Something went wrong. Try again in a minute.")));
      else render(data);
    } catch {
      out.replaceChildren(wrapCard(el("p", "err", "Couldn't reach Greenlit. Check your connection and try again.")));
    } finally {
      go.disabled = false;
    }
  }

  f.addEventListener("submit", (e) => {
    e.preventDefault();
    const url = input.value.trim();
    if (!url) return input.focus();
    history.replaceState(null, "", `?url=${encodeURIComponent(url)}`);
    check(url);
  });

  // A link like /?url=myapp.lovable.app fills the box; the visitor still presses the button.
  const pre = new URLSearchParams(location.search).get("url");
  if (pre) input.value = pre.slice(0, 300);
})();
