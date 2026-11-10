// Replays the CLI's welcome screen in a terminal window: the command is typed, then the screen prints
// line by line, exactly as recorded from the CLI (site/term-data.js). Starts when it scrolls into view;
// with reduced motion it simply shows the finished screen.
(() => {
  const D = window.TERM_SCREEN;
  if (!D) return;
  const still = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const CW = 0.6; // a terminal cell is 0.6em wide and 1.2em tall, so two pixels a cell come out square
  const textLen = Math.max(D.command.length + 2, ...D.rows.map((r) => r.t.reduce((n, [, s]) => n + s.length, 0)), D.after ? D.after.note.length : 0);
  const SPIN = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏";
  // Narrow screens: a line longer than WRAP breaks at its last space, like a terminal that wraps words.
  const WRAP = Math.max(D.w + 2, 48);
  const wrap = (t) => {
    const chars = t.flatMap(([c, s]) => [...s].map((ch) => [c, ch]));
    const lines = [];
    while (chars.length > WRAP) {
      let cut = WRAP;
      while (cut > 2 && chars[cut][1] !== " ") cut--;
      if (cut <= 2) cut = WRAP;
      lines.push(chars.splice(0, cut));
      while (chars.length && chars[0][1] === " ") chars.shift();
      chars.unshift(["", " "], ["", " "]);
    }
    lines.push(chars);
    return lines.map((cs) => cs.reduce((acc, [c, ch]) => {
      const last = acc[acc.length - 1];
      if (last && last[0] === c) last[1] += ch;
      else acc.push([c, ch]);
      return acc;
    }, []));
  };
  // On a narrow screen a command's note goes on its own line under it, so the words can stay readable.
  const narrowLines = (t) => {
    const last = t[t.length - 1];
    if (t.length > 2 && /\$/.test(t[0][1]) && last[0].includes("d")) {
      const head = t.slice(0, -1).map(([c, s]) => [c, s]);
      head[head.length - 1][1] = head[head.length - 1][1].trimEnd();
      return [head, [["", "    "], last]].flatMap(wrap);
    }
    return wrap(t);
  };
  const len = (t) => t.reduce((n, [, s]) => n + s.length, 0);
  const BAR = { wide: 24, narrow: 10 };
  const barLen = (w) => (D.after ? 6 + w + 2 * String(D.after.total).length + 3 + D.after.label.length : 0);
  const stackLen = Math.max(D.command.length + 2, barLen(BAR.narrow), D.after ? D.after.note.length + 2 : 0, ...D.rows.flatMap((r) => narrowLines(r.t).map((t) => 1 + len(t))));

  const el = (tag, cls, text) => {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  };
  const words = (line, t) => {
    for (const [cls, s] of t) line.append(cls ? el("span", cls, s) : document.createTextNode(s));
  };
  const picture = (row) => {
    const c = el("canvas");
    c.width = D.w;
    c.height = 2;
    c.style.width = `${D.w * CW}em`;
    const g = c.getContext("2d");
    row.p.forEach((k, i) => {
      if (k < 0) return;
      g.fillStyle = D.palette[k];
      g.fillRect(i % D.w, Math.floor(i / D.w), 1, 1);
    });
    return c;
  };

  for (const root of document.querySelectorAll("[data-term]")) {
    const body = root.querySelector(".term-body");
    const replay = root.querySelector(".term-replay");
    const said = root.querySelector(".term-said");
    if (!body) continue;
    root.style.setProperty("--accent", D.accent || "#58d26c");
    if (said) said.textContent = [`$ ${D.command}`, ...D.rows.map((r) => r.t.map(([, s]) => s).join("")).filter((s) => s.trim())].join("\n");

    let timers = [];
    let side = null;
    let done = false;
    const at = (ms, fn) => timers.push(setTimeout(fn, ms));
    const stop = () => {
      timers.forEach(clearTimeout);
      timers = [];
    };

    // Side by side, as in a wide terminal; on a narrow screen the words go under the picture.
    const fit = () => {
      const w = body.clientWidth - 2 * parseFloat(getComputedStyle(body).paddingLeft);
      const wide = w / ((2 + D.w + 3 + textLen) * CW);
      const s = wide >= 10.5;
      const fs = s ? wide : w / ((Math.max(D.w + 2, stackLen) + 1) * CW);
      body.style.fontSize = `${Math.min(15, Math.max(7, fs))}px`;
      return s;
    };

    const build = () => {
      body.textContent = "";
      const lines = [];
      const add = (line) => (body.append(line), lines.push(line), line);
      const prompt = add(el("div", "tl"));
      prompt.append(el("span", "pr", "$ "));
      const cmd = prompt.appendChild(el("span", "cmd"));
      const cur = prompt.appendChild(el("span", "cur"));
      const out = [];
      if (side) {
        for (const r of D.rows) {
          const line = el("div", "tl wait");
          line.append("  ", picture(r), "   ");
          words(line, r.t);
          out.push(add(line));
        }
      } else {
        for (const r of D.rows) {
          const line = el("div", "tl wait");
          line.append(" ", picture(r));
          out.push(add(line));
        }
        const withText = D.rows.map((r, i) => (r.t.length ? i : -1)).filter((i) => i >= 0);
        out.push(add(el("div", "tl wait")));
        for (let i = withText[0]; i <= withText[withText.length - 1]; i++) {
          for (const t of narrowLines(D.rows[i].t)) {
            const line = el("div", "tl wait");
            line.append(" ");
            words(line, t);
            out.push(add(line));
          }
        }
      }
      let progress = null;
      if (D.after) {
        progress = add(el("div", "tl wait"));
        out.push(add(el("div", "tl wait d", `  ${D.after.note}`)));
      }
      const end = add(el("div", "tl wait"));
      end.append(el("span", "pr", "$ "), el("span", "cur"));
      return { cmd, cur, out, progress, end };
    };

    const bar = (n, total, i) => {
      const w = side ? BAR.wide : BAR.narrow;
      return `  ${i < 0 ? "✓" : SPIN[i % SPIN.length]} ${"█".repeat(Math.round((n / total) * w)).padEnd(w, "░")} ${n}/${total}  ${D.after.label}`;
    };

    const finish = (v) => {
      v.cmd.textContent = D.command;
      v.cur.remove();
      v.out.forEach((l) => l.classList.remove("wait"));
      if (v.progress) {
        v.progress.textContent = bar(D.after.total, D.after.total, -1);
        v.progress.classList.remove("wait");
      }
      v.end.classList.remove("wait");
      done = true;
      if (replay) replay.hidden = false;
    };

    const play = () => {
      stop();
      done = false;
      side = fit();
      const v = build();
      if (still) return finish(v);
      if (replay) replay.hidden = true;
      // Typing: a short pause, then each key at a human, slightly uneven pace.
      let t = 650;
      [...D.command].forEach((ch, i) => {
        t += 55 + ((i * 37) % 70);
        at(t, () => (v.cmd.textContent += ch));
      });
      t += 420;
      at(t, () => v.cur.remove());
      // The screen prints a line at a time, top to bottom.
      for (const line of v.out.slice(0, v.progress ? -1 : undefined)) {
        t += 55;
        at(t, () => line.classList.remove("wait"));
      }
      if (v.progress) {
        const steps = 28;
        t += 300;
        at(t, () => v.progress.classList.remove("wait"));
        for (let i = 0; i <= steps; i++) {
          at(t + i * 55, () => (v.progress.textContent = bar(Math.round((i / steps) * D.after.total), D.after.total, i)));
        }
        t += steps * 55 + 250;
        at(t, () => (v.progress.textContent = bar(D.after.total, D.after.total, -1)));
        t += 200;
        at(t, () => v.out[v.out.length - 1].classList.remove("wait"));
      }
      t += 350;
      at(t, () => finish(v));
    };

    side = fit();
    const first = build();
    if (still || !("IntersectionObserver" in window)) finish(first);
    else
      new IntersectionObserver((entries, obs) => {
        if (entries.some((e) => e.isIntersecting)) {
          obs.disconnect();
          play();
        }
      }, { threshold: 0.4 }).observe(root);
    replay?.addEventListener("click", play);

    // A resize that changes the layout redraws the finished screen; any other just rescales it.
    let raf = 0;
    addEventListener("resize", () => {
      cancelAnimationFrame(raf);
      raf = requestAnimationFrame(() => {
        const s = fit();
        if (s !== side && done) {
          side = s;
          finish(build());
        }
      });
    });
  }
})();
