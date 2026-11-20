// Small touches only. Everything on the page is readable with this script off.
const still = matchMedia("(prefers-reduced-motion: reduce)").matches;

// The clock in the status bar.
const clock = document.getElementById("clock");
const tick = () => { clock.textContent = new Date().toTimeString().slice(0, 8); };
tick();
setInterval(tick, 1000);

// Number keys jump between windows, like function keys on an old terminal.
const keys = { 1: "patterns", 2: "guard", 3: "prompts", 4: "limits", 5: "faq", 6: "start" };
addEventListener("keydown", (e) => {
  if (e.metaKey || e.ctrlKey || e.altKey || /input|textarea|select/i.test(e.target.tagName)) return;
  const id = keys[e.key];
  if (!id) return;
  document.getElementById(id).scrollIntoView({ behavior: still ? "auto" : "smooth" });
  history.replaceState(null, "", "#" + id);
});

// Copy buttons: after every command, and on the email address.
const copy = async (text, button) => {
  const label = button.textContent;
  try {
    await navigator.clipboard.writeText(text);
    button.textContent = label.includes("[") ? label.replace(/copy\w*/, "copied") : "copied";
  } catch {
    button.textContent = "select and copy";
  }
  setTimeout(() => { button.textContent = label; }, 1400);
};
for (const el of document.querySelectorAll("[data-copy]")) {
  const b = document.createElement("button");
  b.type = "button";
  b.className = "copy";
  b.textContent = "copy";
  b.setAttribute("aria-label", `copy ${el.textContent}`);
  b.addEventListener("click", () => copy(el.textContent, b));
  el.after(b);
}
for (const b of document.querySelectorAll("[data-copy-text]")) {
  b.hidden = false;
  b.addEventListener("click", () => copy(b.dataset.copyText, b));
}

// The sample run prints line by line the first time it scrolls into view, then offers a replay.
const run = document.getElementById("run");
const replay = document.querySelector(".replay");
if (!still && run && "IntersectionObserver" in window) {
  run.innerHTML = run.innerHTML.split("\n").map((l) => `<span class="ln">${l || " "}</span>`).join("\n");
  const lines = [...run.querySelectorAll(".ln")];
  let timers = [];
  const play = () => {
    timers.forEach(clearTimeout);
    timers = [];
    run.classList.add("typing");
    lines.forEach((l) => l.classList.remove("on"));
    let t = 0;
    for (const l of lines) {
      const text = l.textContent;
      // Commands take a moment to "type", results land fast, and a score line pauses before it appears.
      t += text.startsWith("$") ? 700 : /BLOCKED|CLEAR/.test(text) ? 600 : 90;
      timers.push(setTimeout(() => l.classList.add("on"), t));
    }
    timers.push(setTimeout(() => { run.classList.remove("typing"); replay.hidden = false; }, t + 50));
  };
  new IntersectionObserver((entries, obs) => {
    if (entries.some((e) => e.isIntersecting)) { obs.disconnect(); play(); }
  }, { threshold: 0.35 }).observe(run);
  replay.addEventListener("click", play);
}
