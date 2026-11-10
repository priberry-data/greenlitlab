// The public, dated report an owner chooses to publish, and its badge. A result is a fact about one day:
// both show the date, and after 30 days they say the result is out of date instead of showing a grade.
export const FRESH_DAYS = 30;
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const day = (iso) => new Date(iso).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" });
export const isFresh = (report, now = Date.now()) => now - new Date(report.at).getTime() < FRESH_DAYS * 86400e3;

// Only a host name: letters, digits, dots and dashes. Anything else never reaches storage or a page.
export const cleanHost = (h) => {
  const v = String(h || "").toLowerCase().replace(/\.svg$/, "");
  return /^[a-z0-9]([a-z0-9-]{0,62}\.)+([a-z]{2,24}|xn--[a-z0-9-]{2,59})$/.test(v) ? v : null;
};

// What is kept: the grade, the date, and each finding's level and title. Never keys, never the fix prompts.
// `host` is the address the owner asked about (the one in the report's own address), not where a redirect ended.
export const toReport = (result, host = new URL(result.url).host, at = new Date().toISOString()) => ({
  host,
  at,
  grade: result.grade,
  score: result.score,
  verdict: result.verdict,
  builder: result.builder,
  scripts: result.scripts,
  scriptsUnread: result.scriptsUnread || 0,
  findings: result.findings.map(({ severity, title }) => ({ severity, title })).slice(0, 60),
});

// The tag the owner adds to prove the app is theirs.
export const claimTag = (token) => `<meta name="greenlit" content="${token}">`;
// Only a real tag in the page's <head> counts. The same text inside a comment, a script, a text box or the body
// (where visitors' own words can end up) proves nothing.
export const hasClaim = (html, token) => {
  const head = String(html || "")
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<(script|style|textarea|template|noscript|title)\b[\s\S]*?<\/\1\s*>/gi, "")
    .split(/<\/head\s*>|<body\b/i)[0];
  // Each meta tag is read attribute by attribute, so unquoted values (as HTML minifiers write them) count.
  // Every tag is read whole, quotes included, so the tag's text inside any other tag's value is swallowed with it.
  for (const tag of head.match(/<[a-z][\w:-]*(?:[^>"']|"[^"]*"|'[^']*')*>/gi) || []) {
    if (!/^<meta[\s\/>]/i.test(tag)) continue;
    const attrs = {};
    for (const a of tag.matchAll(/([\w:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))/g)) attrs[a[1].toLowerCase()] = a[2] ?? a[3] ?? a[4];
    if (attrs.name === "greenlit" && attrs.content === token) return true;
  }
  return false;
};

// The tag for an app: made from a secret only the server holds, so nothing has to be stored to hand one out.
export async function claimToken(salt, host) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${salt}|${host}`));
  return [...new Uint8Array(digest)].slice(0, 10).map((b) => b.toString(16).padStart(2, "0")).join("");
}

const TONE = { A: "#0b9a47", B: "#0b9a47", C: "#b26a00", D: "#d32f24", F: "#d32f24", "?": "#6c726e" };

export function badgeSvg(report, now = Date.now()) {
  const fresh = report && isFresh(report, now);
  const right = !report ? "no report" : fresh ? `${report.grade} · ${day(report.at)}` : "out of date";
  const color = fresh ? TONE[report.grade] || TONE["?"] : "#6c726e";
  const w = 62 + right.length * 6.6 + 16;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${Math.round(w)}" height="22" role="img" aria-label="Greenlit: ${esc(right)}"><rect width="${Math.round(w)}" height="22" rx="5" fill="#0b0c0b"/><rect x="62" width="${Math.round(w - 62)}" height="22" rx="5" fill="${color}"/><rect x="62" width="6" height="22" fill="${color}"/><g font-family="Verdana,Geneva,sans-serif" font-size="11" fill="#fff"><text x="9" y="15">greenlit</text><text x="70" y="15">${esc(right)}</text></g></svg>`;
}

export function reportPage(report, host, now = Date.now()) {
  const head = (title) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${esc(title)}</title><meta name="robots" content="noindex"><link rel="icon" href="/icon.svg" type="image/svg+xml"><link rel="stylesheet" href="/style.css?v=0.4.0"></head><body><header class="top wrap"><a class="mark" href="/" aria-label="Greenlit home">greenl<span class="i">ı</span>t</a></header><main class="wrap block report">`;
  const foot = `</main><footer class="foot wrap"><span>An independent check by <a href="https://priberry.com">Priberry</a>. <a href="/">Check your own app</a></span></footer></body></html>`;
  if (!report) return `${head("No report · Greenlit")}<div class="card"><p class="r-verdict">No report has been published for ${esc(host)}.</p><p class="note">The owner of an app can publish one from <a href="/">greenlit.priberry.com</a>.</p></div>${foot}`;
  const fresh = isFresh(report, now);
  const graded = report.findings.filter((f) => f.severity !== "info");
  const notes = report.findings.filter((f) => f.severity === "info");
  const list = (items) => `<ul class="r-list">${items.map((f) => `<li><i class="dot ${esc(f.severity)}"></i><span>${esc(f.title)}</span><em>${esc(f.severity === "info" ? "note" : f.severity)}</em></li>`).join("")}</ul>`;
  return `${head(`${report.host} · Greenlit report`)}<div class="card">
<div class="r-head"><span class="grade ${fresh ? (report.grade === "?" ? "g-none" : `g-${esc(report.grade)}`) : "g-none"}">${fresh ? esc(report.grade) : "–"}</span><div><p class="r-verdict">${fresh ? esc(report.verdict) : "This result is out of date."}</p><p class="r-meta">${esc(report.host)} · checked ${esc(day(report.at))}${report.score == null ? "" : ` · ${esc(report.score)}/100`} · ${esc(report.scripts)} script${report.scripts === 1 ? "" : "s"} read${report.scriptsUnread ? `, ${esc(report.scriptsUnread)} not read` : ""}</p></div></div>
${fresh ? "" : `<p class="first">Greenlit results count for ${FRESH_DAYS} days, because apps change. This one was checked on ${esc(day(report.at))}; the owner needs to check again.</p>`}
${graded.length ? list(graded) : `<p class="ok">Nothing found in what Greenlit could see.</p>`}
${notes.length ? `<h3>Notes, and what this check could not see</h3>${list(notes)}` : ""}
<p class="note">What this means: on ${esc(day(report.at))}, Greenlit looked at what any visitor to ${esc(report.host)} can see, such as its code, headers and public settings. It did not sign in, did not test the database behind the app, and is not a security audit or a guarantee. The owner of this app turned on public reports by adding a Greenlit tag to it. Anyone can refresh this page's result, so it shows the latest check, good or bad. Removing the tag takes the report down.</p>
</div>${foot}`;
}
