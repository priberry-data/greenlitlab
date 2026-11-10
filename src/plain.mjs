// A list of findings as text a person reads in a terminal. Used by the advisor, scan and questions commands.
const wrap = (s, w, pad) => {
  const out = [];
  for (const para of String(s).split("\n")) {
    let line = "";
    for (const word of para.split(" ")) {
      if ((line + " " + word).trim().length > w) (out.push(pad + line.trim()), (line = word));
      else line += " " + word;
    }
    out.push(pad + line.trim());
  }
  return out.join("\n");
};

export function renderList(heading, findings, { color = true, pasteInto = "your AI app builder or coding agent", empty = "Nothing found.", footer = "" } = {}) {
  const k = (code) => (s) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
  const red = k("31"), green = k("32"), yellow = k("33"), dim = k("2"), bold = k("1"), cyan = k("36");
  const col = { critical: red, high: red, medium: yellow, low: dim, info: dim };
  const L = ["", bold(heading), ""];
  if (!findings.length) L.push(green(`  ${empty}`), "");
  let n = 0;
  for (const f of findings) {
    L.push(`${String(++n).padStart(2)}. ${col[f.severity](f.severity.toUpperCase().padEnd(8))} ${bold(f.title)}${f.where ? ` ${dim(`(${f.where})`)}` : ""}`);
    L.push(wrap(f.why, 88, "             "));
    if (f.first) L.push(wrap(`${yellow("Do this yourself first:")} ${f.first}`, 88, "             "));
    if (f.prompt) {
      L.push(`             ${cyan(`Then paste this into ${pasteInto}:`)}`);
      L.push(wrap(f.prompt, 84, `             ${dim("│")} `));
    }
    L.push("");
  }
  if (footer) L.push(dim(footer));
  return L.join("\n");
}
