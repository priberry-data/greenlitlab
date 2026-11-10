// The welcome screen: a signal on green beside a night road, drawn in the terminal with half-block
// characters, two pixels to a character cell. Shown only to a real terminal that is wide enough; never in
// pipes, CI, or with NO_COLOR, where the plain help is printed instead.

// --- a very small pixel painter ---------------------------------------------------------------------
const rgb = (hex) => [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16));
// 24-bit colour where the terminal says it has it; otherwise the nearest of the 216 colours every terminal has.
const colour = (hex, layer, truecolor) => {
  const [r, g, b] = rgb(hex);
  if (truecolor) return `${layer};2;${r};${g};${b}`;
  // Near-greys go to the 24-step grey ramp, so a dark grey stays grey instead of turning teal.
  if (Math.max(r, g, b) - Math.min(r, g, b) < 24) return `${layer};5;${232 + Math.max(0, Math.min(23, Math.round(((r + g + b) / 3 - 8) / 10)))}`;
  const q = (v) => (v < 48 ? 0 : v < 115 ? 1 : Math.min(5, Math.round((v - 35) / 40)));
  return `${layer};5;${16 + 36 * q(r) + 6 * q(g) + q(b)}`;
};

export const canvas = (w, h) => Array.from({ length: h }, () => Array(w).fill("."));
export const blit = (c, sprite, x, y) => {
  sprite.forEach((row, j) => [...row].forEach((ch, i) => ch !== "." && c[y + j]?.[x + i] !== undefined && (c[y + j][x + i] = ch)));
  return c;
};

// Each line of text holds two rows of pixels: the upper half-block takes the top pixel's colour as its
// foreground and the bottom pixel's as its background.
export function paint(c, palette, truecolor) {
  const lines = [];
  for (let y = 0; y < c.length; y += 2) {
    let line = "";
    for (let x = 0; x < c[0].length; x++) {
      const top = palette[c[y][x]];
      const bottom = palette[c[y + 1]?.[x]];
      if (!top && !bottom) line += "\x1b[0m ";
      else if (top && bottom) line += `\x1b[0;${colour(top, 38, truecolor)};${colour(bottom, 48, truecolor)}m▀`;
      else if (top) line += `\x1b[0;${colour(top, 38, truecolor)}m▀`;
      else line += `\x1b[0;${colour(bottom, 38, truecolor)}m▄`;
    }
    lines.push(`${line}\x1b[0m`);
  }
  return lines;
}

export const canShow = (stream, env, width) => Boolean(stream.isTTY && !env.NO_COLOR && !env.CI && env.TERM !== "dumb" && (stream.columns ?? 80) >= width);

// --- Greenlit's scene -------------------------------------------------------------------------------
const SIGNAL = [
  "....eeeeee....",
  "...ehhhhhhe...",
  "...hhrrrrhh...",
  "...hrrrrrrh...",
  "...hrrrrrrh...",
  "...hhrrrrhh...",
  "...hhhhhhhh...",
  "...hhaaaahh...",
  "...haaaaaah...",
  "...haaaaaah...",
  "...hhaaaahh...",
  "...hhhhhhhh...",
  "..GhhgggghhG..",
  ".GGhgLLggghGG.",
  ".GGhgLgggghGG.",
  "..GhhgggghhG..",
  "...hhhhhhhh...",
  "...ehhhhhhe...",
  "....eeppee....",
  "......pp......",
  "......pp......",
  "......pp......",
];
const PALETTE = { e: "#4a524c", h: "#262b27", r: "#5a2420", a: "#5c4716", g: "#3dff8a", L: "#d6ffe6", G: "#1a7a2e", p: "#3a403b", d: "#2f3430", m: "#6c726e", s: "#8b918d", S: "#f1f3f1" };

export function scene() {
  const c = canvas(26, 24);
  blit(c, SIGNAL, 1, 0);
  // The road: a kerb line and lane dashes running away to the right.
  for (let x = 0; x < 26; x++) c[22][x] = "d";
  for (const x of [15, 16, 17, 21, 22]) c[23][x] = "m";
  // A few stars, one of them bright.
  for (const [x, y, ch] of [[18, 2, "s"], [23, 5, "S"], [16, 9, "s"], [21, 13, "s"], [24, 17, "s"], [17, 18, "s"]]) c[y][x] = ch;
  return c;
}

export function welcome({ version = "", stream = process.stdout, env = process.env } = {}) {
  if (!canShow(stream, env, 90)) return "";
  const truecolor = /truecolor|24bit/i.test(env.COLORTERM ?? "");
  const art = paint(scene(), PALETTE, truecolor);
  // The words use the terminal's own text colours, so they read on a dark or a light background.
  const off = "\x1b[0m", bold = "\x1b[1m", faint = "\x1b[2m", go = "\x1b[32m";
  const cmd = (c, note) => `${go}$${off} ${c}${" ".repeat(Math.max(2, 34 - c.length))}${faint}${note}${off}`;
  const text = {
    2: `${bold}greenl${go}i${off}${bold}t${off}${version ? `  ${faint}v${version}${off}` : ""}`,
    3: "Know it's safe before you launch.",
    5: cmd("npx greenlitlab myapp.lovable.app", "grade your app"),
    6: cmd("npx greenlitlab <url> --mine", "your own app, deeper"),
    7: cmd("npx greenlitlab scan", "your project's files"),
    8: cmd("npx greenlitlab questions", "what only you know"),
    10: `${faint}--help for everything  ·  greenlit.priberry.com${off}`,
  };
  return ["", ...art.map((line, i) => `  ${line}   ${text[i] ?? ""}`.trimEnd()), ""].join("\n") + "\n";
}
