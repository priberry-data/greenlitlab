import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { welcome } from "../src/welcome.mjs";

const tty = (columns = 140) => ({ isTTY: true, columns });
const plain = (s) => s.replace(/\x1b\[[0-9;]*m/g, "");

test("welcome is drawn only for a real, wide, colour terminal", () => {
  assert.ok(welcome({ stream: tty(), env: {} }).includes("▀"));
  assert.equal(welcome({ stream: { isTTY: false }, env: {} }), "");
  assert.equal(welcome({ stream: tty(), env: { NO_COLOR: "1" } }), "");
  assert.equal(welcome({ stream: tty(), env: { CI: "true" } }), "");
  assert.equal(welcome({ stream: tty(), env: { TERM: "dumb" } }), "");
  assert.equal(welcome({ stream: tty(60), env: {} }), "");
});

test("welcome fits the width it asks for, at every width it accepts", () => {
  for (let columns = 80; columns <= 140; columns++) {
    const w = welcome({ version: "10.20.30", stream: tty(columns), env: {} });
    for (const line of w.split("\n")) assert.ok(plain(line).length <= columns, `line of ${plain(line).length} in ${columns} columns`);
  }
});

test("welcome uses 24-bit colour only when the terminal says so, and always resets", () => {
  const basic = welcome({ stream: tty(), env: {} });
  const rich = welcome({ stream: tty(), env: { COLORTERM: "truecolor" } });
  assert.ok(!/[34]8;2;/.test(basic) && /[34]8;5;/.test(basic));
  assert.ok(/[34]8;2;/.test(rich));
  for (const line of rich.split("\n").filter(Boolean)) assert.equal(line.match(/\x1b\[[0-9;]*m/g)?.at(-1) ?? "\x1b[0m", "\x1b[0m", "no line leaves a colour switched on");
  assert.ok(welcome({ version: "9.9.9", stream: tty(), env: {} }).includes("v9.9.9"));
});

test("piped, the command prints no pixel art", () => {
  const r = spawnSync(process.execPath, ["bin/greenlit.mjs"], { encoding: "utf8", env: { ...process.env, FORCE_COLOR: "", COLORTERM: "truecolor" } });
  assert.ok(!r.stdout.includes("▀") && !r.stdout.includes("▄"));
});
