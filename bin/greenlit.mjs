#!/usr/bin/env node
// greenlit: is your AI-built app safe to launch? A grade from A to F, plain-English reasons, and a prompt
// to paste back into Lovable, Bolt, v0, Replit or Emergent that fixes each problem.
//   greenlit <url>            grade a deployed app from what every visitor can see
//   greenlit <url> --mine     also check your own database (counts and names only, never data)
//   greenlit mcp              run as an MCP server for Claude, Cursor, VS Code and other agents
import fs from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";
import { fileURLToPath } from "node:url";
import { httpProbe } from "../src/node-probe.mjs";
import { siteScan, compare, renderSite, allPrompts, explainError } from "../src/grade.mjs";
import { SEVERITY } from "../src/severity.mjs";
import { loadLast, saveRun } from "../src/history.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const { version: VERSION } = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));

const HELP = `greenlit ${VERSION}: is your AI-built app safe to launch?

  npx greenlitlab <url>                grade an app from what every visitor can see
  npx greenlitlab <url> --mine         your own app: also check which database tables anyone can read
  npx greenlitlab <url> --prompt 1     print just fix prompt 1, to copy (add | pbcopy on a Mac)
  npx greenlitlab <url> --prompt all   every fix in one prompt, worst first
  npx greenlitlab <url> --json         the full result as JSON
  npx greenlitlab <url> --fail-on high exit 1 if anything this serious is found (for CI)
  npx greenlitlab mcp                  run as an MCP server

Before you launch, three more that look where no outside check can:
  npx greenlitlab questions            seven things only you know (backups, spending limits, email)
  npx greenlitlab scan [folder]        read your project's files for rules that let everyone in
  npx greenlitlab advisor results.json Supabase's own Security Advisor, in plain words with fix prompts

Run it again after a fix: it shows what got fixed. In the browser: https://greenlit.priberry.com`;

let opt, positionals;
try {
  ({ values: opt, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      mine: { type: "boolean" },
      prompt: { type: "string" },
      json: { type: "boolean" },
      "fail-on": { type: "string" },
      version: { type: "boolean", short: "v" },
      help: { type: "boolean", short: "h" },
    },
  }));
} catch (e) {
  console.error(`greenlit: ${e.message}\n\n${HELP}`);
  process.exit(2);
}

if (opt.version) {
  console.log(VERSION);
} else if (opt.help || !positionals[0]) {
  console.log(HELP);
} else if (positionals[0] === "mcp") {
  const { serve } = await import("../src/mcp.mjs");
  await serve({ version: VERSION });
} else if (["scan", "advisor", "questions"].includes(positionals[0])) {
  const color = Boolean(process.stdout.isTTY && !process.env.NO_COLOR);
  const { renderList } = await import("../src/plain.mjs");
  const failOn = opt["fail-on"];
  if (failOn && !(failOn in SEVERITY)) {
    console.error(`greenlit: --fail-on takes ${Object.keys(SEVERITY).join(", ")}`);
    process.exit(2);
  }
  const finish = (r, heading, extra) => {
    if (opt.json) console.log(JSON.stringify(r, null, 2));
    else console.log(renderList(heading, r.findings, { color, ...extra }));
    if (failOn && r.findings.some((f) => SEVERITY[f.severity] >= SEVERITY[failOn])) process.exitCode = 1;
  };
  try {
    if (positionals[0] === "scan") {
      const { codeScan } = await import("../src/scan.mjs");
      const r = codeScan(positionals[1] || ".");
      finish(r, `Greenlit scan · ${r.dir} · ${r.files} files read`, { empty: "Nothing found in the patterns Greenlit knows. This is not a full code review.", footer: "Read on your computer; nothing was sent anywhere. Names in .env files were read, never values.\nThis finds known mistakes by pattern. It can't see the live database: for that, run npx greenlitlab <your app> --mine" });
    } else if (positionals[0] === "advisor") {
      const { fromAdvisor, ADVISOR_HOW } = await import("../src/advisor.mjs");
      const file = positionals[1];
      if (!file && process.stdin.isTTY) {
        console.log(`greenlit advisor: Supabase's Security Advisor, in plain words.\n\n${ADVISOR_HOW}`);
        process.exit(2);
      }
      const r = fromAdvisor(fs.readFileSync(!file || file === "-" ? 0 : file, "utf8"));
      finish(r, `Supabase advisor · ${r.lints - r.skipped} result${r.lints - r.skipped === 1 ? "" : "s"}, in plain words${r.skipped ? ` (${r.skipped} unreadable item${r.skipped === 1 ? "" : "s"} skipped)` : ""}`, { empty: "The advisor reported nothing.", footer: "These come from Supabase's own advisor. Greenlit translated them and wrote the prompts; it did not check them itself." });
    } else {
      const { QUESTIONS, advise } = await import("../src/questions.mjs");
      if (opt.json) console.log(JSON.stringify(QUESTIONS, null, 2));
      else if (!process.stdin.isTTY) console.log(QUESTIONS.map((q, i) => `${i + 1}. ${q.ask}\n${q.options.map((o, j) => `     ${String.fromCharCode(97 + j)}) ${o.label}`).join("\n")}`).join("\n\n"));
      else {
        const readline = await import("node:readline/promises");
        const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
        console.log("\nSeven things only you know. No check can see these, so Greenlit asks. Nothing you answer is sent anywhere.\n");
        const answers = {};
        for (const [i, q] of QUESTIONS.entries()) {
          console.log(`${i + 1}. ${q.ask}`);
          q.options.forEach((o, j) => console.log(`     ${j + 1}) ${o.label}`));
          const pick = Number((await rl.question("   Your answer (number, or Enter to skip): ")).trim());
          if (q.options[pick - 1]) answers[q.id] = q.options[pick - 1].key;
          console.log("");
        }
        rl.close();
        const todo = advise(answers).filter((a) => a.ok === false);
        const skipped = advise(answers).filter((a) => a.ok === null).length;
        console.log(renderList(`You told us · ${7 - todo.length - skipped} of 7 in place${skipped ? `, ${skipped} skipped` : ""}`, todo.map((a) => ({ severity: "medium", title: a.ask, where: `you said: ${a.answer}`, why: a.note, prompt: a.prompt })), { color, empty: "Everything you answered is in place.", footer: "These are your answers, not something Greenlit checked, so they don't change your app's grade." }));
      }
    }
  } catch (e) {
    console.error(`greenlit: ${e.message}`);
    process.exit(1);
  }
} else {
  if (opt["fail-on"] && !(opt["fail-on"] in SEVERITY)) {
    console.error(`greenlit: --fail-on takes ${Object.keys(SEVERITY).join(", ")}`);
    process.exit(2);
  }
  const target = positionals[0];
  const quiet = opt.json || opt.prompt || !process.stderr.isTTY;
  const frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
  let i = 0;
  const timer = quiet ? null : setInterval(() => process.stderr.write(`\r${frames[i++ % frames.length]} looking at ${target} the way a stranger would`), 80);
  let result;
  try {
    result = await siteScan(target, { mine: opt.mine, httpProbe });
  } catch (e) {
    if (timer) (clearInterval(timer), process.stderr.write("\r\x1b[K"));
    console.error(`greenlit: ${explainError(e.message)}`);
    process.exit(1);
  }
  if (timer) (clearInterval(timer), process.stderr.write("\r\x1b[K"));

  if (opt.prompt === "all") {
    const all = allPrompts(result);
    if (!all) {
      console.error("greenlit: nothing to fix here.");
      process.exit(2);
    }
    console.log(all);
  } else if (opt.prompt) {
    const withPrompt = result.findings.filter((f) => f.prompt);
    const p = withPrompt[Number(opt.prompt) - 1];
    if (!p) {
      console.error(`greenlit: there is no fix prompt ${opt.prompt}; this check has ${withPrompt.length}.`);
      process.exit(2);
    }
    console.log(p.prompt);
  } else {
    const change = compare(loadLast(result.url, result.mine), result);
    saveRun(result);
    if (opt.json) console.log(JSON.stringify({ ...result, change }, null, 2));
    else console.log(renderSite(result, change, { color: Boolean(process.stdout.isTTY && !process.env.NO_COLOR) }));
  }
  if (opt["fail-on"] && result.findings.some((f) => SEVERITY[f.severity] >= SEVERITY[opt["fail-on"]])) process.exitCode = 1;
  // "Nothing found" in code that couldn't be read is not a pass.
  else if (opt["fail-on"] && result.grade === "?") {
    console.error("greenlit: this app's code couldn't be read, so there is nothing to pass. Exiting with 3.");
    process.exitCode = 3;
  }
}
