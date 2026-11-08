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
import { siteScan, compare, renderSite } from "../src/grade.mjs";
import { SEVERITY } from "../src/severity.mjs";
import { loadLast, saveRun } from "../src/history.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const { version: VERSION } = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));

const HELP = `greenlit ${VERSION}: is your AI-built app safe to launch?

  npx greenlitlab <url>                grade an app from what every visitor can see
  npx greenlitlab <url> --mine         your own app: also check which database tables anyone can read
  npx greenlitlab <url> --prompt 1     print just fix prompt 1, to copy (add | pbcopy on a Mac)
  npx greenlitlab <url> --json         the full result as JSON
  npx greenlitlab <url> --fail-on high exit 1 if anything this serious is found (for CI)
  npx greenlitlab mcp                  run as an MCP server

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
    result = await siteScan(target, { mine: opt.mine });
  } catch (e) {
    if (timer) (clearInterval(timer), process.stderr.write("\r\x1b[K"));
    console.error(`greenlit: ${e.message}`);
    process.exit(1);
  }
  if (timer) (clearInterval(timer), process.stderr.write("\r\x1b[K"));

  if (opt.prompt) {
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
}
