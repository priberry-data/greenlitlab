// Greenlit as an MCP server (stdio, newline-delimited JSON-RPC), so an agent in Claude, Cursor or VS Code
// can grade the app it just deployed and apply the fix prompts itself.
import readline from "node:readline";
import { httpProbe } from "./node-probe.mjs";
import { siteScan, compare, allPrompts } from "./grade.mjs";

const TOOLS = [
  {
    name: "greenlit_check",
    description:
      "Grade a deployed web app (built with Lovable, Bolt, v0, Replit, Emergent or by hand) A to F for what a stranger can use against it: secret keys shipped in its JavaScript (Stripe, OpenAI, OpenRouter, Supabase secret keys and 28 more kinds), a Supabase service_role key in the browser, source maps, clickjacking and missing security headers, plus launch basics (developer-only addresses, Stripe test mode, a test email sender, no https redirect, open CORS, missing DMARC on a custom domain). Every finding has a plain-English reason and a fix prompt; `allFixes` has every fix in one prompt, worst first. Reads only what the site serves to every visitor. Call it again after a fix: `change` shows what got fixed. For the user's own app, have them run `npx greenlitlab <url> --mine`: it also checks which database tables and storage buckets anyone can read, open sign-up, and public .env or .git files.",
    inputSchema: { type: "object", properties: { url: { type: "string", description: "The app's address, for example myapp.lovable.app" } }, required: ["url"], additionalProperties: false },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
  {
    name: "greenlit_scan",
    description:
      "Read a project folder on this computer for launch mistakes that can't be seen from outside, before deploying: Row Level Security policies whose condition is just `true`, tables created without RLS, Supabase edge functions with verify_jwt = false, Stripe webhook handlers that never verify the signature, secrets behind a public prefix (VITE_, NEXT_PUBLIC_), a tracked .env file, and an agent config with a writable database connection. Pattern-based, not a full code review. Reads names in .env files, never values. Each finding has a fix prompt.",
    inputSchema: { type: "object", properties: { dir: { type: "string", description: "The project folder. Defaults to the current folder." } }, additionalProperties: false },
    annotations: { readOnlyHint: true },
  },
  {
    name: "greenlit_advisor",
    description:
      "Turn Supabase's Security or Performance Advisor results into plain-English findings with a fix prompt for each, worst first. Get the results from the Supabase MCP server's get_advisors tool (type \"security\") for the user's project, then pass them here as `lints`. This is the reliable way to learn which rules are too loose and whether strangers can change or delete data, which no outside check can see.",
    inputSchema: { type: "object", properties: { lints: { description: "The advisor output: a list of lints, or the object that contains one." } }, required: ["lints"], additionalProperties: false },
    annotations: { readOnlyHint: true },
  },
  {
    name: "greenlit_questions",
    description:
      "Seven launch questions only the app's owner can answer (backups and restore, separate test database, hard spending limits, payment webhook checks, outage alerts, email sender, database plan). Call with no arguments to get the questions and options to ask the user. Call with `answers` ({questionId: optionKey}) to get, for each gap, the fact that makes it matter and a fix prompt. Answers are the owner's word, never graded.",
    inputSchema: { type: "object", properties: { answers: { type: "object", description: "For example {\"backup\": \"no\", \"spend\": \"alerts\"}" } }, additionalProperties: false },
    annotations: { readOnlyHint: true },
  },
];

const last = new Map();

async function call(name, args = {}) {
  if (name === "greenlit_scan") return (await import("./scan.mjs")).codeScan(args.dir || ".");
  if (name === "greenlit_advisor") return (await import("./advisor.mjs")).fromAdvisor(args.lints);
  if (name === "greenlit_questions") {
    const { QUESTIONS, advise } = await import("./questions.mjs");
    return args.answers ? { told: advise(args.answers), note: "The owner's own answers. Greenlit did not check them, and they don't change the app's grade." } : { questions: QUESTIONS };
  }
  if (name !== "greenlit_check") throw new Error(`unknown tool ${name}`);
  const result = await siteScan(args.url, { mine: false, httpProbe });
  // Remembered for this session only, so a second call shows what the fixes changed.
  const change = compare(last.get(result.url), result);
  last.set(result.url, { at: new Date().toISOString(), score: result.score, grade: result.grade, findings: result.findings.map(({ id, severity, title }) => ({ id, severity, title })) });
  return { ...result, change, allFixes: allPrompts(result) };
}

export function serve({ version, input = process.stdin, output = process.stdout } = {}) {
  const send = (msg) => output.write(JSON.stringify({ jsonrpc: "2.0", ...msg }) + "\n");
  const rl = readline.createInterface({ input, crlfDelay: Infinity });
  const pending = new Set();
  rl.on("line", (line) => {
    const job = handle(line).finally(() => pending.delete(job));
    pending.add(job);
  });
  async function handle(line) {
    let m;
    try {
      m = JSON.parse(line);
    } catch {
      return send({ id: null, error: { code: -32700, message: "parse error" } });
    }
    if (m.id === undefined) return;
    if (m.method === "initialize")
      return send({ id: m.id, result: { protocolVersion: m.params?.protocolVersion || "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "greenlit", version } } });
    if (m.method === "ping") return send({ id: m.id, result: {} });
    if (m.method === "tools/list") return send({ id: m.id, result: { tools: TOOLS } });
    if (m.method === "tools/call") {
      try {
        const r = await call(m.params?.name, m.params?.arguments);
        return send({ id: m.id, result: { content: [{ type: "text", text: JSON.stringify(r, null, 2) }], structuredContent: r } });
      } catch (e) {
        return send({ id: m.id, result: { content: [{ type: "text", text: `greenlit: ${e.message}` }], isError: true } });
      }
    }
    send({ id: m.id, error: { code: -32601, message: `method not found: ${m.method}` } });
  }
  // Let a check still running answer before the server exits.
  return new Promise((resolve) => rl.on("close", () => Promise.allSettled([...pending]).then(resolve)));
}
