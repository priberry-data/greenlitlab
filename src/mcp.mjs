// Greenlit as an MCP server (stdio, newline-delimited JSON-RPC), so an agent in Claude, Cursor or VS Code
// can grade the app it just deployed and apply the fix prompts itself.
import readline from "node:readline";
import { siteScan, compare } from "./grade.mjs";

const TOOLS = [
  {
    name: "greenlit_check",
    description:
      "Grade a deployed web app (built with Lovable, Bolt, v0, Replit, Emergent or by hand) A to F for what a stranger can use against it: secret keys shipped in its JavaScript, a Supabase service_role key in the browser, source maps, missing security headers. Every finding has a plain-English reason and a fix prompt. Reads only what the site serves to every visitor. Call it again after a fix: `change` shows what got fixed. For database checks on the user's own app, have them run `npx greenlitlab <url> --mine`.",
    inputSchema: { type: "object", properties: { url: { type: "string", description: "The app's address, for example myapp.lovable.app" } }, required: ["url"], additionalProperties: false },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
];

const last = new Map();

async function call(name, args = {}) {
  if (name !== "greenlit_check") throw new Error(`unknown tool ${name}`);
  const result = await siteScan(args.url, { mine: false });
  // Remembered for this session only, so a second call shows what the fixes changed.
  const change = compare(last.get(result.url), result);
  last.set(result.url, { at: new Date().toISOString(), score: result.score, grade: result.grade, findings: result.findings.map(({ id, severity, title }) => ({ id, severity, title })) });
  return { ...result, change };
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
