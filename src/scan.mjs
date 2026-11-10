// greenlit scan [folder]: reads a project's own files, on your computer, for the launch mistakes that can't be
// seen from outside: rules that let everyone in, functions that skip the sign-in check, payment messages nobody
// verifies, secrets named so they ship to the browser. Node only. Reads names in .env files, never values.
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";

const SKIP = new Set(["node_modules", ".git", "dist", "build", ".next", ".vercel", ".netlify", ".wrangler", "coverage", ".turbo", ".cache", "vendor", "__pycache__", ".venv"]);
const TEXT = /\.(sql|toml|json|js|jsx|ts|tsx|mjs|cjs|py|vue|svelte)$|(^|\/)\.env[^/]*$/;
const PUBLIC_PREFIX = "(?:VITE_|NEXT_PUBLIC_|REACT_APP_|EXPO_PUBLIC_|PUBLIC_|NUXT_PUBLIC_)";
const SECRET_NAME = new RegExp(`\\b(${PUBLIC_PREFIX}[A-Z0-9_]*(?:SECRET|SERVICE_ROLE|PRIVATE_KEY|PASSWORD|WEBHOOK|DATABASE_URL)[A-Z0-9_]*)`, "g");

function walk(root, max = 5000) {
  const out = [];
  const stack = [root];
  while (stack.length && out.length < max) {
    const dir = stack.pop();
    let entries = [];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {}
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) !SKIP.has(e.name) && stack.push(full);
      else if (e.isFile() && TEXT.test(full.split(path.sep).join("/"))) out.push(full);
    }
  }
  return out;
}

const lineOf = (text, index) => text.slice(0, index).split("\n").length;
const bare = (name) => name.replace(/"/g, "").replace(/^public\./i, "").toLowerCase();

export function codeScan(dir = ".") {
  const root = path.resolve(dir);
  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) throw new Error(`"${dir}" isn't a folder`);
  const files = walk(root);
  const rel = (f) => path.relative(root, f).split(path.sep).join("/");
  const findings = [];
  const add = (f) => findings.some((x) => x.id === f.id) || findings.push(f);
  const created = new Map(); // table -> where it was created
  const protectedTables = new Set();

  for (const file of files) {
    const name = rel(file);
    let text = "";
    try {
      if (fs.statSync(file).size > 1024 * 1024) continue;
      text = fs.readFileSync(file, "utf8");
    } catch {
      continue;
    }
    const isEnv = /(^|\/)\.env[^/]*$/.test(name);

    // Names only: a secret behind a public prefix is copied into the code every visitor downloads.
    for (const m of text.matchAll(SECRET_NAME)) {
      if (isEnv && !new RegExp(`^\\s*(?:export\\s+)?${m[1]}\\s*=`, "m").test(text)) continue;
      add({ id: `scan:public-secret:${m[1]}`, severity: "critical", where: `${name}:${lineOf(text, m.index)}`, title: `The secret ${m[1]} is named so it ships to the browser`, why: "Anything whose name starts with a public prefix (VITE_, NEXT_PUBLIC_ and the like) is copied into the JavaScript every visitor downloads. A secret there is public.", fix: "Rename it without the public prefix and use it only in backend code.", first: "Treat this key as leaked if the app has ever been deployed with it: revoke it and make a new one.", prompt: `My project has a secret named ${m[1]}. The public prefix means it is built into the frontend, where anyone can read it. Rename it without the prefix, move every use of it into backend code (an edge function or server route) that checks the user is signed in, and confirm it no longer appears anywhere in the frontend build. List the files you changed.` });
    }
    if (isEnv) continue;

    if (name.endsWith(".sql")) {
      for (const m of text.matchAll(/create\s+table\s+(?:if\s+not\s+exists\s+)?((?:public\.)?"?[a-z_][\w]*"?)/gi)) if (!/^(auth|storage|pg_)/i.test(m[1])) created.has(bare(m[1])) || created.set(bare(m[1]), `${name}:${lineOf(text, m.index)}`);
      for (const m of text.matchAll(/alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?((?:public\.)?"?[a-z_][\w]*"?)\s+enable\s+row\s+level\s+security/gi)) protectedTables.add(bare(m[1]));
      for (const m of text.matchAll(/create\s+policy\s+[\s\S]*?;/gi)) {
        const stmt = m[0];
        if (!/(?:using|with\s+check)\s*\(\s*true\s*\)/i.test(stmt)) continue;
        const table = bare((stmt.match(/\bon\s+((?:[a-z_]\w*\.)?"?[a-z_]\w*"?)/i) || [, "a table"])[1]);
        const action = (stmt.match(/\bfor\s+(select|insert|update|delete|all)\b/i) || [, "all"])[1].toLowerCase();
        const toAuthed = /\bto\s+authenticated\b/i.test(stmt) && !/\banon\b/i.test(stmt);
        const readOnly = action === "select";
        add({ id: `scan:policy-true:${table}:${action}`, severity: readOnly ? "medium" : "high", where: `${name}:${lineOf(text, m.index)}`, title: readOnly ? `A rule lets ${toAuthed ? "every signed-in user" : "everyone"} read all of "${table}"` : `A rule lets ${toAuthed ? "every signed-in user" : "everyone"} ${action === "all" ? "read, change and delete" : action} rows in "${table}"`, why: `The policy's condition is simply "true", so Row Level Security is on but checks nothing for this action.${readOnly ? " That is fine for a public list such as products, and a leak for anything about people." : ""}`, fix: "Compare auth.uid() with the row's owner column instead of using true.", first: null, prompt: `In my database, a Row Level Security policy on "${table}" for ${action} uses the condition true, so ${toAuthed ? "any signed-in user" : "anyone"} passes it. Rewrite it so a user can only ${action === "all" ? "reach" : action} their own rows (auth.uid() = the owner column; add that column if it's missing). If "${table}" really is meant to be public to read, keep a read-only policy and make insert, update and delete owner-only. Write this as a new migration, don't edit old ones, and show me the SQL.` });
      }
      if (/(^|\/)migrations\//.test(name)) {
        const d = text.match(/^\s*(drop\s+table|truncate)\b[^;]*;/im);
        if (d) add({ id: `scan:destructive:${name}`, severity: "low", where: `${name}:${lineOf(text, d.index)}`, title: "A migration deletes data", why: `It contains "${d[0].trim().slice(0, 60)}". Run against the live database, that data is gone unless you have a backup.`, fix: "Make sure a backup exists before this runs on the live database.", first: null, prompt: `My migration ${name} contains a statement that deletes data (${d[1].toLowerCase()}). Tell me exactly what would be lost if it runs on the live database, whether that is intended, and how to back up that data first. Change nothing.` });
      }
    }

    if (/(^|\/)supabase\/config\.toml$/.test(name)) {
      for (const m of text.matchAll(/\[functions\.([\w-]+)\][^\[]*?verify_jwt\s*=\s*false/g))
        add({ id: `scan:verify-jwt:${m[1]}`, severity: "high", where: `${name}:${lineOf(text, m.index)}`, title: `The function "${m[1]}" skips the sign-in check`, why: "verify_jwt = false means anyone on the internet can call this function. That is right only for webhooks that check a signature themselves.", fix: "Remove verify_jwt = false, or verify a signature inside the function.", first: null, prompt: `My Supabase edge function "${m[1]}" has verify_jwt = false, so anyone can call it. If it is a webhook, make it verify the sender's signature before doing anything. Otherwise remove that setting and make the function check the signed-in user and what they are allowed to do. Show me what you changed.` });
    }

    if (/webhook/i.test(name) && /\.(js|ts|mjs|tsx|py)$/.test(name) && /stripe/i.test(text) && !/constructEvent|construct_event|stripe-signature/i.test(text))
      add({ id: `scan:webhook:${name}`, severity: "high", where: name, title: "Payment messages are accepted without checking who sent them", why: "This Stripe webhook handler never verifies the Stripe-Signature header, so anyone can send it a fake \"payment succeeded\" message.", fix: "Verify the signature with stripe.webhooks.constructEvent and the signing secret.", first: null, prompt: `My Stripe webhook handler in ${name} doesn't verify the Stripe-Signature header. Change it to read the raw request body and call stripe.webhooks.constructEvent (constructEventAsync on edge runtimes) with the signing secret from a server secret, reject anything that fails with a 400, and only then act on the event. Show me the change.` });

    if (/(^|\/)(\.mcp\.json|\.cursor\/mcp\.json|\.vscode\/mcp\.json)$/.test(name) && (/postgres(?:ql)?:\/\//i.test(text) || (/supabase/i.test(text) && !/read[-_]only/i.test(text))))
      add({ id: `scan:agent-db:${name}`, severity: "medium", where: name, title: "Your coding agent can change your database", why: "This agent configuration gives the AI a database connection that isn't read-only. An agent has deleted a production database this way.", fix: "Use the read-only mode, and point the agent at a development database.", first: null, prompt: `My agent configuration in ${name} gives you a database connection that can write. Tell me how to change it to read-only and scoped to a development project (for the Supabase MCP server: the read-only and project-ref options), and whether the live database is reachable with it today. Change nothing until I confirm.` });
  }

  if (files.some((f) => /(^|\/)supabase\//.test(rel(f))))
    for (const [table, where] of created)
      if (!protectedTables.has(table))
        add({ id: `scan:no-rls:${table}`, severity: "high", where, title: `The table "${table}" is created without Row Level Security`, why: "No migration turns Row Level Security on for it. If the app's public key can reach the table, every row is readable. (If you turned it on in the dashboard instead, the live database may be fine: check with npx greenlitlab <your app> --mine.)", fix: `Add: alter table public.${table} enable row level security; plus a policy for the owner.`, first: null, prompt: `My migrations create the table "${table}" but never enable Row Level Security on it. Write a new migration that enables it and adds policies so a signed-in user reaches only their own rows (auth.uid() = the owner column; add one if needed). If the table is meant to be public to read, say so and add a read-only policy. Show me the SQL.` });

  try {
    const tracked = execFileSync("git", ["-C", root, "ls-files"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).split("\n");
    const env = tracked.find((f) => /(^|\/)\.env(\.local|\.production)?$/.test(f));
    if (env) add({ id: "scan:env-tracked", severity: "high", where: env, title: `Your ${env} file is saved in version control`, why: "Everyone with access to the repository, now or later, has every key in it. If the repository is public, so does the world.", fix: "Remove it from git, add it to .gitignore, and replace the keys it held.", first: "Replace every key in that file: once committed, a key stays in the history.", prompt: `My ${env} file is tracked by git. Remove it from version control without deleting my local copy (git rm --cached), add it to .gitignore, and give me an .env.example with the names only. Then list every key that was in it so I can replace each one.` });
  } catch {}

  if (fs.existsSync(path.join(root, "package.json")) && !["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "bun.lock"].some((f) => fs.existsSync(path.join(root, f))))
    add({ id: "scan:no-lockfile", severity: "low", where: "package.json", title: "No lockfile", why: "Without a lockfile every build may install different versions of your dependencies, so the app you tested isn't the app you ship.", fix: "Commit the lockfile your package manager creates.", first: null, prompt: "My project has no lockfile. Run the install for the package manager this project uses, commit the lockfile it creates, and make the build use it." });

  const order = ["critical", "high", "medium", "low", "info"];
  findings.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
  return { source: "your project's files", dir: root, files: files.length, findings };
}
