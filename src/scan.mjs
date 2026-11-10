// greenlit scan [folder]: reads a project's own files, on your computer, for the launch mistakes that can't be
// seen from outside: rules that let everyone in, functions that skip the sign-in check, payment messages nobody
// verifies, secrets named so they ship to the browser. Node only. Reads names in .env files, never values.
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";

// Build output, dependencies, agents' working copies, and tests (whose made-up secrets and tables aren't the app's).
const SKIP = new Set(["node_modules", ".claude", "worktrees", "__tests__", "__mocks__", "__fixtures__", "fixtures", "test", "tests", "e2e", "cypress", ".git", "dist", "build", ".next", ".vercel", ".netlify", ".wrangler", "coverage", ".turbo", ".cache", "vendor", "__pycache__", ".venv"]);
const TEXT = /\.(sql|toml|json|js|jsx|ts|tsx|mjs|cjs|py|vue|svelte)$|(^|\/)\.env[^/]*$/;
const PUBLIC_PREFIX = "(?:VITE_|NEXT_PUBLIC_|REACT_APP_|EXPO_PUBLIC_|PUBLIC_|NUXT_PUBLIC_)";
// The name must END in the secret word (or _KEY/_TOKEN after it): VITE_STRIPE_SECRET_KEY is a secret,
// VITE_PASSWORD_MIN_LENGTH and VITE_WEBHOOK_URL are settings.
const SECRET_NAME = new RegExp(`\\b(${PUBLIC_PREFIX}[A-Z0-9_]*?(?:SECRET(?:_KEY|_TOKEN)?|SERVICE_ROLE(?:_KEY)?|PRIVATE_KEY|PASSWORD|DATABASE_URL))(?![A-Z0-9_])`, "g");
// A key for a paid service behind a public prefix (VITE_OPENAI_API_KEY) is the same mistake under another name.
const PAID_KEY_NAME = new RegExp(`\\b(${PUBLIC_PREFIX}[A-Z0-9_]*?(?:OPENAI|ANTHROPIC|CLAUDE|GEMINI|GROQ|OPENROUTER|MISTRAL|PERPLEXITY|REPLICATE|HUGGINGFACE|RESEND|SENDGRID|MAILGUN|TWILIO|GITHUB)[A-Z0-9_]*?(?:KEY|TOKEN))(?![A-Z0-9_])`, "g");
// A table or policy target the way SQL writes it: orders, public.orders, "public"."orders".
const IDENT = String.raw`(?:"?(\w+)"?\s*\.\s*)?"?(\w+)"?`;
// Comments blanked out, keeping every character's position so line numbers stay right.
// Text inside single quotes is blanked too: it is data or SQL run later, not a statement in this file.
// Double-quoted names are matched first and kept as they are, so an apostrophe in a policy's name ("Users can't …") starts nothing.
const noComments = (sql) => sql.replace(/"(?:[^"]|"")*"|'(?:[^']|'')*'|\/\*[\s\S]*?\*\/|--[^\n]*/g, (m) => (m[0] === '"' ? m : m[0] === "'" ? `'${m.slice(1, -1).replace(/[^\n]/g, " ")}'` : m.replace(/[^\n]/g, " ")));

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

export function codeScan(dir = ".") {
  const root = path.resolve(dir);
  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) throw new Error(`"${dir}" isn't a folder`);
  const files = walk(root);
  const rel = (f) => path.relative(root, f).split(path.sep).join("/");
  const findings = [];
  const add = (f) => findings.some((x) => x.id === f.id) || findings.push(f);
  const created = new Map(); // table -> where it was created
  const protectedTables = new Set();
  const publicRead = { everyone: [], "every signed-in user": [] };
  let dynamicRls = false;

  for (const file of files) {
    const name = rel(file);
    let text = "";
    try {
      if (fs.statSync(file).size > 1024 * 1024) continue;
      text = fs.readFileSync(file, "utf8");
    } catch {
      continue;
    }
    if (/\.(test|spec)\.[a-z]+$/i.test(name)) continue;
    const isEnv = /(^|\/)\.env[^/]*$/.test(name);

    // Names only: a secret behind a public prefix is copied into the code every visitor downloads.
    for (const m of [...text.matchAll(SECRET_NAME), ...text.matchAll(PAID_KEY_NAME)]) {
      if (isEnv && !new RegExp(`^\\s*(?:export\\s+)?${m[1]}\\s*=`, "m").test(text)) continue;
      add({ id: `scan:public-secret:${m[1]}`, severity: "critical", where: `${name}:${lineOf(text, m.index)}`, title: `The secret ${m[1]} is named so it ships to the browser`, why: "Anything whose name starts with a public prefix (VITE_, NEXT_PUBLIC_ and the like) is copied into the JavaScript every visitor downloads. A secret there is public.", fix: "Rename it without the public prefix and use it only in backend code.", first: "Treat this key as leaked if the app has ever been deployed with it: revoke it and make a new one.", prompt: `My project has a secret named ${m[1]}. The public prefix means it is built into the frontend, where anyone can read it. Rename it without the prefix, move every use of it into backend code (an edge function or server route) that checks the user is signed in, and confirm it no longer appears anywhere in the frontend build. List the files you changed.` });
    }
    if (isEnv) continue;

    if (name.endsWith(".sql")) {
      const sql = noComments(text);
      // Protection switched on in a loop: foreach t in array['a','b'] loop execute format('alter table … enable row level security', t).
      // The names are inside quotes, so they are read from the file as written.
      for (const m of text.matchAll(/foreach\s+\w+\s+in\s+array\s+(?:array\s*)?\[([^\]]*)\]\s*loop([\s\S]*?)end\s+loop/gi))
        if (/enable\s+row\s+level\s+security/i.test(m[2])) for (const n of m[1].matchAll(/'([\w.]+)'/g)) protectedTables.add(n[1].replace(/^public\./i, "").toLowerCase());
      // Any other statement built at run time that turns it on: the tables it covers can't be known from the file.
      if (/execute\b[\s\S]{0,300}?enable\s+row\s+level\s+security/i.test(text)) dynamicRls = true;
      for (const m of sql.matchAll(new RegExp(String.raw`create\s+(?:unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?${IDENT}`, "gi"))) {
        // Only the public schema is reachable with the app's public key.
        if ((m[1] || "public").toLowerCase() !== "public") continue;
        const table = m[2].toLowerCase();
        created.has(table) || created.set(table, `${name}:${lineOf(sql, m.index)}`);
      }
      for (const m of sql.matchAll(new RegExp(String.raw`alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?${IDENT}\s+enable\s+row\s+level\s+security`, "gi"))) if ((m[1] || "public").toLowerCase() === "public") protectedTables.add(m[2].toLowerCase());
      // The policy's own name is skipped first: it is free text and often contains the word "on".
      for (const m of sql.matchAll(new RegExp(String.raw`create\s+policy\s+(?:"[^"]*"|\w+)\s+on\s+${IDENT}([^;]*);`, "gi"))) {
        const rest = m[3];
        if (!/(?:using|with\s+check)\s*\(+\s*true\s*\)+/i.test(rest)) continue;
        // Policies in a private schema open nothing to the app's public key; storage is named in full.
        const schema = (m[1] || "public").toLowerCase();
        if (schema !== "public" && schema !== "storage") continue;
        const roles = (rest.match(/\bto\s+([\w\s,"]+?)(?=\s+(?:using|with)\b|$)/i) || [, ""])[1].toLowerCase();
        // The service role skips every rule anyway; a policy for it alone opens nothing.
        if (/service_role/.test(roles) && !/anon|authenticated|public/.test(roles)) continue;
        const table = schema === "public" ? m[2].toLowerCase() : `${schema}.${m[2].toLowerCase()}`;
        const action = (rest.match(/\bfor\s+(select|insert|update|delete|all)\b/i) || [, "all"])[1].toLowerCase();
        const toAuthed = /authenticated/.test(roles) && !/anon|public/.test(roles);
        const who = toAuthed ? "every signed-in user" : "everyone";
        const where = `${name}:${lineOf(sql, m.index)}`;
        // Reading a whole table is often meant (products, courses), so those are gathered into one question below.
        if (action === "select") {
          publicRead[who].some((t) => t.table === table) || publicRead[who].push({ table, where });
          continue;
        }
        // Adding rows is right for a contact form, a waitlist or a log. Changing and deleting rarely is.
        const addOnly = action === "insert";
        add({ id: `scan:policy-true:${table}:${action}`, severity: addOnly ? "medium" : "high", where, title: `A rule lets ${who} ${action === "all" ? "read, change and delete" : addOnly ? "add" : action} rows in "${table}"`, why: `The policy's condition is simply "true", so Row Level Security is on but checks nothing for this action.${addOnly ? " That is right for a contact form, a waitlist or a log, and a problem if anything in the app trusts what is in this table." : ""}`, fix: "Compare auth.uid() with the row's owner column instead of using true.", first: null, prompt: `In my database, a Row Level Security policy on "${table}" for ${action} uses the condition true, so ${toAuthed ? "any signed-in user" : "anyone"} passes it. ${addOnly ? `Tell me first whether "${table}" is meant to take rows from ${toAuthed ? "any signed-in user" : "strangers"} (a form, a waitlist, a log). If it is, keep it but make sure the new row can't claim to belong to someone else (set the owner column from auth.uid(), never from the request) and can't be flooded. If it isn't, rewrite` : "Rewrite"} it so a user can only ${action === "all" ? "reach" : action} their own rows (auth.uid() = the owner column; add that column if it's missing). Write this as a new migration, don't edit old ones, and show me the SQL.` });
      }
      if (/(^|\/)migrations\//.test(name)) {
        const d = sql.match(/^\s*(drop\s+table|truncate)\b[^;]*;/im);
        if (d) add({ id: `scan:destructive:${name}`, severity: "low", where: `${name}:${lineOf(sql, d.index)}`, title: "A migration deletes data", why: `It contains "${d[0].trim().slice(0, 60)}". Run against the live database, that data is gone unless you have a backup.`, fix: "Make sure a backup exists before this runs on the live database.", first: null, prompt: `My migration ${name} contains a statement that deletes data (${d[1].toLowerCase()}). Tell me exactly what would be lost if it runs on the live database, whether that is intended, and how to back up that data first. Change nothing.` });
      }
    }

    if (/(^|\/)supabase\/config\.toml$/.test(name)) {
      for (const m of text.matchAll(/\[functions\.([\w-]+)\][^\[]*?verify_jwt\s*=\s*false/g))
        add({ id: `scan:verify-jwt:${m[1]}`, severity: "high", where: `${name}:${lineOf(text, m.index)}`, title: `The function "${m[1]}" skips the sign-in check`, why: "verify_jwt = false means anyone on the internet can call this function. That is right only for webhooks that check a signature themselves.", fix: "Remove verify_jwt = false, or verify a signature inside the function.", first: null, prompt: `My Supabase edge function "${m[1]}" has verify_jwt = false, so anyone can call it. If it is a webhook, make it verify the sender's signature before doing anything. Otherwise remove that setting and make the function check the signed-in user and what they are allowed to do. Show me what you changed.` });
    }

    if (/webhook/i.test(name) && /\.(js|ts|mjs|tsx|py)$/.test(name) && /stripe/i.test(text) && !/constructEvent|construct_event|stripe-signature/i.test(text))
      add({ id: `scan:webhook:${name}`, severity: "medium", where: name, title: "Greenlit couldn't see a signature check in this payment webhook", why: "This file handles Stripe messages but never mentions the Stripe-Signature header or constructEvent. If the check isn't done in another file it calls, anyone can send a fake \"payment succeeded\" message.", fix: "Verify the signature with stripe.webhooks.constructEvent and the signing secret.", first: null, prompt: `My Stripe webhook handler in ${name} doesn't verify the Stripe-Signature header. Change it to read the raw request body and call stripe.webhooks.constructEvent (constructEventAsync on edge runtimes) with the signing secret from a server secret, reject anything that fails with a 400, and only then act on the event. Show me the change.` });

    if (/(^|\/)(\.mcp\.json|\.cursor\/mcp\.json|\.vscode\/mcp\.json)$/.test(name) && (/postgres(?:ql)?:\/\//i.test(text) || (/supabase/i.test(text) && !/read[-_]only/i.test(text))))
      add({ id: `scan:agent-db:${name}`, severity: "medium", where: name, title: "Your coding agent can change your database", why: "This agent configuration gives the AI a database connection that isn't read-only. An agent has deleted a production database this way.", fix: "Use the read-only mode, and point the agent at a development database.", first: null, prompt: `My agent configuration in ${name} gives you a database connection that can write. Tell me how to change it to read-only and scoped to a development project (for the Supabase MCP server: the read-only and project-ref options), and whether the live database is reachable with it today. Change nothing until I confirm.` });
  }

  if (files.some((f) => /(^|\/)supabase\//.test(rel(f))))
    for (const [table, where] of created)
      if (!protectedTables.has(table) && dynamicRls)
        add({ id: `scan:no-rls:${table}`, severity: "medium", where, title: `Greenlit couldn't see Row Level Security being turned on for "${table}"`, why: "Your migrations switch it on for some tables with a statement built while it runs, and Greenlit can't tell which tables that covers. This one may be protected.", fix: "Check it in Supabase → Advisors → Security Advisor, or run npx greenlitlab <your app> --mine.", first: null, prompt: `Tell me whether Row Level Security is enabled on the table "${table}" in my database, and which statement enables it. Change nothing.` });
      else if (!protectedTables.has(table))
        add({ id: `scan:no-rls:${table}`, severity: "high", where, title: `The table "${table}" is created without Row Level Security`, why: "No migration turns Row Level Security on for it. If the app's public key can reach the table, every row is readable. (If you turned it on in the dashboard instead, the live database may be fine: check with npx greenlitlab <your app> --mine.)", fix: `Add: alter table public.${table} enable row level security; plus a policy for the owner.`, first: null, prompt: `My migrations create the table "${table}" but never enable Row Level Security on it. Write a new migration that enables it and adds policies so a signed-in user reaches only their own rows (auth.uid() = the owner column; add one if needed). If the table is meant to be public to read, say so and add a read-only policy. Show me the SQL.` });

  try {
    const tracked = execFileSync("git", ["-C", root, "ls-files"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).split("\n");
    const env = tracked.find((f) => /(^|\/)\.env(\.local|\.production)?$/.test(f));
    if (env) add({ id: "scan:env-tracked", severity: "high", where: env, title: `Your ${env} file is saved in version control`, why: "Everyone with access to the repository, now or later, has every key in it. If the repository is public, so does the world.", fix: "Remove it from git, add it to .gitignore, and replace the keys it held.", first: "Replace every key in that file: once committed, a key stays in the history.", prompt: `My ${env} file is tracked by git. Remove it from version control without deleting my local copy (git rm --cached), add it to .gitignore, and give me an .env.example with the names only. Then list every key that was in it so I can replace each one.` });
  } catch {}

  for (const [who, list] of Object.entries(publicRead)) {
    if (!list.length) continue;
    const names = list.map((t) => t.table);
    add({ id: `scan:public-read:${who === "everyone" ? "everyone" : "signed-in"}`, severity: "medium", where: list[0].where, title: `${list.length} table${list.length > 1 ? "s" : ""} can be read in full by ${who}`, why: `${names.slice(0, 15).join(", ")}${names.length > 15 ? ` and ${names.length - 15} more` : ""}. Each has a policy whose condition is simply "true". That is fine for a public list such as products or courses, and a leak for anything about people.`, fix: "Go through the list: keep the ones that are meant to be public, and limit the rest to the row's owner.", first: null, prompt: `These tables in my database have a read policy with the condition true, so ${who === "everyone" ? "anyone on the internet" : "any signed-in user"} can read every row: ${names.join(", ")}. Go through them one by one and tell me, for each, whether it holds anything about a specific person (names, emails, messages, payments, activity). Change nothing yet. Then list the ones you would restrict to the row's owner, and wait for my OK.` });
  }

  // A lockfile only matters when there is something to lock.
  let hasDeps = false;
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
    hasDeps = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies }).length > 0;
  } catch {}
  if (hasDeps && !["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "bun.lock"].some((f) => fs.existsSync(path.join(root, f))))
    add({ id: "scan:no-lockfile", severity: "low", where: "package.json", title: "No lockfile", why: "Without a lockfile every build may install different versions of your dependencies, so the app you tested isn't the app you ship.", fix: "Commit the lockfile your package manager creates.", first: null, prompt: "My project has no lockfile. Run the install for the package manager this project uses, commit the lockfile it creates, and make the build use it." });

  const order = ["critical", "high", "medium", "low", "info"];
  findings.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
  return { source: "your project's files", dir: root, files: files.length, findings };
}
