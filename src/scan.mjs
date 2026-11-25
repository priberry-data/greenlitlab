// greenlit scan [folder]: reads a project's own files, on your computer, for the launch mistakes that can't be
// seen from outside: rules that let everyone in, functions that skip the sign-in check, payment messages nobody
// verifies, secrets that ship to the browser. Node only. Reads names in .env files, never values; a key found in
// code is reported by its kind and place, never by its value.
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";

// Build output, dependencies and agents' working copies. Test folders are skipped too (their made-up secrets and
// tables aren't the app's), except a "test" folder inside a route tree, which is a real page.
const SKIP = new Set(["node_modules", ".claude", "worktrees", "__tests__", "__mocks__", "__fixtures__", "fixtures", "e2e", "cypress", ".git", "dist", "build", ".next", ".nuxt", ".svelte-kit", ".output", ".vercel", ".netlify", ".wrangler", "coverage", ".turbo", ".cache", "vendor", "__pycache__", ".venv", "venv", ".expo", "ios", "android", "Pods"]);
const TEST_DIRS = new Set(["test", "tests", "spec", "specs"]);
const TEXT = /\.(sql|toml|json|jsonc|js|jsx|ts|tsx|mjs|cjs|py|vue|svelte|astro|rules|ya?ml)$|(^|\/)(\.env[^/]*|\.dev\.vars)$/;
// Folders read first, so a cap never lands on the files that matter most.
const FIRST = new Set(["supabase", "migrations", "src", "app", "functions", "api", "server", "lib", "pages", "components", "db", "database", "firebase"]);
const MAX_FILES = 20000;
const BIG = 1024 * 1024;
const PUBLIC_PREFIX = "(?:VITE_|NEXT_PUBLIC_|REACT_APP_|EXPO_PUBLIC_|PUBLIC_|NUXT_PUBLIC_|GATSBY_|STORYBOOK_)";
// The name must END in the secret word: VITE_STRIPE_SECRET_KEY is a secret, VITE_PASSWORD_MIN_LENGTH is a setting.
const SECRET_NAME = new RegExp(`\\b(${PUBLIC_PREFIX}[A-Z0-9_]*?(?:SECRET(?:_ACCESS)?(?:_KEY|_TOKEN)?|SERVICE_ROLE(?:_KEY)?|SERVICE_KEY|PRIVATE_KEY|PASSWORD|DATABASE_URL|DB_URL|POSTGRES_URL))(?![A-Z0-9_])`, "g");
// A key for a paid service behind a public prefix (VITE_OPENAI_API_KEY) is the same mistake under another name.
// Keys made to be public (Stripe publishable, Supabase anon) are left out.
const PAID = "OPENAI|ANTHROPIC|CLAUDE|GEMINI|GOOGLE_AI|GOOGLE_GENAI|GROQ|OPENROUTER|MISTRAL|PERPLEXITY|REPLICATE|HUGGINGFACE|HF|DEEPSEEK|XAI|GROK|COHERE|TOGETHER|FIREWORKS|ELEVENLABS|DEEPGRAM|ASSEMBLYAI|PINECONE|VOYAGE|FAL|RUNWAY|STABILITY|TAVILY|SERPAPI|FIRECRAWL|EXA|RESEND|SENDGRID|MAILGUN|POSTMARK|BREVO|TWILIO|GITHUB|STRIPE|PAYPAL|RAZORPAY|LEMONSQUEEZY|LEMON_SQUEEZY|PADDLE|AWS|NOTION|AIRTABLE|SLACK|DISCORD|TELEGRAM|SHOPIFY|HUBSPOT|MAPBOX_SECRET|ALGOLIA_ADMIN|UPSTASH";
const PAID_KEY_NAME = new RegExp(`\\b(${PUBLIC_PREFIX}(?![A-Z0-9_]*(?:PUBLISHABLE|_PK(?:_|$)|PUBLIC_KEY|ANON|CLIENT_ID|SITE_KEY|APP_ID|PROJECT_ID|ACCOUNT_ID|MEASUREMENT))[A-Z0-9_]*?(?:${PAID})[A-Z0-9_]*?(?:KEY|TOKEN))(?![A-Z0-9_])`, "g");
// Keys recognised by their shape, wherever they're written. Only the kind and the place are ever reported.
const KEY_SHAPES = [
  ["a live Stripe secret key", /\b[rs]k_live_[0-9A-Za-z]{10,}/g],
  ["a Stripe webhook signing secret", /\bwhsec_[0-9A-Za-z]{20,}/g],
  ["an OpenAI key", /\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{16,}|\bsk-[A-Za-z0-9]{40,}\b/g],
  ["an Anthropic key", /\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{20,}/g],
  ["an OpenRouter key", /\bsk-or-v1-[a-f0-9]{32,}/g],
  ["a Groq key", /\bgsk_[A-Za-z0-9]{40,}/g],
  ["an xAI key", /\bxai-[A-Za-z0-9]{40,}/g],
  ["a Replicate token", /\br8_[A-Za-z0-9]{30,}/g],
  ["a Hugging Face token", /\bhf_[A-Za-z0-9]{30,}/g],
  ["an AWS access key", /\bAKIA[0-9A-Z]{16}\b/g],
  ["a GitHub token", /\bgh[pousr]_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{40,}/g],
  ["a Slack token", /\bxox[baprs]-[A-Za-z0-9-]{10,}/g],
  ["a SendGrid key", /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/g],
  ["a Resend key", /\bre_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}/g],
  ["a Supabase access token", /\bsbp_[a-f0-9]{40}\b/g],
  ["a private key", /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----(?:\s|\\n|\\r)*[A-Za-z0-9+\/]{40,}/g],
];
const PLACEHOLDER = /x{4,}|\.\.\.|your[_-]|example|placeholder|dummy|<|\*{3,}|changeme|replace/i;
// A table or policy target the way SQL writes it: orders, public.orders, "public"."orders".
const IDENT = String.raw`(?:"?(\w+)"?\s*\.\s*)?"?(\w+)"?`;
// A column name that says the table holds something about a person.
const PERSONAL_COLUMN = /\b(e_?mail|phone|mobile|password|passwd|address|street|postcode|zip_?code|birth|dob|ssn|national_id|passport|full_name|first_name|last_name|ip_address|salary|iban|card_number|medical|diagnosis)\b/i;
const SENSITIVE_BUCKET = /(^|[-_])(ids?|identity|identities|kyc|verif\w*|documents?|docs|passports?|licen[cs]es?|selfies?|private|secure|medical|health|invoices?|receipts?|contracts?|statements?|tax|payslips?|resumes?|cvs?|uploads?|attachments?|records?|backups?)([-_]|$)/i;

// Comments blanked out, keeping every character's position so line numbers stay right. With `strings`,
// text inside single quotes is blanked too: it is data or SQL run later, not a statement in this file.
// Double-quoted names are kept, so an apostrophe in a policy's name ("Users can't …") starts nothing.
const sqlBlank = (sql, strings = true) =>
  sql.replace(/"(?:[^"]|"")*"|'(?:[^']|'')*'|\/\*[\s\S]*?\*\/|--[^\n]*/g, (m) => (m[0] === '"' ? m : m[0] === "'" ? (strings ? `'${m.slice(1, -1).replace(/[^\n]/g, " ")}'` : m) : m.replace(/[^\n]/g, " ")));
const noComments = (sql) => sqlBlank(sql, true);
const jsNoComments = (t) => t.replace(/("(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|`(?:[^`\\]|\\.)*`)|\/\*[\s\S]*?\*\/|(^|[^:\\])\/\/[^\n]*/g, (m, str, pre) => (str ? m : pre != null ? pre + m.slice(pre.length).replace(/[^\n]/g, " ") : m.replace(/[^\n]/g, " ")));
const shortHash = (s) => crypto.createHash("sha1").update(s).digest("hex").slice(0, 8);
const lineOf = (text, index) => text.slice(0, index).split("\n").length;

// Splits SQL into statements at semicolons, keeping $tag$ … $tag$ bodies whole. Linear in the file's length.
function statements(code) {
  const out = [];
  let start = 0;
  let i = 0;
  const n = code.length;
  while (i < n) {
    const c = code[i];
    if (c === "$") {
      const m = code.slice(i, i + 64).match(/^\$([A-Za-z_]\w*)?\$/);
      if (m) {
        const end = code.indexOf(m[0], i + m[0].length);
        i = end < 0 ? n : end + m[0].length;
        continue;
      }
    }
    if (c === ";") {
      out.push({ text: code.slice(start, i), index: start });
      start = i + 1;
    }
    i++;
  }
  if (code.slice(start).trim()) out.push({ text: code.slice(start), index: start });
  return out;
}
// The text inside the parentheses that open at `from` (which must point at "(").
function parens(s, from) {
  let depth = 0;
  for (let j = from; j < s.length && j < from + 20000; j++) {
    if (s[j] === "(") depth++;
    else if (s[j] === ")" && --depth === 0) return s.slice(from + 1, j);
  }
  return null;
}
const clause = (stmt, word) => {
  const m = stmt.match(new RegExp(`\\b${word}\\s*\\(`, "i"));
  return m ? parens(stmt, m.index + m[0].length - 1) : null;
};
// Splits a condition at top-level OR / ||.
function disjuncts(expr) {
  const parts = [];
  let depth = 0;
  let last = 0;
  for (let j = 0; j < expr.length; j++) {
    const c = expr[j];
    if (c === "(") depth++;
    else if (c === ")") depth--;
    else if (depth === 0) {
      if (/^\s+or\s/i.test(expr.slice(j, j + 5)) || expr.slice(j, j + 2) === "||") {
        parts.push(expr.slice(last, j));
        j += expr.slice(j, j + 2) === "||" ? 1 : 3;
        last = j + 1;
      }
    }
  }
  parts.push(expr.slice(last));
  return parts.map((p) => p.trim().replace(/^\(+|\)+$/g, (x) => x).toLowerCase().replace(/\s+/g, " "));
}
const unwrapParens = (p) => {
  let s = p.trim();
  while (s.startsWith("(") && parens(s, 0) === s.slice(1, -1)) s = s.slice(1, -1).trim();
  return s;
};
// "true", "1=1", "true or …": a condition that lets everyone through.
const ALWAYS = (d) => /^(true|'t'|'true'|1\s*=\s*1|true::bool(ean)?|not\s+false)$/.test(unwrapParens(d));
// A condition that only asks "is anyone signed in?": every signed-in user passes.
const ANY_SIGNED_IN = (d) => /^(\(?\s*(select\s+)?auth\.uid\s*\(\s*\)\s*\)?\s+is\s+not\s+null|\(?\s*(select\s+)?auth\.role\s*\(\s*\)\s*\)?\s*=\s*'authenticated'|\(?\s*(select\s+)?auth\.jwt\s*\(\s*\)\s*\)?\s+is\s+not\s+null|auth\.uid\s*\(\s*\)\s*<>\s*null)$/.test(unwrapParens(d));

function isCheckout(dotGit) {
  try {
    const st = fs.statSync(dotGit);
    if (st.isFile()) return /^gitdir:\s*\S/.test(fs.readFileSync(dotGit, "utf8").slice(0, 4096));
    return st.isDirectory() && fs.existsSync(path.join(dotGit, "HEAD")) && fs.existsSync(path.join(dotGit, "objects"));
  } catch {
    return false;
  }
}

function walk(root) {
  const out = [];
  const nested = [];
  const seen = new Set();
  const stack = [root];
  let truncated = false;
  while (stack.length) {
    const dir = stack.pop();
    let real;
    try {
      real = fs.realpathSync(dir);
    } catch {
      continue;
    }
    if (seen.has(real)) continue;
    seen.add(real);
    let entries = [];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {}
    const later = [];
    const first = [];
    for (const e of entries) {
      const full = path.join(dir, e.name);
      let isDir = e.isDirectory();
      let isFile = e.isFile();
      if (e.isSymbolicLink()) {
        try {
          const st = fs.statSync(full);
          isDir = st.isDirectory();
          isFile = st.isFile();
        } catch {}
      }
      if (isDir) {
        if (SKIP.has(e.name)) continue;
        const relDir = path.relative(root, dir).split(path.sep).join("/");
        if (TEST_DIRS.has(e.name) && !/(^|\/)(app|pages|routes)(\/|$)/.test(relDir)) continue;
        // Another checkout inside this one (a git worktree, a submodule, a cloned repo) is a different project.
        // Only a real one: an empty .git can't hide a folder. Every skipped folder is reported.
        if (isCheckout(path.join(full, ".git"))) {
          nested.push(path.relative(root, full).split(path.sep).join("/"));
          continue;
        }
        (FIRST.has(e.name) ? first : later).push(full);
      } else if (isFile && TEXT.test(full.split(path.sep).join("/"))) {
        if (out.length >= MAX_FILES) {
          truncated = true;
          return { files: out, truncated, nested };
        }
        out.push(full);
      }
    }
    stack.push(...later, ...first); // the FIRST folders are popped first
  }
  return { files: out, truncated, nested };
}

// Whether a function's own code checks a webhook signature (Stripe, Svix/Resend/Clerk, GitHub, Lemon Squeezy, Paddle).
const SIGNATURE = /constructEvent(?:Async)?\s*\(|webhooks?\.verify\s*\(|new\s+Webhook\s*\([\s\S]*?\.verify\s*\(|x-hub-signature|x-signature|paddle-signature|timingSafeEqual|construct_event\s*\(/i;
function signsItself(dir) {
  let found = false;
  const stack = [dir];
  while (stack.length && !found) {
    const d = stack.pop();
    let entries = [];
    try {
      entries = fs.readdirSync(d, { withFileTypes: true });
    } catch {}
    for (const e of entries) {
      const full = path.join(d, e.name);
      if (e.isDirectory()) e.name !== "node_modules" && stack.push(full);
      else if (/\.(ts|js|mjs)$/.test(e.name)) {
        try {
          if (SIGNATURE.test(jsNoComments(fs.readFileSync(full, "utf8")))) found = true;
        } catch {}
      }
    }
  }
  return found;
}

// Code that runs in the visitor's browser, judged by where it lives and what it says about itself.
function clientSide(name, text, project) {
  if (/(^|\/)(api|server|backend|functions|netlify\/functions|supabase\/functions|scripts|workers?|cron|jobs|lib\/server|routes\/api|app\/api|pages\/api)\//.test(name)) return false;
  if (/(^|\/)(route|middleware|\+server|\+page\.server|\+layout\.server|server)\.[jt]s$|\.(server|nitro|worker|cron|edge)\.[jt]sx?$/.test(name)) return false;
  if (/^\s*["']use server["']/m.test(text)) return false;
  if (/^\s*["']use client["']/m.test(text)) return true;
  // Server functions (TanStack Start, SolidStart, Remix loaders) and anything reading process.env run on a server:
  // a Vite build gives the browser import.meta.env, not process.env.
  if (/\bcreateServerFn\b|\bcreateServerAction\b|\bcreateMiddleware\b|["']server-only["']|["']@tanstack\/(?:react-)?start\/server["']|\bexport\s+(?:async\s+)?function\s+(?:loader|action)\b/.test(text)) return false;
  // Outside a single-page app, a file reading a non-public process.env value runs on a server. In a Vite or
  // Create React App build it may still be bundled for the browser, so there it proves nothing.
  if (!project.spa && /\bprocess\.env\.(?!NODE_ENV\b|REACT_APP_|NEXT_PUBLIC_|EXPO_PUBLIC_|VITE_|GATSBY_)[A-Z_]/.test(text)) return false;
  if (/import\.meta\.env\b/.test(text)) return true;
  if (/\.(vue|svelte|html)$/.test(name)) return true;
  if (/\.astro$/.test(name)) return false; // frontmatter runs on the server
  // In a single-page app (Vite, Create React App, Expo) everything under src/ or app/ ships to the browser or phone.
  return project.spa && /^(src|app|components|pages|hooks|screens|public)\//.test(name);
}

export function codeScan(dir = ".") {
  const root = path.resolve(dir);
  if (!fs.existsSync(root) || !fs.statSync(root).isDirectory()) throw new Error(`"${dir}" isn't a folder`);
  // In name order, which for migrations is the order they ran in: a later file can undo an earlier one.
  const walked = walk(root);
  const files = walked.files.sort();
  const rel = (f) => path.relative(root, f).split(path.sep).join("/");
  const findings = [];
  const unread = [];
  const add = (f) => findings.some((x) => x.id === f.id) || findings.push(f);
  const exists = (p) => fs.existsSync(path.join(root, p));
  let pkg = {};
  try {
    pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
  } catch {}
  const deps = { ...pkg.dependencies, ...pkg.devDependencies };
  const project = {
    spa: !["@tanstack/react-start", "@tanstack/start", "@remix-run/node", "@react-router/node", "@sveltejs/kit", "nuxt", "astro", "@solidjs/start", "vinxi", "@builder.io/qwik-city"].some((d) => d in deps) && !exists("next.config.js") && !exists("next.config.mjs") && !exists("next.config.ts") && (["vite.config.ts", "vite.config.js", "vite.config.mjs"].some(exists) || "react-scripts" in deps || "expo" in deps),
    gemini: "@google/generative-ai" in deps || "@google/genai" in deps,
  };
  let usesSupabase = exists("supabase") || Object.keys(deps).some((d) => d.startsWith("@supabase/"));

  // Database state across every migration, in order.
  const created = new Map(); // table -> { where, people }
  const protectedTables = new Set();
  const dynamic = []; // tables created before an EXECUTE … enable row level security we can't read
  const publicRead = { everyone: [], "every signed-in user": [] };
  const policies = new Map(); // "schema.table|name" -> { action, roles, using, check, where, table, schema }
  const buckets = new Map(); // bucket id -> { public, where }
  const views = new Map(); // view -> { where, invoker, auth, revoked }
  const definers = new Map(); // function -> { where, dynamicSql, revoked }
  const keyFiles = [];

  for (const file of files) {
    const name = rel(file);
    if (/\.(test|spec)\.[a-z]+$/i.test(name)) continue;
    if (/(^|\/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lock|composer\.lock)$/.test(name)) continue;
    let text = "";
    try {
      const size = fs.statSync(file).size;
      if (size > BIG && !(name.endsWith(".sql") && size < 16 * BIG)) {
        if (/\.(sql|rules|toml)$|(^|\/)(firebase|database\.rules)\.json$/.test(name)) unread.push(name);
        continue;
      }
      text = fs.readFileSync(file, "utf8");
    } catch {
      continue;
    }
    if (text.includes("\0")) continue;
    if (!usesSupabase && /@supabase\/(supabase-js|ssr|auth-helpers)/.test(text)) usesSupabase = true;
    if (!project.gemini && /generativelanguage\.googleapis\.com|GoogleGenerativeAI|@google\/genai/.test(text)) project.gemini = true;
    const isEnv = /(^|\/)(\.env[^/]*|\.dev\.vars)$/.test(name);

    // Names only: a secret behind a public prefix is copied into the code every visitor downloads.
    for (const m of [...text.matchAll(SECRET_NAME), ...text.matchAll(PAID_KEY_NAME)]) {
      if (isEnv && !new RegExp(`^\\s*(?:export\\s+)?${m[1]}\\s*=`, "m").test(text)) continue;
      add({ id: `scan:public-secret:${m[1]}`, severity: "critical", where: `${name}:${lineOf(text, m.index)}`, title: `The secret ${m[1]} is named so it ships to the browser`, why: "Anything whose name starts with a public prefix (VITE_, NEXT_PUBLIC_ and the like) is copied into the JavaScript every visitor downloads. A secret there is public.", fix: "Rename it without the public prefix and use it only in backend code.", first: "Treat this key as leaked if the app has ever been deployed with it: revoke it and make a new one.", prompt: `My project has a secret named ${m[1]}. The public prefix means it is built into the frontend, where anyone can read it. Rename it without the prefix, move every use of it into backend code (an edge function or server route) that checks the user is signed in, and confirm it no longer appears anywhere in the frontend build. List the files you changed.` });
    }
    if (isEnv) continue;

    // Firebase rules, wherever firebase.json says they are.
    if (/\.rules$/.test(name) || (/(^|\/)database\.rules\.json$/.test(name))) {
      scanFirebase(name, text, add);
      continue;
    }

    if (name.endsWith(".sql")) {
      scanSql(name, text);
      continue;
    }

    if (/(^|\/)supabase\/config\.toml$/.test(name)) {
      scanSupabaseConfig(name, text, file);
      continue;
    }

    const code = /\.(js|jsx|ts|tsx|mjs|cjs|vue|svelte|astro)$/.test(name) ? jsNoComments(text) : text;
    const client = clientSide(name, text, project);

    // Keys written into the code itself, recognised by their shape.
    if (!/\.(example|sample)\./.test(name)) {
      for (const [kind, re] of KEY_SHAPES) {
        for (const m of code.matchAll(re)) {
          if (PLACEHOLDER.test(m[0].slice(6)) || /^(.)\1+$/.test(m[0].slice(-12))) continue;
          const line = lineOf(code, m.index);
          add({ id: `scan:key-in-code:${name}:${shortHash(kind)}`, severity: client ? "critical" : "high", where: `${name}:${line}`, title: `${kind[0].toUpperCase()}${kind.slice(1)} is written into ${client ? "code that ships to the browser" : "the code"}`, why: client ? "Anyone who opens the app can read it from the JavaScript they download." : "Everyone with access to the code, now or later, has this key. If the repository is ever public, so does the world.", fix: "Move it into a server-side secret and read it from there.", first: "Revoke this key and make a new one: it has been copied wherever this code has been.", prompt: `${name} line ${line} contains ${kind} written directly in the code. Don't show me the value. Move it into a server-side secret (an environment variable that never reaches the browser, or your platform's secret store), read it only in backend code, and remove it from this file. Then remind me to revoke the old key and make a new one.` });
          break;
        }
      }
      // A Supabase key whose role is service_role: it skips every Row Level Security rule.
      for (const m of code.matchAll(/\beyJ[A-Za-z0-9_-]{10,}\.(eyJ[A-Za-z0-9_-]{10,})\.[A-Za-z0-9_-]{8,}/g)) {
        let role = "";
        try {
          role = JSON.parse(Buffer.from(m[1], "base64url").toString("utf8")).role;
        } catch {}
        if (role !== "service_role") continue;
        const line = lineOf(code, m.index);
        add({ id: `scan:service-role-literal:${name}`, severity: client ? "critical" : "high", where: `${name}:${line}`, title: `The Supabase service_role key is written into ${client ? "code that ships to the browser" : "the code"}`, why: "The service_role key skips every Row Level Security rule: whoever has it can read, change and delete every row in the database.", fix: "Use the anon (publishable) key in the app, and keep service_role only in server-side secrets.", first: "Rotate the service_role key in Supabase (Settings → API) now.", prompt: `${name} line ${line} contains my Supabase service_role key written into the code. Don't show me the value. Replace it with the anon (publishable) key if this code runs in the browser, or read it from a server-side secret if it runs on a server. Then tell me how to rotate the service_role key in the Supabase dashboard.` });
      }
      // Google keys (AIza…) became Gemini keys on projects with the Generative Language API on.
      for (const m of code.matchAll(/\bAIza[0-9A-Za-z_-]{35}\b/g)) keyFiles.push({ name, line: lineOf(code, m.index), client });
    }
    // The service_role key used in browser code, by name.
    const SR_USE = /\benv(?:\.|\[\s*["'])[A-Z0-9_]*SERVICE_ROLE[A-Z0-9_]*|\b[A-Z0-9_]*SERVICE_ROLE_KEY\b(?!["'`]\s*[,\]])/;
    if (client && SR_USE.test(code) && /\bcreateClient\s*\(/.test(code))
      add({ id: `scan:service-role-client:${name}`, severity: "critical", where: `${name}:${lineOf(code, code.search(SR_USE))}`, title: "Browser code uses the Supabase service_role key", why: "This file runs in the visitor's browser and builds a Supabase client with the service_role key, which skips every Row Level Security rule. Anyone can take it from the page.", fix: "Use the anon key here and move anything that needs service_role into an edge function.", first: "If this has been deployed, rotate the service_role key.", prompt: `${name} runs in the browser and uses my Supabase service_role key. Change it to use the anon (publishable) key, move anything that really needs service_role into a Supabase edge function or server route that checks the signed-in user, and confirm the service_role key appears nowhere in the frontend build.` });
    // An AI SDK told to run in the browser ships its key to every visitor.
    if (/[{,]\s*dangerouslyAllowBrowser\s*:\s*true/.test(code))
      add({ id: `scan:ai-in-browser:${name}`, severity: "high", where: `${name}:${lineOf(code, code.search(/dangerouslyAllowBrowser/))}`, title: "An AI SDK is set to run in the browser", why: "dangerouslyAllowBrowser: true means the AI provider's key is in the page. Anyone can copy it and run up your bill, as happened to thousands of sites with exposed ChatGPT keys.", fix: "Call the AI provider from a server route or edge function and keep the key there.", first: "Revoke the key this code uses and make a new one.", prompt: `${name} calls an AI provider from the browser with dangerouslyAllowBrowser: true, so the API key ships to every visitor. Move the call into a server route or edge function that checks the user is signed in and limits how often they can call it, keep the key in a server-side secret, and remove dangerouslyAllowBrowser. Show me the change.` });

    // A login or session secret written into the code: anyone with the code can sign in as anyone.
    if (!/\.(md|html)$/.test(name)) {
      const yaml = /\.ya?ml$/.test(name);
      const re = yaml
        ? /\b(JWT_SECRET|JWT_KEY|SECRET_KEY|SESSION_SECRET|NEXTAUTH_SECRET|AUTH_SECRET|TOKEN_SECRET|COOKIE_SECRET|APP_SECRET|SECRET_KEY_BASE)\s*[:=]\s*["']?([^"'\s#${}][^"'\s#]{0,200})/g
        : /\b(JWT_SECRET|JWT_KEY|SECRET_KEY|SESSION_SECRET|NEXTAUTH_SECRET|AUTH_SECRET|TOKEN_SECRET|COOKIE_SECRET|APP_SECRET|jwtSecret|jwt_secret|sessionSecret|secretKey|secret_key)\b["']?\s*(?:[:=]|\|\||\?\?|,)\s*["'`]([^"'`\s$]{1,200})["'`]|\b(?:JWT_SECRET|SESSION_SECRET|SECRET_KEY|NEXTAUTH_SECRET|AUTH_SECRET)\b["']?\s*\)?\s*(?:\|\||\?\?|or)\s*["'`]([^"'`\s$]{1,200})["'`]|(?:environ\.get|getenv)\(\s*["'](?:JWT_SECRET|SECRET_KEY|SESSION_SECRET)["']\s*,\s*["']([^"'\s]{1,200})["']/g;
      // The same secret passed straight to the code that uses it, with no variable name to go on:
      // jwt.sign(user, "supersecretkey"), session({ secret: "keyboard cat" }), cookieParser("..."),
      // Flask's app.config["SECRET_KEY"] = "...". The literal must end the argument, so a quoted key inside the payload doesn't count.
      const direct = yaml ? [] : [
        /\b(?:jwt|jsonwebtoken|JWT)\s*\.\s*(?:sign|verify)\s*\([^;]{0,300}?,\s*()["'`]([^"'`\s$]{1,200})["'`]\s*[,)]/g,
        /\b(?:session|cookieSession|expressSession)\s*\(\s*\{[^}]{0,300}?\b(?:secret|keys)\s*:\s*\[?\s*()["'`]([^"'`$\n]{1,200})["'`]/g,
        /\bcookieParser\s*\(\s*()["'`]([^"'`\s$]{1,200})["'`]/g,
        /\bconfig\s*\[\s*["'](?:SECRET_KEY|JWT_SECRET_KEY)["']\s*\]\s*=\s*()["']([^"'\s]{1,200})["']/g,
      ];
      for (const m of [...code.matchAll(re), ...direct.flatMap((d) => [...code.matchAll(d)])]) {
        const v = m[2] ?? m[3] ?? m[4] ?? "";
        if (!v || /^(process|import|os\.|env|config|settings|\$|\{|true|false|null|none|undefined)/i.test(v) || PLACEHOLDER.test(v) && !/secret|changeme/i.test(v)) continue;
        if (/\.(example|sample)\b/.test(name)) continue;
        const line = lineOf(code, m.index);
        add({ id: `scan:hardcoded-auth-secret:${name}`, severity: "high", where: `${name}:${line}`, title: "A login secret is written into the code", why: "The secret that signs login tokens or sessions is a fixed value in this file. Anyone who reads it can make a valid login for any user. Invicti found the same few values (like \"supersecretkey\") in over a thousand AI-generated apps.", fix: "Generate a long random secret, keep it in an environment variable, and fail to start if it's missing.", first: "Change the secret in production: every token signed with the old one stays valid until you do.", prompt: `${name} line ${line} sets the secret that signs logins or sessions to a fixed value (or falls back to one when the environment variable is missing). Don't show me the value. Make the app read it only from an environment variable, refuse to start if it isn't set, and tell me how to generate a long random one. Then remind me that changing it signs everyone out.` });
        break;
      }
    }

    // Payment webhooks that act on a message without checking who sent it.
    if (/\.(js|ts|mjs|tsx|py)$/.test(name)) {
      const stripe = !client && /from\s+["'](?:npm:|https?:\/\/[^"'\s]*\/)?stripe(?:@[^"'?\/\s]*)?(?:\?[^"'\s]*)?["']|require\(\s*["']stripe["']\)|^\s*import\s+stripe\b/m.test(code);
      const events = /checkout\.session\.completed|invoice\.(?:paid|payment_succeeded)|customer\.subscription\.|payment_intent\.succeeded|event\.type\s*===?|event\[["']type["']\]/.test(code);
      const named = /webhook/i.test(name);
      // A route that takes a Stripe event as JSON, whatever the file is called (but not one that creates a checkout).
      const takesEvent = /\b(?:const|let|var)\s+(?:event|evt)\s*=\s*(?:await\s+)?(?:req|request)\.json\(\)|\.data\.object\b/.test(code);
      if (stripe && (named || events || takesEvent) && !/constructEvent|construct_event|stripe-signature|Stripe-Signature/i.test(code)) {
        const trusts = /\b(req|request)\.json\(\)|JSON\.parse\(|\breq\.body\b|request\.get_json|await\s+request\.body/.test(code);
        add({ id: `scan:webhook:${name}`, severity: trusts ? "high" : "medium", where: name, title: "Greenlit couldn't see a signature check in this payment webhook", why: "This file handles Stripe messages but never checks the Stripe-Signature header (constructEvent). If the check isn't done in another file it calls, anyone can send a fake \"payment succeeded\" message and get what was paid for.", fix: "Verify the signature with stripe.webhooks.constructEvent and the signing secret.", first: null, prompt: `My Stripe webhook handler in ${name} doesn't verify the Stripe-Signature header. Change it to read the raw request body and call stripe.webhooks.constructEvent (constructEventAsync on edge runtimes) with the signing secret from a server secret, reject anything that fails with a 400, and only then act on the event. Show me the change.` });
      }
    }

    // Coding agents with a database connection that can write.
    if (/(^|\/)(\.mcp\.json|\.cursor\/mcp\.json|\.vscode\/mcp\.json|\.windsurf\/mcp_config\.json|\.gemini\/settings\.json|claude_desktop_config\.json|\.roo\/mcp\.json|\.kiro\/settings\/mcp\.json)$/.test(name) && (/postgres(?:ql)?:\/\//i.test(text) || (/supabase/i.test(text) && !/read[-_]only/i.test(text))))
      add({ id: `scan:agent-db:${name}`, severity: "medium", where: name, title: "Your coding agent can change your database", why: "This agent configuration gives the AI a database connection that isn't read-only. An agent has deleted a production database this way, and a support ticket with hidden instructions made an agent leak private tables through the Supabase MCP server.", fix: "Use the read-only mode, scope it to one development project, and keep user-written text away from the agent.", first: null, prompt: `My agent configuration in ${name} gives you a database connection that can write. Tell me how to change it to read-only and scoped to a development project (for the Supabase MCP server: the read-only and project-ref options), and whether the live database is reachable with it today. Change nothing until I confirm.` });
  }

  // ---------- SQL: every statement, in the order the migrations run
  function scanSql(name, text) {
    const code = noComments(text); // strings blanked: for structure
    const orig = sqlBlank(text, false); // comments blanked, strings kept: for names and conditions
    const at = (i) => `${name}:${lineOf(code, i)}`;
    const pkey = (schema, table, pol) => `${(schema || "public").toLowerCase()}.${table.toLowerCase()}|${pol.replace(/"/g, "").toLowerCase()}`;
    for (const st of statements(code)) {
      const s = st.text;
      const o = orig.slice(st.index, st.index + s.length);
      const lead = s.length - s.trimStart().length;
      const i = st.index + lead;
      const head = s.trimStart().slice(0, 200).toLowerCase().replace(/\s+/g, " ");
      let m;
      if ((m = s.match(new RegExp(String.raw`^\s*create\s+(?:(?:global|local)\s+)?(?:temp(?:orary)?\s+|unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?${IDENT}`, "i")))) {
        if ((m[1] || "public").toLowerCase() !== "public" || /\btemp/i.test(m[0])) continue;
        const table = m[2].toLowerCase();
        if (!created.has(table) || created.get(table).dropped) {
          protectedTables.delete(table);
          created.set(table, { where: at(i), people: PERSONAL_COLUMN.test(s) });
        }
        continue;
      }
      if ((m = s.match(new RegExp(String.raw`^\s*alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?${IDENT}\s+(enable|disable)\s+row\s+level\s+security`, "i")))) {
        if ((m[1] || "public").toLowerCase() !== "public") continue;
        if (m[3].toLowerCase() === "enable") protectedTables.add(m[2].toLowerCase());
        else protectedTables.delete(m[2].toLowerCase());
        continue;
      }
      if ((m = s.match(new RegExp(String.raw`^\s*alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?${IDENT}\s+rename\s+to\s+"?(\w+)"?`, "i")))) {
        const [from, to] = [m[2].toLowerCase(), m[3].toLowerCase()];
        if (created.has(from)) created.set(to, created.get(from)), created.delete(from);
        if (protectedTables.delete(from)) protectedTables.add(to);
        continue;
      }
      if (/^\s*drop\s+table\b/i.test(s)) {
        for (const t of s.replace(/^\s*drop\s+table\s+(?:if\s+exists\s+)?/i, "").replace(/\b(cascade|restrict)\b/gi, "").split(",")) {
          const mm = t.trim().match(new RegExp(`^${IDENT}`));
          if (!mm) continue;
          const table = mm[2].toLowerCase();
          if ((mm[1] || "public").toLowerCase() === "public") {
            created.delete(table);
            protectedTables.delete(table);
          }
          for (const k of [...policies.keys()]) if (k.startsWith(`${(mm[1] || "public").toLowerCase()}.${table}|`)) policies.delete(k);
        }
        if (/(^|\/)migrations\//.test(name))
          add({ id: `scan:destructive:${name}`, severity: "low", where: at(i), title: "A migration deletes data", why: `It contains "${s.trim().slice(0, 60)}". Run against the live database, that data is gone unless you have a backup.`, fix: "Make sure a backup exists before this runs on the live database.", first: null, prompt: `My migration ${name} contains a statement that deletes data (drop table). Tell me exactly what would be lost if it runs on the live database, whether that is intended, and how to back up that data first. Change nothing.` });
        continue;
      }
      if (/^\s*truncate\b/i.test(s) && /(^|\/)migrations\//.test(name)) {
        add({ id: `scan:destructive:${name}`, severity: "low", where: at(i), title: "A migration deletes data", why: `It contains "${s.trim().slice(0, 60)}". Run against the live database, that data is gone unless you have a backup.`, fix: "Make sure a backup exists before this runs on the live database.", first: null, prompt: `My migration ${name} contains a statement that deletes data (truncate). Tell me exactly what would be lost if it runs on the live database, whether that is intended, and how to back up that data first. Change nothing.` });
        continue;
      }
      // Row Level Security switched on at run time.
      // Only an anonymous DO block runs here; a function that does the same may never be called.
      if (/^\s*do\b/i.test(o) && /\bexecute\b/i.test(o) && /enable\s+row\s+level\s+security/i.test(o)) {
        const arr = o.match(/foreach\s+\w+\s+in\s+array\s+(?:array\s*)?\[([^\]]*)\]/i);
        if (arr) for (const n of arr[1].matchAll(/'([\w.]+)'/g)) protectedTables.add(n[1].replace(/^public\./i, "").toLowerCase());
        else if (/pg_tables|information_schema\.tables|pg_class|pg_catalog/i.test(o)) for (const t of created.keys()) protectedTables.add(t); // a loop over every table
        else {
          // A fixed statement in quotes names its table; one built from pieces (%I, ||, a variable) can't be read.
          const literal = [...o.matchAll(/'\s*alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(?:"?public"?\s*\.\s*)?"?(\w+)"?\s+enable\s+row\s+level\s+security\s*;?\s*'/gi)];
          for (const l of literal) protectedTables.add(l[1].toLowerCase());
          if (/%I|%s|\|\||execute\s+(?!')\w/i.test(o)) for (const t of created.keys()) if (!protectedTables.has(t)) dynamic.push(t);
        }
        continue;
      }
      // Policies.
      if ((m = s.match(new RegExp(String.raw`^\s*create\s+policy\s+("[^"]*"|\w+)\s+on\s+${IDENT}`, "i")))) {
        const rest = o.slice(m[0].length);
        if (/\bas\s+restrictive\b/i.test(rest)) continue; // narrows access, opens nothing
        const roles = (rest.match(/\bto\s+([\w\s,"]+?)(?=\s+(?:using|with)\b|\s*$)/i) || [, "public"])[1].toLowerCase();
        const action = (rest.match(/\bfor\s+(select|insert|update|delete|all)\b/i) || [, "all"])[1].toLowerCase();
        policies.set(pkey(m[2], m[3], m[1]), { schema: (m[2] || "public").toLowerCase(), table: m[3].toLowerCase(), roles, action, using: clause(rest, "using"), check: clause(rest, "with\\s+check"), where: at(i) });
        continue;
      }
      if ((m = s.match(new RegExp(String.raw`^\s*alter\s+policy\s+("[^"]*"|\w+)\s+on\s+${IDENT}`, "i")))) {
        const key = pkey(m[2], m[3], m[1]);
        const p = policies.get(key);
        const rest = o.slice(m[0].length);
        const ren = rest.match(/^\s*rename\s+to\s+("[^"]*"|\w+)/i);
        if (ren) {
          if (p) policies.set(pkey(m[2], m[3], ren[1]), p), policies.delete(key);
          continue;
        }
        if (!p) continue;
        const roles = rest.match(/\bto\s+([\w\s,"]+?)(?=\s+(?:using|with)\b|\s*$)/i);
        policies.set(key, { ...p, roles: roles ? roles[1].toLowerCase() : p.roles, using: clause(rest, "using") ?? p.using, check: clause(rest, "with\\s+check") ?? p.check, where: at(i) });
        continue;
      }
      if ((m = s.match(new RegExp(String.raw`^\s*drop\s+policy\s+(?:if\s+exists\s+)?("[^"]*"|\w+)\s+on\s+${IDENT}`, "i")))) {
        policies.delete(pkey(m[2], m[3], m[1]));
        continue;
      }
      // Storage buckets made public.
      if (/^\s*insert\s+into\s+storage\.buckets\b/i.test(s)) {
        const cols = (o.match(/storage\.buckets\s*\(([^)]*)\)/i) || [, ""])[1].split(",").map((c) => c.trim().replace(/"/g, "").toLowerCase());
        const idIdx = cols.indexOf("id") >= 0 ? cols.indexOf("id") : cols.indexOf("name");
        const pubIdx = cols.indexOf("public");
        const valuesAt = o.search(/\bvalues\b/i);
        if (valuesAt >= 0 && pubIdx >= 0) {
          for (const tup of o.slice(valuesAt).matchAll(/\(([^()]*)\)/g)) {
            const vals = tup[1].split(",").map((v) => v.trim());
            const id = (vals[idIdx] || "").replace(/^'|'$/g, "");
            if (/^(true|'t'|'true')$/i.test(vals[pubIdx] || "")) buckets.set(id, { public: true, where: at(i) });
            else buckets.set(id, { public: false, where: at(i) });
          }
        }
        continue;
      }
      if ((m = o.match(/^\s*update\s+storage\.buckets\s+set\s+public\s*=\s*(true|false)\b[\s\S]*?\bwhere\s+(?:id|name)\s*=\s*'([^']+)'/i))) {
        buckets.set(m[2], { public: m[1].toLowerCase() === "true", where: at(i) });
        continue;
      }
      // Views and functions that run with their owner's rights.
      if ((m = s.match(new RegExp(String.raw`^\s*create\s+(?:or\s+replace\s+)?(?:materialized\s+)?view\s+(?:if\s+not\s+exists\s+)?${IDENT}`, "i")))) {
        if ((m[1] || "public").toLowerCase() !== "public") continue;
        const view = m[2].toLowerCase();
        views.set(view, { where: at(i), invoker: /security_invoker\s*=\s*(on|true|1|yes)/i.test(s), auth: /\bauth\s*\.\s*users\b/i.test(s), materialized: /materialized/i.test(m[0]), revoked: false });
        continue;
      }
      if ((m = s.match(new RegExp(String.raw`^\s*alter\s+view\s+(?:if\s+exists\s+)?${IDENT}\s+set\s*\(([^)]*)\)`, "i")))) {
        const v = views.get(m[2].toLowerCase());
        if (v && /security_invoker\s*=\s*(on|true|1|yes)/i.test(m[3])) v.invoker = true;
        continue;
      }
      if ((m = s.match(/^\s*revoke\s+[\w\s,]*?\bon\s+(?:table\s+)?(?:"?public"?\s*\.\s*)?"?(\w+)"?\s+from\s+([\w\s,]+)/i))) {
        const v = views.get(m[1].toLowerCase());
        if (v && /anon|public/i.test(m[2])) v.revoked = true;
      }
      if ((m = s.match(/^\s*revoke\s+(?:all|execute)[\s\S]*?\bon\s+function\s+(?:"?public"?\s*\.\s*)?"?(\w+)"?[\s\S]*?\bfrom\s+([\w\s,]+)/i))) {
        const f = definers.get(m[1].toLowerCase());
        if (f && /anon|public/i.test(m[2])) f.revoked = true;
        continue;
      }
      if ((m = s.match(new RegExp(String.raw`^\s*create\s+(?:or\s+replace\s+)?function\s+${IDENT}`, "i")))) {
        if ((m[1] || "public").toLowerCase() !== "public") continue;
        if (!/\bsecurity\s+definer\b/i.test(s)) continue;
        if (/\breturns\s+trigger\b/i.test(s)) continue; // triggers can't be called through the API
        definers.set(m[2].toLowerCase(), { where: at(i), dynamicSql: /\bexecute\s+(?:format\s*\(|'|\w+\s*\|\||\w+\s*;)/i.test(o) || /\bexecute\s+\w+/i.test(o.replace(/\bexecute\s+(procedure|function)\b/gi, "")), revoked: false });
        continue;
      }
      void head;
    }
  }

  // ---------- Supabase config: functions without the sign-in check, public buckets
  function scanSupabaseConfig(name, text, file) {
    let section = null;
    const lines = text.split("\n");
    for (let k = 0; k < lines.length; k++) {
      const line = lines[k].replace(/(^|[^"'])#.*$/, "$1");
      const h = line.match(/^\s*\[\s*([^\]]+?)\s*\]\s*$/);
      if (h) {
        section = h[1].split(".").map((p) => p.trim().replace(/^["']|["']$/g, ""));
        continue;
      }
      if (!section) continue;
      if (section[0] === "functions" && section[1] && /^\s*verify_jwt\s*=\s*false\b/.test(line)) {
        const fn = section[1];
        const where = `${name}:${k + 1}`;
        if (signsItself(path.join(path.dirname(file), "functions", fn)))
          add({ id: `scan:verify-jwt:${fn}`, severity: "low", where, title: `The function "${fn}" skips the sign-in check and verifies a signature instead`, why: "That is the right setup for a webhook. Greenlit saw a signature check in its code but can't confirm it runs before anything else.", fix: "Make sure the signature check is the first thing the function does.", first: null, prompt: `My Supabase edge function "${fn}" has verify_jwt = false and verifies a webhook signature. Confirm the signature check runs before the function reads or changes anything, and that a request with a missing or wrong signature gets a 400. Change nothing unless it doesn't.` });
        else add({ id: `scan:verify-jwt:${fn}`, severity: "high", where, title: `The function "${fn}" skips the sign-in check`, why: "verify_jwt = false means anyone on the internet can call this function. That is right only for webhooks that check a signature themselves.", fix: "Remove verify_jwt = false, or verify a signature inside the function.", first: null, prompt: `My Supabase edge function "${fn}" has verify_jwt = false, so anyone can call it. If it is a webhook, make it verify the sender's signature before doing anything. Otherwise remove that setting and make the function check the signed-in user and what they are allowed to do. Show me what you changed.` });
      }
      if (section[0] === "storage" && section[1] === "buckets" && section[2] && /^\s*public\s*=\s*true\b/.test(line)) buckets.set(section[2], { public: true, where: `${name}:${k + 1}` });
    }
  }

  // ---------- after every file: what's still open
  if (usesSupabase || [...created.keys()].length)
    for (const [table, info] of created) {
      if (protectedTables.has(table) || !usesSupabase) continue;
      const maybe = dynamic.includes(table);
      add({ id: `scan:no-rls:${table}`, severity: maybe ? "medium" : "high", where: info.where, title: maybe ? `Greenlit couldn't see Row Level Security switched on for "${table}"` : `The table "${table}" is created without Row Level Security`, why: `No migration turns Row Level Security on for it.${maybe ? " (A statement built at run time switches it on for some tables, and Greenlit can't tell whether this is one of them.)" : ""} If the app's public key can reach the table, every row is readable. (If you turned it on in the dashboard instead, the live database may be fine: check with npx greenlitlab <your app> --mine.)`, fix: `Add: alter table public.${table} enable row level security; plus a policy for the owner.`, first: null, prompt: `My migrations create the table "${table}" but never enable Row Level Security on it${maybe ? " in a statement I can read" : ""}. Write a new migration that enables it and adds policies so a signed-in user reaches only their own rows (auth.uid() = the owner column; add one if needed). If the table is meant to be public to read, say so and add a read-only policy. Show me the SQL.` });
    }

  for (const p of policies.values()) {
    if (p.schema !== "public" && p.schema !== "storage") continue;
    // The service role skips every rule anyway; a policy for it alone opens nothing.
    if (/service_role/.test(p.roles) && !/anon|authenticated|public/.test(p.roles)) continue;
    const conds = [p.using, p.check].filter((c) => c != null);
    if (!conds.length) continue;
    const parts = conds.flatMap(disjuncts);
    const always = parts.some(ALWAYS);
    const anySignedIn = !always && conds.every((c) => disjuncts(c).some((d) => ALWAYS(d) || ANY_SIGNED_IN(d)));
    const meta = conds.some((c) => /user_metadata|raw_user_meta_data/i.test(c));
    const table = p.schema === "public" ? p.table : `${p.schema}.${p.table}`;
    if (meta)
      add({ id: `scan:policy-user-metadata:${table}`, severity: "high", where: p.where, title: `A rule on "${table}" trusts user_metadata, which users can change themselves`, why: "user_metadata is written by the user (supabase.auth.updateUser), so a rule that checks it can be passed by anyone who edits their own metadata. Supabase's own Security Advisor flags this as an error (lint 0015).", fix: "Check app_metadata (set only by the server) or a column in your own table instead.", first: null, prompt: `A Row Level Security policy on "${table}" checks user_metadata, which every user can change for themselves. Rewrite it to use app_metadata (which only the server can set) or a roles column in my own table that users can't write, as a new migration. Show me the SQL and how roles get assigned.` });
    if (!always && !anySignedIn) continue;
    const toAuthed = anySignedIn || (/authenticated/.test(p.roles) && !/anon|public/.test(p.roles));
    const who = toAuthed ? "every signed-in user" : "everyone";
    if (p.schema === "storage") {
      if (p.table !== "objects") continue;
      const bucket = conds.join(" ").match(/bucket_id\s*=\s*'([^']+)'/i)?.[1];
      if (p.action === "select" || p.action === "all") {
        if (bucket && p.action === "select") continue; // a policy naming one bucket is judged with the bucket below
        add({ id: `scan:storage-open:${p.action}`, severity: toAuthed && p.action === "select" ? "medium" : "high", where: p.where, title: `${who === "everyone" ? "Anyone" : "Any signed-in user"} can ${p.action === "all" ? "read, replace and delete" : "read"} every file in storage`, why: "The policy on storage.objects lets this through with no condition on the bucket or the file's owner, so every uploaded file is reachable: profile photos, documents, ID scans. The Tea app leaked verification selfies and IDs this way.", fix: "Limit the policy to one bucket and to files under the user's own folder (auth.uid()).", first: null, prompt: `My storage.objects policy lets ${who} ${p.action === "all" ? "read, replace and delete" : "read"} every file in every bucket. Rewrite it as a new migration so each user reaches only files in their own folder (storage.foldername(name))[1] = auth.uid()::text, limited to the right bucket. Keep only truly public buckets (like avatars) readable by everyone, and tell me which you kept.` });
      } else if (!bucket && p.action !== "insert") add({ id: `scan:storage-open:${p.action}`, severity: "high", where: p.where, title: `${who === "everyone" ? "Anyone" : "Any signed-in user"} can ${p.action} any file in storage`, why: "The policy on storage.objects has no condition on the bucket or the owner.", fix: "Limit it to the user's own folder.", first: null, prompt: `My storage.objects policy for ${p.action} lets ${who} through for any file. Rewrite it as a new migration so a user can ${p.action} only files in their own folder ((storage.foldername(name))[1] = auth.uid()::text). Show me the SQL.` });
      continue;
    }
    // Reading a whole table is often meant (products, courses), so those are gathered into one question below.
    if (p.action === "select") {
      if (!publicRead[who].some((t) => t.table === table)) publicRead[who].push({ table, where: p.where, people: Boolean(created.get(p.table)?.people) });
      continue;
    }
    // Adding rows is right for a contact form, a waitlist or a log. Changing and deleting rarely is.
    const addOnly = p.action === "insert";
    add({ id: `scan:policy-true:${table}:${p.action}`, severity: addOnly ? "medium" : "high", where: p.where, title: `A rule lets ${who} ${p.action === "all" ? "read, change and delete" : addOnly ? "add" : p.action} rows in "${table}"`, why: `${anySignedIn ? "The policy's condition only asks whether someone is signed in, so any account passes" : 'The policy\'s condition is simply "true"'}: Row Level Security is on but checks nothing about whose row it is.${addOnly ? " That is right for a contact form, a waitlist or a log, and a problem if anything in the app trusts what is in this table." : ""}`, fix: "Compare auth.uid() with the row's owner column instead.", first: null, prompt: `In my database, a Row Level Security policy on "${table}" for ${p.action} ${anySignedIn ? "only checks that the user is signed in" : "uses the condition true"}, so ${toAuthed ? "any signed-in user" : "anyone"} passes it. ${addOnly ? `Tell me first whether "${table}" is meant to take rows from ${toAuthed ? "any signed-in user" : "strangers"} (a form, a waitlist, a log). If it is, keep it but make sure the new row can't claim to belong to someone else (set the owner column from auth.uid(), never from the request) and can't be flooded. If it isn't, rewrite` : "Rewrite"} it so a user can only ${p.action === "all" ? "reach" : p.action} their own rows (auth.uid() = the owner column; add that column if it's missing). Write this as a new migration, don't edit old ones, and show me the SQL.` });
  }

  // Buckets: public ones, judged by what their name says they hold.
  const bucketPolicies = [...policies.values()].filter((p) => p.schema === "storage" && p.table === "objects" && p.action === "select");
  for (const p of bucketPolicies) {
    const conds = [p.using].filter(Boolean).join(" ");
    const id = conds.match(/bucket_id\s*=\s*'([^']+)'/i)?.[1];
    if (!id || /auth\.uid|auth\.jwt|storage\.foldername/i.test(conds)) continue;
    if (/authenticated/.test(p.roles) && !/anon|public/.test(p.roles)) continue;
    if (!buckets.has(id)) buckets.set(id, { public: true, where: p.where, viaPolicy: true });
  }
  for (const [id, b] of buckets) {
    if (!b.public) continue;
    const sensitive = SENSITIVE_BUCKET.test(id);
    add({ id: `scan:public-bucket:${id}`, severity: sensitive ? "critical" : "medium", where: b.where, title: `The storage bucket "${id}" can be read by anyone`, why: `${b.viaPolicy ? "A policy lets everyone read every file in it" : "It is created as a public bucket"}: anyone with a file's address can download it, with no login.${sensitive ? " Its name says it holds documents or IDs. The Tea app leaked 72,000 images, including ID photos, from a bucket like this." : " That is fine for avatars or product photos, and a leak for anything private."}`, fix: "Make the bucket private and hand out short-lived signed URLs to the file's owner.", first: sensitive ? "Check the bucket's access logs: files may already have been downloaded." : null, prompt: `My Supabase storage bucket "${id}" is public, so anyone with a link can download its files. Tell me what it holds. If anything in it is private, write a migration that makes it private (public = false), add a storage.objects policy so users read only files under their own folder, and change the app to use createSignedUrl with a short expiry. Show me the changes.` });
  }

  for (const [view, v] of views) {
    if (v.revoked) continue;
    if (v.auth)
      add({ id: `scan:view-auth-users:${view}`, severity: "critical", where: v.where, title: `The view "${view}" exposes your users' accounts`, why: "It reads from auth.users (emails, phone numbers, sign-in details) and sits in the public schema, where the app's public key can reach it. Supabase's Security Advisor flags this as an error (lint 0002).", fix: "Move the view out of the public schema, or select only harmless columns from your own profiles table.", first: null, prompt: `My view "${view}" in the public schema reads from auth.users, so the app's public key may reach my users' emails and sign-in details. Replace it with a view over my own profiles table that has only the columns the app needs, created with (security_invoker = on), or move it to a private schema. Write it as a new migration and show me the SQL.` });
    else if (!v.invoker && !v.materialized)
      add({ id: `scan:view-definer:${view}`, severity: "high", where: v.where, title: `The view "${view}" skips Row Level Security`, why: "Views run with their creator's rights unless they're created with security_invoker = on, so this view returns rows the user's own rules would hide. Supabase's Security Advisor flags this as an error (lint 0010).", fix: "Recreate it with (security_invoker = on), or revoke access from anon and authenticated.", first: null, prompt: `My view "${view}" isn't created with security_invoker = on, so it ignores the Row Level Security on the tables it reads. Write a new migration: alter view public.${view} set (security_invoker = on); then check the app still works for a signed-in user and tell me if any rule needs changing.` });
    else if (v.materialized)
      add({ id: `scan:matview-exposed:${view}`, severity: "medium", where: v.where, title: `The materialized view "${view}" has no Row Level Security`, why: "Materialized views can't have Row Level Security. If it's in the public schema, the app's public key can read all of it (Supabase lint 0016).", fix: "Move it to a private schema, or revoke select from anon and authenticated.", first: null, prompt: `My materialized view "${view}" is in the public schema, and materialized views can't have Row Level Security. Tell me what it contains. If any of it is private, move it to a private schema or revoke select on it from anon and authenticated, in a new migration.` });
  }
  for (const [fn, f] of definers) {
    if (f.revoked) continue;
    add({ id: `scan:definer-function:${fn}`, severity: f.dynamicSql ? "high" : "medium", where: f.where, title: `The function "${fn}" runs with full rights and anyone can call it`, why: `It's SECURITY DEFINER in the public schema, so it skips Row Level Security, and Supabase lets the public key call public functions unless execute is revoked (lint 0028).${f.dynamicSql ? " It also builds SQL from text at run time, so a caller may be able to run any query (lint 0031)." : ""}`, fix: "Revoke execute from anon (and public), or make it SECURITY INVOKER.", first: null, prompt: `My function "${fn}" is SECURITY DEFINER in the public schema, so anyone with the public key can call it and it ignores Row Level Security. Write a new migration that revokes execute on it from public and anon (grant it only to authenticated if needed), sets search_path = '', and makes it check auth.uid() itself${f.dynamicSql ? ". It also runs SQL built from text: rewrite that part without dynamic SQL, or with format('%I', …) and a fixed list of allowed names" : ""}. Show me the SQL.` });
  }

  // Firebase/Google keys in browser code that may now call Gemini.
  if (keyFiles.length) {
    const k = keyFiles.find((x) => x.client) ?? keyFiles[0];
    add({ id: `scan:google-key:${k.name}`, severity: project.gemini && k.client ? "high" : "low", where: `${k.name}:${k.line}`, title: project.gemini && k.client ? "A Google API key in browser code, in a project that uses Gemini" : "A Google API key is in the code: make sure it can't call Gemini", why: "Google API keys (AIza…) used to be safe to publish, for Firebase or Maps. Since Gemini, the same key can call the Gemini API if the Generative Language API is switched on in its project, and run up your bill. Truffle Security found 2,863 live keys like this.", fix: "Restrict the key to the APIs and websites it needs, and keep Gemini calls on a server with its own key.", first: null, prompt: `My code has a Google API key (AIza…) at ${k.name}:${k.line}. Don't show me the value. Tell me how to check in Google Cloud whether this key can call the Generative Language (Gemini) API, how to restrict it to only the APIs and websites it needs, and, if the app calls Gemini, move those calls into a server route with a separate key kept in a server-side secret.` });
  }

  let gitUnavailable = false;
  try {
    // From the top of the repository: a .env committed above the folder being checked still ships with it.
    const top = execFileSync("git", ["-C", root, "rev-parse", "--show-toplevel"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
    const tracked = execFileSync("git", ["-C", top, "ls-files"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], maxBuffer: 64 * 1024 * 1024 }).split("\n");
    const envs = tracked.filter((f) => /(^|\/)(\.env(\.[\w.-]+)?|\.dev\.vars)$/.test(f) && !/\.(example|sample|template|defaults?|dist|schema)$/.test(f));
    // Lovable and others commit a .env that holds only browser-safe values (the Supabase URL and
    // publishable key). That is not a leak, so flag a tracked .env only when it holds a filled-in
    // value whose name says it is secret. Values are read to see whether they are empty, never shown.
    for (const env of envs) {
      const secrets = trackedEnvSecrets(path.join(top, env));
      if (secrets === null || !secrets.length) continue;
      const shown = path.relative(root, path.join(top, env)).split(path.sep).join("/") || env;
      const list = secrets.slice(0, 8).join(", ") + (secrets.length > 8 ? ` and ${secrets.length - 8} more` : "");
      add({ id: "scan:env-tracked", severity: "high", where: shown, title: `Your ${env} file is saved in version control, with secrets in it`, why: `It holds ${list}. Everyone with access to the repository, now or later, has those values. If the repository is public, so does the world.`, fix: "Remove it from git, add it to .gitignore, and replace those keys.", first: "Replace each of those keys: once committed, a key stays in the history.", prompt: `My ${env} file is tracked by git and holds secrets (${list}). Remove it from version control without deleting my local copy (git rm --cached), add it to .gitignore, and give me an .env.example with the names only. Then tell me where to replace each of those keys.` });
      break;
    }
  } catch {
    gitUnavailable = true;
  }

  for (const [who, list] of Object.entries(publicRead)) {
    if (!list.length) continue;
    const names = list.map((t) => t.table);
    add({ id: `scan:public-read:${who === "everyone" ? "everyone" : "signed-in"}`, severity: "medium", where: list[0].where, tables: list, title: `${list.length} table${list.length > 1 ? "s" : ""} can be read in full by ${who}`, why: `${names.slice(0, 15).join(", ")}${names.length > 15 ? ` and ${names.length - 15} more` : ""}. Each has a policy whose condition is simply "true"${who === "everyone" ? "" : " or only asks whether someone is signed in"}. That is fine for a public list such as products or courses, and a leak for anything about people.`, fix: "Go through the list: keep the ones that are meant to be public, and limit the rest to the row's owner.", first: null, prompt: `These tables in my database have a read policy that lets ${who === "everyone" ? "anyone on the internet" : "any signed-in user"} read every row: ${names.join(", ")}. Go through them one by one and tell me, for each, whether it holds anything about a specific person (names, emails, messages, payments, activity). Change nothing yet. Then list the ones you would restrict to the row's owner, and wait for my OK.` });
  }

  // A lockfile only matters when there is something to lock.
  const hasDeps = Object.keys(deps).length > 0;
  if (hasDeps && !["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "bun.lock"].some((f) => fs.existsSync(path.join(root, f))))
    add({ id: "scan:no-lockfile", severity: "low", where: "package.json", title: "No lockfile", why: "Without a lockfile every build may install different versions of your dependencies, so the app you tested isn't the app you ship.", fix: "Commit the lockfile your package manager creates.", first: null, prompt: "My project has no lockfile. Run the install for the package manager this project uses, commit the lockfile it creates, and make the build use it." });

  const order = ["critical", "high", "medium", "low", "info"];
  findings.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
  return { source: "your project's files", dir: root, files: files.length, findings, truncated: walked.truncated, unread, gitUnavailable, nested: walked.nested };
}

// ---------- Tracked .env files
// Names that are meant to reach the browser (and are safe there) never count as secrets.
const BROWSER_SAFE_ENV = /(^|_)(SUPABASE_(URL|ANON_KEY|PUBLISHABLE_KEY|PUBLISHABLE_DEFAULT_KEY|PROJECT_ID|PROJECT_REF)|FIREBASE_(API_KEY|AUTH_DOMAIN|PROJECT_ID|STORAGE_BUCKET|MESSAGING_SENDER_ID|APP_ID|MEASUREMENT_ID|DATABASE_URL)|PUBLISHABLE_KEY|STRIPE_PUBLISHABLE_KEY|CLERK_PUBLISHABLE_KEY|POSTHOG_KEY|SENTRY_DSN|GA_MEASUREMENT_ID|MAPBOX_TOKEN)$/i;
const SECRET_ENV = /(SECRET|PASSWORD|PASSWD|PRIVATE|CREDENTIAL|SERVICE_ROLE|SERVICE_KEY|TOKEN|API_KEY|ACCESS_KEY|_KEY$|^KEY$|DATABASE_URL|DB_URL|POSTGRES_URL|MONGODB_URI|REDIS_URL|DSN$|WEBHOOK)/i;
// Returns the names of filled-in secret values in a .env file, or null if it can't be read.
export function trackedEnvSecrets(file) {
  let text;
  try { text = fs.readFileSync(file, "utf8"); } catch { return null; }
  const out = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const m = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$/.exec(line);
    if (!m) continue;
    const [, name, rawValue] = m;
    const value = rawValue.replace(/\s+#.*$/, "").replace(/^(["'])(.*)\1$/, "$2").trim();
    if (!value || /^(your|xxx|changeme|replace|<|\$\{)/i.test(value)) continue;
    if (BROWSER_SAFE_ENV.test(name) || !SECRET_ENV.test(name)) continue;
    out.push(name);
  }
  return out;
}

// ---------- Firebase rules
function scanFirebase(name, text, add) {
  if (/\.json$/.test(name)) {
    // Realtime Database: ".read": true anywhere, or "auth != null" for the whole database.
    for (const m of text.matchAll(/"\.(read|write)"\s*:\s*(?:true|"true")/g)) {
      const line = lineOf(text, m.index);
      add({ id: `scan:firebase-open:database:${m[1]}:${shortHash(text.slice(Math.max(0, m.index - 200), m.index))}`, severity: "critical", where: `${name}:${line}`, title: `Your Realtime Database rules let anyone ${m[1]} this data`, why: `"${m[0]}" lets anyone on the internet ${m[1]} it, signed in or not.`, fix: 'Use "auth != null && auth.uid === $uid" under a per-user path instead of true.', first: m[1] === "write" ? "Look for data you didn't put there: anyone could have changed or deleted it." : null, prompt: `My Firebase Realtime Database rules in ${name} set ".${m[1]}": true at line ${line}, so anyone can ${m[1]} the data. Rewrite them so each user reaches only their own data (for example under users/$uid with auth != null && auth.uid === $uid), keep anything truly public read-only and say which it is, and show me the new rules.` });
    }
    let rules;
    try {
      rules = JSON.parse(text.replace(/\/\*[\s\S]*?\*\/|(^|[^:"])\/\/[^\n]*/g, "$1")).rules;
    } catch {}
    for (const op of ["read", "write"]) {
      const v = rules?.[`.${op}`];
      if (typeof v === "string" && /^\s*auth\s*!==?\s*null\s*$/.test(v))
        add({ id: `scan:firebase-signed-in:database:${op}`, severity: "high", where: name, title: `Any signed-in user can ${op} your whole Realtime Database`, why: `".${op}": "auth != null" at the top of the rules lets every account ${op} everything. Anyone can make an account.`, fix: "Scope rules to per-user paths: users/$uid with auth.uid === $uid.", first: null, prompt: `My Firebase Realtime Database rules give every signed-in user ".${op}" access to the whole database. Rewrite them so each user reaches only their own data under a path like users/$uid (auth.uid === $uid), with anything truly shared listed explicitly. Show me the new rules.` });
    }
    return;
  }
  const rules = text.replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/g, (m) => m.replace(/[^\n]/g, " "));
  const kind = /firebase\.storage/.test(rules) ? "Storage" : "Firestore";
  const k = kind.toLowerCase();
  // allow <ops>;  allow <ops>: if <condition>;  (the semicolon is optional before "}")
  for (const m of rules.matchAll(/\ballow\s+([a-z]+(?:\s*,\s*[a-z]+){0,8})\s*(?::\s*if\b([^;{}]{0,2000}))?\s*(?:;|(?=\}))/g)) {
    const actions = m[1].replace(/\s+/g, "").split(",").filter(Boolean);
    const cond = m[2] == null ? null : m[2].trim();
    const parts = cond == null ? ["true"] : disjuncts(cond);
    const open = parts.some((p) => /^(true|\(?\s*true\s*\)?)$/.test(unwrapParens(p)));
    const testMode = !open && parts.some((p) => /^request\.time\s*<\s*timestamp\.date\s*\(/.test(unwrapParens(p)));
    const signedIn = !open && !testMode && parts.length === 1 && /^request\.auth\s*!=\s*null$|^request\.auth\.uid\s*!=\s*null$/.test(unwrapParens(parts[0]));
    if (!open && !testMode && !signedIn) continue;
    // The match path this rule sits under: the nearest "match /…" before it.
    const before = rules.slice(0, m.index);
    const paths = [...before.matchAll(/match\s+(\/(?:\{[^}\s]*\}|[^\s{])*)\s*\{/g)];
    const matchPath = paths.length ? paths[paths.length - 1][1] : "";
    const wildcard = /\{\w+=\*\*\}/.test(matchPath);
    if (signedIn && !wildcard) continue; // "signed in" on one collection is often meant; the agent reviews it
    const writes = actions.some((a) => ["write", "create", "update", "delete"].includes(a));
    const line = lineOf(rules, m.index);
    const what = writes ? (actions.some((a) => ["read", "get", "list"].includes(a)) ? "read and change" : "change") : "read";
    const id = `scan:firebase-open:${k}:${shortHash(`${matchPath}|${actions.join(",")}|${cond ?? ""}`)}`;
    if (signedIn) {
      add({ id, severity: "high", where: `${name}:${line}`, title: `Any signed-in user can ${what} all of your ${kind} data`, why: `"allow ${actions.join(", ")}: if request.auth != null" on ${matchPath} lets every account ${what} every document, not just their own. Anyone can make an account.`, fix: "Check that the document belongs to request.auth.uid, collection by collection.", first: null, prompt: `My ${kind} rules in ${name} let any signed-in user ${what} everything under ${matchPath}. Replace that catch-all with rules per collection, so a user reaches only documents they own (request.auth.uid == resource.data.ownerId or the path's user id), with anything truly shared listed explicitly. Show me the new rules and how to test them with the emulator.` });
      continue;
    }
    add({ id, severity: writes || kind === "Firestore" ? "critical" : "high", where: `${name}:${line}`, title: `Your ${kind} rules let anyone ${what} this data${testMode ? " until a date" : ""}`, why: testMode ? "This is Firebase's test-mode rule: until that date, anyone on the internet passes it, signed in or not. Data is often left in test mode by accident." : `${cond == null ? `"allow ${actions.join(", ")}" with no condition` : `"if ${cond.replace(/\s+/g, " ").slice(0, 80)}"`} lets anyone on the internet ${what} it, signed in or not, with nothing but the project's public config.`, fix: "Allow access only when request.auth != null and the document belongs to request.auth.uid.", first: writes ? "Look for data you didn't put there: with write open, anyone could have changed or deleted it." : null, prompt: `My ${kind === "Storage" ? "Firebase Storage" : "Firestore"} security rules in ${name} at line ${line} let anyone on the internet ${what} the data under ${matchPath || "this path"}. Rewrite the rules so a signed-in user reaches only their own documents (request.auth != null && request.auth.uid == the owner field or path segment), keep anything truly public read-only and say which it is, and show me the new rules file. Then tell me how to test them with the Firebase emulator before deploying.` });
  }
}
