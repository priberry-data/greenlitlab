// greenlit <url>: checks a deployed app the way a curious stranger would, for the mistakes that
// AI app builders (Lovable, Bolt, v0, Replit, Emergent and the rest) ship most often:
//   - secret keys inside the JavaScript every visitor downloads
//   - a Supabase or Firebase database that anyone can read with the app's public key (with --mine only)
//   - source maps that hand out the whole source code
// Every finding comes with a fix prompt to paste back into the app builder, and running the check again
// shows what got fixed. It reads only what the site serves to every visitor. The database checks ask for
// a row count (Supabase) or a single document name (Firebase), never for data, and run only when you say
// the app is yours.
// No Node-only imports here: the same code runs in the CLI and in the web check on Cloudflare.
import { SEVERITY } from "./severity.mjs";

// [pattern, id, what it is, what a stranger can do with it, where to revoke it]
const SECRETS = [
  // sk_live_ is used by Stripe and by other services (Clerk, Paystack); the advice is the same for all of them.
  [/\bsk_live_[0-9A-Za-z]{20,}/, "stripe", "A live secret key for payments or sign-in (Stripe, Clerk or similar)", "With Stripe, anyone can charge, refund and read your customers' payments; with Clerk, anyone can manage your users.", "the dashboard of the service it belongs to (Stripe: Developers → API keys → Roll key; Clerk: API keys → roll the secret key)", "STRIPE_SECRET_KEY"],
  [/rk_live_[0-9A-Za-z]{20,}/, "stripe-restricted", "A live Stripe restricted key", "Anyone can do whatever this key allows on your Stripe account.", "Stripe → Developers → API keys → delete the restricted key", "STRIPE_RESTRICTED_KEY"],
  [/sk-(proj|svcacct|admin)-[0-9A-Za-z_-]{20,}|sk-[0-9A-Za-z]{48}\b/, "openai", "An OpenAI API key", "Anyone can run up your OpenAI bill.", "platform.openai.com → API keys → revoke", "OPENAI_API_KEY"],
  [/sk-ant-[0-9A-Za-z_-]{20,}/, "anthropic", "An Anthropic API key", "Anyone can run up your Anthropic bill.", "console.anthropic.com → API keys → disable", "ANTHROPIC_API_KEY"],
  [/\bAKIA[0-9A-Z]{16}\b/, "aws", "An AWS access key", "Depending on its rights: your servers, storage and bill.", "AWS console → IAM → Users → Security credentials → deactivate the key", "AWS_SECRET_ACCESS_KEY"],
  [/gh[pousr]_[0-9A-Za-z]{30,}|github_pat_[0-9A-Za-z_]{20,}/, "github", "A GitHub token", "Access to your code, and possibly the right to change it.", "GitHub → Settings → Developer settings → tokens → delete", "GITHUB_TOKEN"],
  [/xox[bpas]-[0-9A-Za-z-]{10,}/, "slack", "A Slack token", "Anyone can read or post in your Slack.", "api.slack.com/apps → your app → reinstall to get a new token", "SLACK_TOKEN"],
  [/re_[0-9A-Za-z]{8}_[0-9A-Za-z]{20,}/, "resend", "A Resend API key", "Anyone can send email as you.", "resend.com → API Keys → delete", "RESEND_API_KEY"],
  [/SG\.[0-9A-Za-z_-]{20,}\.[0-9A-Za-z_-]{20,}/, "sendgrid", "A SendGrid API key", "Anyone can send email as you.", "SendGrid → Settings → API Keys → delete", "SENDGRID_API_KEY"],
  [/\bAC[0-9a-f]{32}\b[\s\S]{0,80}?\b[0-9a-f]{32}\b/, "twilio", "Twilio credentials", "Anyone can send texts and make calls on your account.", "Twilio console → Account → API keys & tokens → rotate the auth token", "TWILIO_AUTH_TOKEN"],
  [/gsk_[0-9A-Za-z]{40,}/, "groq", "A Groq API key", "Anyone can run up your Groq bill.", "console.groq.com → API Keys → delete", "GROQ_API_KEY"],
  [/\bsb_secret_[0-9A-Za-z_-]{20,}/, "supabase-secret", "A Supabase secret key", "It skips every security rule: anyone can read, change and delete all of your data and users.", "Supabase → Project Settings → API Keys → delete this secret key and create a new one", "SUPABASE_SECRET_KEY"],
  [/\bsbp_[0-9a-f]{40}\b/, "supabase-token", "A Supabase personal access token", "Anyone can manage your Supabase account: every project, database and setting.", "supabase.com → Account → Access Tokens → revoke", "SUPABASE_ACCESS_TOKEN"],
  [/\bsk-or-v1-[0-9a-f]{64}\b/, "openrouter", "An OpenRouter API key", "Anyone can run up your OpenRouter bill on any model.", "openrouter.ai → Keys → delete", "OPENROUTER_API_KEY"],
  [/\bxai-[0-9A-Za-z]{60,}/, "xai", "An xAI (Grok) API key", "Anyone can run up your xAI bill.", "console.x.ai → API Keys → delete", "XAI_API_KEY"],
  [/\bpplx-[0-9A-Za-z]{40,}/, "perplexity", "A Perplexity API key", "Anyone can run up your Perplexity bill.", "perplexity.ai → Settings → API → revoke", "PERPLEXITY_API_KEY"],
  [/\bhf_[0-9A-Za-z]{34,}/, "huggingface", "A Hugging Face token", "Anyone can use your Hugging Face account and, with a write token, change your models.", "huggingface.co → Settings → Access Tokens → delete", "HF_TOKEN"],
  [/\br8_[0-9A-Za-z]{37}\b/, "replicate", "A Replicate API token", "Anyone can run up your Replicate bill.", "replicate.com → Account → API tokens → delete", "REPLICATE_API_TOKEN"],
  [/\bpcsk_[0-9A-Za-z_]{40,}/, "pinecone", "A Pinecone API key", "Anyone can read, change and delete your vector database.", "app.pinecone.io → API Keys → delete", "PINECONE_API_KEY"],
  [/\b(?:glpat|gldt)-[0-9A-Za-z_-]{20,}/, "gitlab", "A GitLab token", "Access to your code, and possibly the right to change it.", "GitLab → Preferences → Access Tokens → revoke", "GITLAB_TOKEN"],
  [/\bnpm_[0-9A-Za-z]{36}\b/, "npm", "An npm token", "Anyone can publish packages as you, which can infect everyone who installs them.", "npmjs.com → Access Tokens → delete", "NPM_TOKEN"],
  [/\bshp(?:at|ca|pa|ss)_[0-9a-fA-F]{32}\b/, "shopify", "A Shopify access token", "Anyone can read and change your store, orders and customers.", "Shopify admin → Apps → your app → API credentials → rotate", "SHOPIFY_ACCESS_TOKEN"],
  [/\bxkeysib-[0-9a-f]{64}-[0-9A-Za-z]{16}\b/, "brevo", "A Brevo (Sendinblue) API key", "Anyone can send email as you and read your contacts.", "Brevo → SMTP & API → API Keys → delete", "BREVO_API_KEY"],
  [/\b[0-9a-f]{32}-us\d{1,2}\b/, "mailchimp", "A Mailchimp API key", "Anyone can read your mailing list and send campaigns as you.", "Mailchimp → Profile → Extras → API keys → delete", "MAILCHIMP_API_KEY"],
  [/\bkey-[0-9a-f]{32}\b/, "mailgun", "A Mailgun API key", "Anyone can send email as you.", "Mailgun → API Security → delete the key", "MAILGUN_API_KEY"],
  [/\b\d{8,10}:AA[0-9A-Za-z_-]{33}\b/, "telegram", "A Telegram bot token", "Anyone can take over your bot and read the messages people send it.", "Telegram → @BotFather → /revoke", "TELEGRAM_BOT_TOKEN"],
  [/\bsk\.eyJ[0-9A-Za-z_-]{20,}\.[0-9A-Za-z_-]{20,}/, "mapbox", "A secret Mapbox token", "Anyone can use your Mapbox account and run up your bill. (Public pk. tokens are fine.)", "account.mapbox.com → Tokens → delete", "MAPBOX_SECRET_TOKEN"],
  [/-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----(?:\\n|\\r|\s)+[A-Za-z0-9+\/=]{60,}/, "private-key", "A private key", "Whatever this key signs in to or signs for, anyone can now do too.", "the service the key belongs to: replace the key pair there and delete the old one", "PRIVATE_KEY"],
  [/"type"\s*:\s*"service_account"[\s\S]{0,400}"private_key"/, "gcp-service-account", "A Google Cloud or Firebase service-account key", "It's an admin key: anyone can reach your Firebase and Google Cloud data with full rights.", "Google Cloud console → IAM → Service Accounts → Keys → delete this key", "GOOGLE_APPLICATION_CREDENTIALS"],
  [/AIza[0-9A-Za-z_-]{35}(?=[\s\S]{0,400}(generativelanguage|gemini))/, "gemini", "A Google AI (Gemini) API key", "Anyone can run up your Gemini bill. (Firebase keys are public by design; this one sits next to Gemini calls.)", "aistudio.google.com → API keys → delete", "GEMINI_API_KEY"],
  [/\bwhsec_[0-9A-Za-z]{24,}/, "stripe-webhook", "A Stripe webhook signing secret", "Anyone can fake a \"payment succeeded\" message to your app and get paid features for free.", "Stripe → Developers → Webhooks → your endpoint → roll the signing secret", "STRIPE_WEBHOOK_SECRET"],
  [/\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s:"'`\/@]{1,64}:[^\s"'`\/@]{6,}@[A-Za-z0-9.-]+\.[a-z]{2,}/, "database-url", "A database address with its password", "Anyone can connect straight to your database and read, change or delete everything in it.", "your database provider's dashboard: reset the database password, then update the apps that use it", "DATABASE_URL"],
];
const JWT = /eyJ[0-9A-Za-z_-]{10,}\.eyJ[0-9A-Za-z_-]{10,}\.[0-9A-Za-z_-]{10,}/g;
const SUPABASE_URL = /https:\/\/([a-z0-9]{20})\.supabase\.co/;
const FB_PROJECT = /projectId["']?\s*:\s*["']([a-z0-9-]{4,40})["']/;
const FB_DB = /["'](https:\/\/[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:firebaseio\.com|firebasedatabase\.app))\/?["']/;
const FB_KEY = /apiKey["']?\s*:\s*["'](AIza[0-9A-Za-z_-]{35})["']/;
// Firestore can't list its collections without admin rights, so try the names apps use for people and money.
const FIRESTORE_GUESSES = ["users", "profiles", "customers", "accounts", "orders", "payments", "messages", "chats", "leads", "contacts", "posts"];
// Supabase stopped listing tables for the public key in 2026, so table names come from the app's own code:
// supabase.from("orders") calls and /rest/v1/orders addresses. Names that aren't tables answer "not found" and are dropped.
const TABLE_REF = /\.from\(\s*["'`]([A-Za-z_][A-Za-z0-9_]{1,62})["'`]\s*\)|\/rest\/v1\/([A-Za-z_][A-Za-z0-9_]{1,62})(?![A-Za-z0-9_])/g;
const RPC_REF = /\.rpc\(\s*["'`]([A-Za-z_][A-Za-z0-9_]{1,62})["'`]|\/rest\/v1\/rpc\/([A-Za-z_][A-Za-z0-9_]{1,62})/g;
const BUCKET_REF = /storage\s*\.from\(\s*["'`]([A-Za-z0-9_.-]{1,63})["'`]/g;
const EDGE_REF = /functions\s*\.invoke\(\s*["'`]([A-Za-z0-9_-]{1,63})["'`]|\/functions\/v1\/([A-Za-z0-9_-]{1,63})/g;
// Column names that mean a readable table holds personal or secret data. Greenlit asks only whether the column exists.
const SENSITIVE_COLUMNS = ["email", "phone", "password", "password_hash", "token", "access_token", "api_key", "secret", "address", "date_of_birth", "card_number"];
// Addresses the builder or host owns. The owner can't change DNS, email records or most headers there.
const BUILDER_HOST = /\.(lovable\.app|lovableproject\.com|bolt\.host|bolt\.new|replit\.app|repl\.co|replit\.dev|vercel\.app|netlify\.app|pages\.dev|workers\.dev|emergent\.host|emergentagent\.com|base44\.app|web\.app|firebaseapp\.com|github\.io|onrender\.com|fly\.dev|railway\.app)$/i;
// Cookies set by the host or CDN, not by the app.
const PLATFORM_COOKIE = /^(__cf|cf_|_cf|__vercel|_vercel|nf_|__Host-next|__Secure-next|AWSALB|ARRAffinity)/i;
const DEFAULT_TITLE = /^\s*(Lovable App|Lovable Generated Project|Vite \+ React(?: \+ TS)?|Create Next App|v0 App|React App|New Project|My App|Bolt)\s*$/i;
const AI_DIRECT = /https:\/\/(api\.openai\.com\/v1|api\.anthropic\.com\/v1|generativelanguage\.googleapis\.com\/v1|api\.groq\.com\/openai|openrouter\.ai\/api\/v1|api\.x\.ai\/v1|api\.mistral\.ai\/v1)/;
const PERSONAL = /user|profile|customer|account|order|payment|message|chat|contact|lead|email|subscri|invoice/i;

// Which app builder made this, so the fix prompt can say where to paste it.
export function detectBuilder(host, html = "") {
  const h = host.toLowerCase();
  if (/\.lovable\.app$|\.lovableproject\.com$/.test(h) || /lovable-tagger|content=["']Lovable/i.test(html)) return "Lovable";
  if (/\.bolt\.host$|\.bolt\.new$/.test(h)) return "Bolt";
  if (/\.replit\.app$|\.repl\.co$|\.replit\.dev$/.test(h)) return "Replit";
  if (/\.emergent\.host$|\.emergentagent\.com$|\.preview\.emergentagent\.com$/.test(h)) return "Emergent";
  if (/\.base44\.app$/.test(h)) return "Base44";
  if (/(^|\.)v0\.(dev|app)$/.test(h) || /generated by v0/i.test(html)) return "v0";
  return null;
}

const decodeJwt = (t) => {
  try {
    const b = t.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(b + "=".repeat((4 - (b.length % 4)) % 4)), (c) => c.charCodeAt(0))));
  } catch {
    return null;
  }
};

// Reads at most `max` bytes, so a huge file can't use up the memory of the machine doing the check.
async function readCapped(r, max) {
  if (!r.body?.getReader) return (await r.text()).slice(0, max);
  const reader = r.body.getReader();
  const parts = [];
  let size = 0;
  while (size < max) {
    const { done, value } = await reader.read();
    if (done) break;
    parts.push(value);
    size += value.byteLength;
  }
  reader.cancel().catch(() => {});
  const all = new Uint8Array(Math.min(size, max));
  let at = 0;
  for (const p of parts) {
    const take = Math.min(p.byteLength, all.length - at);
    all.set(p.subarray(0, take), at);
    at += take;
    if (at >= all.length) break;
  }
  return new TextDecoder().decode(all);
}

const safeUrl = (u, base) => {
  try {
    return new URL(u, base);
  } catch {
    return null;
  }
};

async function get(url, { timeout = 15000, headers = {}, method = "GET", body = null, max = 8 * 1024 * 1024, fetcher = fetch } = {}) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeout);
  try {
    const r = await fetcher(url, { method, headers: { "user-agent": "greenlit (+https://greenlit.priberry.com)", ...headers }, ...(body != null && { body }), signal: ctl.signal, redirect: "follow" });
    const text = method === "HEAD" ? "" : await readCapped(r, max);
    return { status: r.status, headers: r.headers, text, url: r.url };
  } catch (e) {
    return { status: 0, error: e.name === "AbortError" ? "timed out" : e.message, text: "" };
  } finally {
    clearTimeout(t);
  }
}

// What went wrong, in words a non-developer can act on. Shared by the web check and the CLI.
export function explainError(message) {
  const m = String(message);
  const code = Number((m.match(/\((\d{3})\)$/) || [])[1]);
  if (/look like a web address/.test(m)) return "That doesn't look like a web address. Try something like myapp.lovable.app.";
  if (/isn't a web page/.test(m)) return "That address isn't a web page. Enter the address people open to use your app.";
  if (code === 404) return "That address answered \"not found\". Check it's the live address of your app (open it in your browser first).";
  if (code === 530) return "Nothing answers at that address. Check the spelling, and that the app is published.";
  if (code === 401 || code === 403 || code === 429) return "That site turned the check away. It may be private, password-protected, or blocking automated visitors, so Greenlit can't grade it from here.";
  if (code >= 500) return `That site had an error of its own (${code}). Open it in your browser to see if it's up, then try again.`;
  if (/timed out/.test(m)) return "That site took too long to answer. Try again in a minute.";
  return "Couldn't reach that site. Check the spelling, and that the app is published.";
}

// A script belongs to the app if it's on the same site (static.myapp.com for myapp.com) or on a hosting CDN.
// Scripts on anyone else's site (Stripe, analytics) are that company's code, not the app's.
const siteKey = (host) => {
  const parts = host.toLowerCase().split(".");
  const short = parts.length > 2 && parts.at(-1).length === 2 && /^(co|com|org|net|ac|gov|edu)$/.test(parts.at(-2));
  return parts.slice(short ? -3 : -2).join(".");
};
const HOSTING_CDN = /(^|\.)(cloudfront\.net|azureedge\.net|b-cdn\.net|r2\.dev|fastly\.net|akamaized\.net|amazonaws\.com|storage\.googleapis\.com)$/i;

// Paths to other scripts mentioned inside a script or page: imports of every form, and the lists of lazy-loaded
// pages that Vite and Next.js keep ("assets/Page-abc.js", "static/chunks/abc.js"). This is where most of an app's code is.
const SCRIPT_REF = /["'`]((?:\.{0,2}\/|assets\/|_next\/|static\/chunks\/)[\w@.~\/-]+\.m?js(?:\?[^"'`\s]*)?)["'`]/g;
const resolveRef = (ref, from, origin) => (/^(assets|_next)\//.test(ref) ? safeUrl(ref, `${origin}/`) : ref.startsWith("static/chunks/") ? safeUrl(`/_next/${ref}`, origin) : safeUrl(ref, from));

// Builders and hosts often answer an address with nothing on it with a normal-looking page and status 200.
const DEAD_PAGE = /<title[^>]*>[^<]*(?:(?:website|site|page|project|app|application|deployment)\s+(?:was\s+|is\s+)?not\s+found|\b404\b)[^<]*<\/title>/i;

// --- fix prompts ---------------------------------------------------------------------------------
// Written for someone who can't read the code: what to do by hand first (revoking a key is something
// no AI builder can do for you), then one prompt to paste into the builder's chat.
const P = {
  secret: (label, revoke, env) => ({
    first: `Revoke the leaked key, because it is already public: ${revoke}. Then make a new one, and give it only to your backend (in Supabase: Edge Functions → Secrets, named ${env}).`,
    prompt: `My app has ${label.replace(/^A |^An /, "a ")} in its frontend code, so every visitor can download it. Remove that key from every frontend file. Move every call that uses it into a backend function (a Supabase Edge Function, or a server route if this app has a server) that reads the key from the secret ${env}, and have the frontend call that function instead. The function must check that the user is signed in before it does anything, and must never send the key back to the browser. When you're done, list every file you changed and confirm the key appears nowhere in the frontend.`,
  }),
  serviceRole: () => ({
    first: "Rotate the key, because it is already public: Supabase → Project Settings → API → generate new keys (or reset the JWT secret), then update the apps and functions that use them.",
    prompt: "My app has the Supabase service_role key in its frontend code. That key skips every security rule. Remove it from every frontend file; the browser must only ever use the anon (publishable) key. Anything that really needs admin access goes into a Supabase Edge Function that reads SUPABASE_SERVICE_ROLE_KEY from its environment and checks the signed-in user before acting. Then make sure Row Level Security is on for every table, with policies so users reach only their own rows. List what you changed.",
  }),
  rls: (table, personal) => ({
    first: null,
    prompt: personal
      ? `In my Supabase database, anyone on the internet can read the table "${table}" using the public anon key. Turn on Row Level Security for "${table}" and add policies so a signed-in user can read and change only their own rows: compare auth.uid() with the column that stores the owner's user id (if there is no such column, add user_id uuid references auth.users default auth.uid(), and fill it for existing rows). If some rows really must be public, add a separate read-only policy for just those rows and tell me which. Do not turn off any existing policy. Show me the SQL you ran.`
      : `In my Supabase database, anyone on the internet can read the table "${table}" using the public anon key. First tell me in one sentence whether this app needs strangers to read "${table}" (a public product list or blog does; anything about specific users doesn't). If it should be public: turn on Row Level Security, add a policy that lets everyone read it, and allow insert, update and delete only for signed-in admins or the row's owner, so strangers can look but never change it. If it shouldn't be public: turn on Row Level Security and let a signed-in user reach only their own rows (auth.uid() = user_id). Do not turn off any existing policy. Show me the SQL you ran.`,
    sql: personal
      ? `alter table public."${table}" enable row level security;\ncreate policy "own rows" on public."${table}" for all using (auth.uid() = user_id) with check (auth.uid() = user_id);`
      : `alter table public."${table}" enable row level security;\ncreate policy "anyone can read" on public."${table}" for select using (true);`,
  }),
  rtdb: () => ({
    first: null,
    prompt: 'Anyone on the internet can read my Firebase Realtime Database. Rewrite the database rules so nothing is readable or writable without signing in, and each user can only reach their own data, for example under /users/$uid with ".read": "auth.uid === $uid" and ".write": "auth.uid === $uid". Keep public only what truly must be public, and tell me which paths those are. Show me the final rules.',
  }),
  firestore: (coll) => ({
    first: null,
    prompt: `Anyone on the internet can read the Firestore collection "${coll}". Rewrite my Firestore security rules so "${coll}" (and every other collection) is closed by default, and a signed-in user can only read and write documents they own, for example match /${coll}/{id} { allow read, write: if request.auth != null && request.auth.uid == resource.data.userId; }. Adjust the owner field to whatever this app uses. Show me the final rules.`,
  }),
  signup: () => ({
    first: "Supabase → Authentication → Sign In / Providers → Email: turn on \"Confirm email\". If only people you invite should get in, turn off \"Allow new users to sign up\" too.",
    prompt: "In my Supabase project, anyone can create an account with any email address without confirming it. Find every Row Level Security policy that only checks that a user is signed in (for example `to authenticated using (true)`, or `auth.role() = 'authenticated'`), because to a stranger those are open. Rewrite each one so a user reaches only their own rows (auth.uid() = user_id), or only rows they were given access to. List each policy you changed, and show me the SQL.",
  }),
  storage: (bucket) => ({
    first: null,
    prompt: `In my Supabase project, anyone on the internet can list the files in the storage bucket "${bucket}". Change the storage policies so files in "${bucket}" can only be listed and read by the user who uploaded them (for example, store files under a folder named after auth.uid() and check (storage.foldername(name))[1] = auth.uid()::text). If some files must be public, keep them in a separate public bucket and tell me which. Show me the SQL.`,
  }),
  envFile: (path) => ({
    first: `Assume every key in ${path} is public: revoke and replace each one in the dashboard of the service it belongs to.`,
    prompt: `My live site serves the file ${path} to anyone who asks for it. Make sure ${path} is never deployed: add it to .gitignore and to the host's ignore settings, move its values into the host's environment variable settings, redeploy, and confirm that opening ${path} on the live site now returns "not found".`,
  }),
  gitDir: () => ({
    first: "Assume anyone can now download your whole code history, including any key ever committed: revoke and replace those keys.",
    prompt: "My live site serves its .git folder, so anyone can download my whole code history. Change the deployment so the .git folder is never uploaded or served (deploy only the build output folder), redeploy, and confirm that opening /.git/config on the live site returns \"not found\".",
  }),
  framing: () => ({
    first: null,
    prompt: "Any other website can show my app inside a hidden frame and trick my users into clicking things (clickjacking). Add the response header `Content-Security-Policy: frame-ancestors 'self'` (or `X-Frame-Options: DENY`) in my host's header settings, redeploy, and confirm the header is there. If this host doesn't let me set response headers, say so plainly instead of adding a meta tag, because a meta tag can't do this. Then tell me what my options are.",
  }),
  dbCheck: (db) =>
    db === "Supabase"
      ? "Check my Supabase database and change nothing yet. For every table, tell me whether Row Level Security is on, and which policies let someone read or change rows without signing in, or read rows that aren't theirs. Do the same for my storage buckets. Also tell me whether anyone can sign up without confirming their email. End with a plain list of what is open to strangers, worst first."
      : "Check my Firebase security rules and change nothing yet. For Firestore, Realtime Database and Storage, tell me which paths someone can read or change without signing in, or read when the data isn't theirs. End with a plain list of what is open to strangers, worst first.",
  fnCheck: (names) => `My app calls these backend functions: ${names.join(", ")}. Check each one and change nothing yet. For every function tell me: does it check that the caller is signed in, does it check that the caller is allowed to act on the record it touches, and could a stranger call it directly and cost me money or change data? Then fix every function that fails, and show me what you changed.`,
  localhost: (u) => ({ first: null, prompt: `My live app still points at ${u}, which only exists on a developer's computer, so that part can't work for real visitors. Find every place the app uses a localhost or 127.0.0.1 address and replace it with the live address, read from an environment variable. Then tell me each file you changed.` }),
  mixed: () => ({ first: null, prompt: "My live app loads a script, style or frame over plain http:// from a page served over https://. Browsers block that. Change every such address to https://, or host the file with the app, and tell me what you changed." }),
  testPayments: () => ({ first: "In Stripe, switch to live mode and copy your live publishable key (pk_live_…). Add your live secret key and webhook secret to your backend's secrets, never to the frontend.", prompt: "My live app uses a Stripe test key (pk_test_), so real customers can't pay. Switch the frontend to read the live publishable key from an environment variable, make sure the backend uses the live secret key and the live webhook signing secret from its secrets, and check that the webhook is registered for the live address. Tell me what you changed and what I still need to do in the Stripe dashboard." }),
  title: (t) => ({ first: null, prompt: `My app's page title is still the default "${t}". Set a real title and description for the app in index.html (or the page metadata), plus the Open Graph title, description and image, so shared links look right.` }),
  noindex: () => ({ first: null, prompt: "My live app tells search engines not to list it (a robots noindex tag or header). If this app should be found on Google, remove that tag from the live build only. If it's meant to stay private, leave it and tell me." }),
  aiDirect: () => ({ first: null, prompt: "My app's browser code calls an AI provider's API directly. That only works if the secret key is in the browser, where anyone can copy it and spend my money. Move every AI call into a backend function that reads the key from a secret, checks the user is signed in, and limits how many calls each user can make per day. Remove the provider's key from the frontend. List what you changed." }),
  testSender: () => ({ first: "In your email provider (for example Resend), add and verify your own domain, then choose a sender such as hello@yourdomain.", prompt: "My app sends email from a test address (onboarding@resend.dev), which only delivers to my own inbox. Change the sender to an address on my verified domain, read from an environment variable, and tell me which DNS records I must add for that domain." }),
  cookie: (name) => ({ first: null, prompt: `My app sets the cookie "${name}" without the Secure and HttpOnly flags, so it can leak over plain http or be read by any script on the page. Set Secure, HttpOnly and SameSite=Lax on every sign-in or session cookie, and tell me where you changed it.` }),
  httpsRedirect: () => ({ first: null, prompt: "My app answers on plain http:// without sending visitors to https://. Turn on \"always use HTTPS\" (a permanent redirect from http to https) in my host's settings, and add the header Strict-Transport-Security: max-age=31536000. Tell me exactly where that setting is for my host." }),
  cors: () => ({ first: null, prompt: "My app tells browsers that any website may read its responses with the visitor's login attached (it repeats back whatever Origin it is sent and allows credentials). Change the CORS settings to allow only my own site's address, never a repeated-back origin together with credentials, and show me the new settings." }),
  dmarc: (domain) => ({ first: `Add a TXT record at _dmarc.${domain} with the value: v=DMARC1; p=none; rua=mailto:you@${domain} (use an inbox you read). Your domain provider's DNS page is where this goes.`, prompt: `My domain ${domain} has no DMARC record, so anyone can send email pretending to be me, and Gmail and Outlook trust my real emails less. Tell me, step by step for my DNS provider, how to add a DMARC record starting with p=none, and how to check that my sign-up and password-reset emails pass SPF and DKIM before I tighten it to p=quarantine.` }),
  spf: (domain) => ({ first: null, prompt: `The SPF record for my domain ${domain} is broken (there must be exactly one, and it must not end in +all). Tell me which services send email for my app, write one correct SPF record that covers them and ends in ~all, and tell me exactly what to change at my DNS provider.` }),
  sourceMaps: () => ({
    first: null,
    prompt: "My production build publishes source maps, so anyone can read my app's original source code. Turn them off for production builds only (for Vite: build.sourcemap = false in vite.config), rebuild and redeploy. Don't change anything else.",
  }),
  csp: (origins) => ({
    first: null,
    prompt: `My app has no Content-Security-Policy. Add one as a <meta http-equiv="Content-Security-Policy"> tag in index.html (or as a response header if this host supports headers). Allow scripts, styles and fonts only from my own site and the services this app really uses${origins.length ? `, including ${origins.join(", ")}` : ""}, and allow connect-src for my backend and APIs. Then test every page and fix anything the policy blocks, without loosening it to allow everything.`,
  }),
};

// --- the check -----------------------------------------------------------------------------------
export async function siteScan(target, { mine = false, fetcher = fetch, maxScripts = 400, maxBytes = 8 * 1024 * 1024, maxTotalBytes = 200 * 1024 * 1024, deadlineMs = 120000, scriptTimeoutMs = 15000, httpProbe = null, wantPage = false } = {}) {
  const deadline = Date.now() + deadlineMs;
  const fetchOpts = (o = {}) => ({ max: maxBytes, ...o, fetcher });
  const url = safeUrl(/^https?:\/\//i.test(String(target).trim()) ? String(target).trim() : `https://${String(target).trim()}`);
  if (!url || !/^https?:$/.test(url.protocol) || !url.hostname.includes(".")) throw new Error(`"${target}" doesn't look like a web address`);
  const findings = [];
  const add = (f) => findings.push(f);

  const page = await get(url.href, fetchOpts());
  if (!page.status || page.status >= 400) throw new Error(`could not load ${url.href} (${page.error || page.status})`);
  const pageType = page.headers?.get("content-type") || "";
  if (pageType && !/html/i.test(pageType)) throw new Error(`${url.href} isn't a web page`);
  if (DEAD_PAGE.test(page.text)) throw new Error(`could not load ${url.href} (404)`);
  const pageUrl = page.url || url.href;
  const origin = new URL(pageUrl).origin;
  const site = siteKey(new URL(origin).hostname);
  const builder = detectBuilder(new URL(origin).host, page.text);
  const isOwn = (href) => {
    const h = new URL(href).hostname;
    return siteKey(h) === site || HOSTING_CDN.test(h);
  };

  // Every script that belongs to the app: the ones the page loads, then whatever those mention, until none are left.
  const srcs = new Set();
  const collect = (text, base) => {
    for (const m of text.matchAll(SCRIPT_REF)) {
      const u = resolveRef(m[1], base, origin);
      if (u && /^https?:$/.test(u.protocol)) srcs.add(u.href);
    }
  };
  for (const m of page.text.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)) safeUrl(m[1], pageUrl) && srcs.add(safeUrl(m[1], pageUrl).href);
  for (const m of page.text.matchAll(/<link[^>]+href=["']([^"']+\.m?js(?:\?[^"']*)?)["']/gi)) safeUrl(m[1], pageUrl) && srcs.add(safeUrl(m[1], pageUrl).href);
  collect(page.text, pageUrl);

  const bundles = [{ where: "the page itself", text: page.text }];
  const seen = new Set();
  let total = page.text.length;
  let stopped = false;
  let cut = 0;
  let fetched = 0;
  const retried = new Set();
  const failed = new Set();
  for (;;) {
    const waiting = [...srcs].filter((src) => !seen.has(src) && isOwn(src));
    if (!waiting.length) break;
    const room = maxScripts - fetched;
    if (room <= 0 || total >= maxTotalBytes || Date.now() > deadline) {
      stopped = true;
      break;
    }
    // Six at a time.
    const batch = waiting.slice(0, Math.min(6, room));
    for (const src of batch) seen.add(src);
    fetched += batch.length;
    const got = await Promise.all(batch.map((src) => get(src, fetchOpts({ timeout: scriptTimeoutMs })).then((r) => ({ src, r }))));
    for (const { src, r } of got) {
      // A file that wouldn't load isn't the same as a file that doesn't exist: try once more, then count it as unread.
      if (r.status === 0 || r.status === 429 || r.status >= 500) {
        if (retried.has(src)) failed.add(src);
        else {
          retried.add(src);
          seen.delete(src);
        }
        continue;
      }
      // Many hosts answer a missing file with the home page; that isn't a script.
      if (r.status !== 200 || /text\/html/i.test(r.headers?.get("content-type") || "")) continue;
      if (r.text.length >= maxBytes) cut++;
      total += r.text.length;
      bundles.push({ where: new URL(src).pathname, text: r.text, url: src });
      collect(r.text, src);
    }
  }
  const unread = [...srcs].filter((src) => !seen.has(src) && isOwn(src)).length + failed.size;
  const scriptTags = [...page.text.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)].map((m) => safeUrl(m[1], pageUrl)).filter((u) => u && /^https?:$/.test(u.protocol));
  const elsewhere = scriptTags.filter((u) => !isOwn(u.href)).length;
  // The page has scripts, but all of them live on another site, so its real code was never read.
  const noCodeRead = bundles.length === 1 && elsewhere > 0;

  let mapTries = 0;
  let supabase = null;
  let firebase = null;
  const keysSeen = new Set();
  const thirdParty = new Set();
  for (const b of bundles) {
    for (const m of b.text.matchAll(/https:\/\/([a-z0-9-]+\.)+[a-z]{2,}/gi)) {
      const o = safeUrl(m[0])?.origin;
      if (!o) continue;
      if (o !== origin && /supabase\.co|firebase|googleapis|stripe\.com|clerk|posthog|sentry|vercel/.test(o)) thirdParty.add(o.replace(/^https:\/\/[a-z0-9]{20}\.supabase\.co$/, "https://*.supabase.co"));
    }
    for (const [re, id, title, why, revoke, env] of SECRETS) {
      const m = b.text.match(re);
      if (m && !keysSeen.has(m[0])) {
        keysSeen.add(m[0]);
        add({ id: `secret:${id}`, severity: "critical", where: b.where, title: `${title} is in code every visitor downloads`, why: `${why} Found: ${m[0].slice(0, 8)}…`, fix: "Revoke this key now, make a new one, and call that service only from your backend (an edge function or server route), never from the browser.", ...P.secret(title, revoke, env) });
      }
    }
    for (const t of b.text.match(JWT) || []) {
      const p = decodeJwt(t);
      if (!p) continue;
      if (p.role === "service_role" && !keysSeen.has(t)) {
        keysSeen.add(t);
        add({ id: "supabase:service_role", severity: "critical", where: b.where, title: "Your Supabase service_role key is in the browser code", why: "This key skips every security rule: anyone can read, change and delete all of your data and users.", fix: "Rotate it in Supabase (Settings → API) and use it only on a server. The browser should only ever have the anon key.", ...P.serviceRole() });
      }
      if (p.role === "anon" && p.iss === "supabase") supabase = { ...(supabase || {}), anon: t, ref: p.ref };
    }
    const pk = b.text.match(/sb_publishable_[0-9A-Za-z_-]{20,}/);
    if (pk) supabase = { ...(supabase || {}), anon: supabase?.anon || pk[0] };
    const su = b.text.match(SUPABASE_URL);
    if (su) supabase = { ...(supabase || {}), url: su[0], ref: supabase?.ref || su[1] };
    const fp = b.text.match(FB_PROJECT);
    if (fp && /firebase/i.test(b.text)) {
      firebase = { ...(firebase || {}), project: fp[1] };
      const db = b.text.match(FB_DB);
      if (db) firebase.db = db[1];
      const k = b.text.match(FB_KEY);
      if (k) firebase.key = k[1];
    }
    const sm = b.url && b.text.match(/sourceMappingURL=([^\s'"]+\.map)/);
    const mapUrl = sm && safeUrl(sm[1], b.url)?.href;
    // A few tries are enough: an app either publishes its maps or it doesn't.
    if (mapUrl && isOwn(mapUrl) && mapTries < 3 && !findings.some((f) => f.id === "sourcemaps")) {
      mapTries++;
      // Check what comes back: hosts that answer every missing file with the home page would look "public" otherwise.
      const r = await get(mapUrl, fetchOpts({ max: 4096 }));
      if (r.status === 200 && /^\s*\{[\s\S]*"(version|mappings|sources)"/.test(r.text))
        add({ id: "sourcemaps", severity: "medium", where: new URL(mapUrl).pathname, title: "Source maps are public", why: "Anyone can read your app's original source code, including comments and any logic you assumed was hidden.", fix: "Turn off source maps in production builds (for Vite: build.sourcemap = false).", ...P.sourceMaps() });
    }
  }

  const database = supabase?.url && supabase.anon ? "Supabase" : firebase?.project ? "Firebase" : null;
  if (database && !mine)
    add({ id: "db:skipped", severity: "info", where: database, title: `Your ${database} database wasn't checked`, why: `This app uses ${database}. Greenlit can check which of its data anyone on the internet can read, but only on your own computer, for an app you own.`, fix: `Run \`npx greenlitlab ${url.host} --mine\` if this is your app.`, first: null, prompt: null, checkPrompt: P.dbCheck(database) });
  if (unread || cut)
    add({ id: "coverage:partial", severity: "info", where: "your app's scripts", title: unread ? `${unread} of this app's scripts weren't read` : "Some of this app's scripts were too big to read to the end", why: `Greenlit read ${bundles.length - 1} scripts, but couldn't get through the rest in one check. A problem in those wouldn't show up here.`, fix: `Run \`npx greenlitlab ${url.host}\` on your computer, which reads them all.`, first: null, prompt: null });
  if (noCodeRead)
    add({ id: "coverage:none", severity: "info", where: "your app's scripts", title: "This app's code wasn't read", why: `All ${elsewhere} of its scripts load from other sites, and Greenlit can't tell which of them are yours. Only the page itself and its settings were checked.`, fix: "If your app loads its code from a site of its own, check that site's address too.", first: null, prompt: null });

  // Supabase: with the public anon key, which tables can anyone read?
  let tables = null;
  let tablesTested = 0;
  let dbBlind = false;
  let tablesListed = false;
  // Database functions the app calls. Listed for the owner, never called: calling one runs it.
  const functions = new Set();
  const bucketsInCode = new Set();
  if (supabase)
    for (const b of bundles) {
      for (const m of b.text.matchAll(RPC_REF)) functions.add(m[1] || m[2]);
      for (const m of b.text.matchAll(BUCKET_REF)) bucketsInCode.add(m[1]);
    }
  const edge = new Set();
  if (supabase) for (const b of bundles) for (const m of b.text.matchAll(EDGE_REF)) edge.add(m[1] || m[2]);
  const called = [...new Set([...edge, ...functions])];
  if (called.length)
    add({ id: "supabase:functions", severity: "info", where: "Supabase functions", title: `Your app calls ${called.length} backend function${called.length > 1 ? "s" : ""} that Greenlit can't test`, why: `${called.slice(0, 12).join(", ")}${called.length > 12 ? " and more" : ""}. A function that doesn't check who is calling it is open to everyone, and that is how some of the largest leaks from AI-built apps happened. Greenlit lists them and never calls them, because calling one runs it.`, fix: "Have your builder check each function (the prompt below), or open Supabase → Advisors → Security Advisor.", first: null, prompt: null, checkPrompt: P.fnCheck(called.slice(0, 30)) });
  // Signs of Supabase, but not both its address and its public key: nothing can be tested.
  const supabasePartial = Boolean(supabase && !(supabase.url && supabase.anon) && !firebase?.project);
  if (supabasePartial)
    add({ id: "db:not-found", severity: "info", where: "Supabase", title: "This app seems to use Supabase, but its database wasn't checked", why: "Greenlit found signs of Supabase but not both its address and its public key in the code it read, so it couldn't test anything. The app may reach its database through its own server, which is the safer design, or the key may be in code that wasn't read.", fix: "Open Supabase → Advisors → Security Advisor: it lists every table and function that strangers can reach.", first: null, prompt: null, checkPrompt: P.dbCheck("Supabase") });
  if (mine && supabase?.url && supabase.anon) {
    // The newer sb_publishable_ keys aren't JWTs and go in the apikey header only.
    const h = { apikey: supabase.anon, ...(supabase.anon.startsWith("eyJ") && { authorization: `Bearer ${supabase.anon}` }) };
    const names = new Set();
    // Older projects still answer this with the list of tables; newer ones refuse the public key.
    const api = await get(`${supabase.url}/rest/v1/`, fetchOpts({ headers: h }));
    try {
      for (const p of Object.keys(JSON.parse(api.text).paths || {})) if (p.slice(1) && !p.startsWith("/rpc/")) names.add(p.slice(1));
    } catch {}
    tablesListed = names.size > 0;
    for (const b of bundles) for (const m of b.text.matchAll(TABLE_REF)) (m[1] || m[2]) !== "rpc" && names.add(m[1] || m[2]);
    tables = [];
    for (const t of [...names].slice(0, 80)) {
      // A HEAD request with count=exact returns how many rows are visible, and no rows.
      const r = await get(`${supabase.url}/rest/v1/${encodeURIComponent(t)}?select=*`, fetchOpts({ method: "HEAD", headers: { ...h, prefer: "count=exact", range: "0-0" } }));
      // "Not found" means the name wasn't a table; no answer means it wasn't tested. Neither counts.
      if (!r.status || r.status === 404 || r.status >= 500) continue;
      tablesTested++;
      const n = Number((r.headers?.get("content-range") || "").split("/")[1]);
      if (r.status < 300 && n > 0) tables.push({ table: t, rows: n });
    }
    // A check that tested no tables must say so, not report "nothing open".
    dbBlind = tablesTested === 0;
    if (dbBlind)
      add({ id: "db:no-tables", severity: "info", where: "Supabase", title: "Your database tables weren't checked", why: "Greenlit couldn't find any of your table names in the code it read, and Supabase no longer lists them for the public key. So it couldn't test which tables strangers can read. Storage and sign-up settings were still checked.", fix: "Open Supabase → Advisors → Security Advisor: it lists every table that strangers can reach.", first: null, prompt: null, checkPrompt: P.dbCheck("Supabase") });
    // For tables strangers can read: which hold personal data? Asks whether a column exists, never for its values.
    for (const t of tables.slice(0, 8)) {
      t.sensitive = [];
      for (const c of SENSITIVE_COLUMNS) {
        const r = await get(`${supabase.url}/rest/v1/${encodeURIComponent(t.table)}?select=${c}`, fetchOpts({ method: "HEAD", headers: { ...h, range: "0-0" } }));
        if (r.status === 200 || r.status === 206) t.sensitive.push(c);
      }
    }
    for (const { table, rows, sensitive = [] } of tables) {
      const personal = PERSONAL.test(table) || sensitive.length > 0;
      const why = personal
        ? "The anon key is public (it ships in your app), so a table without Row Level Security is readable by everyone. This is how most vibe-coded apps have leaked data."
        : "The anon key is public (it ships in your app). If this table is meant to be public, like a product list, reading it is fine, but make sure strangers can't change it. If it isn't, it's leaking.";
      add({ id: `supabase:table:${table}`, severity: personal ? "critical" : "medium", where: `Supabase table "${table}"`, title: `Anyone on the internet can read ${rows.toLocaleString("en-US")} row${rows > 1 ? "s" : ""} of "${table}"${sensitive.length ? `, including ${sensitive.slice(0, 4).join(", ")}` : ""}`, why, fix: `In Supabase, open Table Editor → ${table} → turn on RLS, then add a policy so people read only their own rows (for example: auth.uid() = user_id).`, ...P.rls(table, personal) });
    }
  }

  // Your own app only: files that should never be on a live site. A real .env has KEY=value lines; a real .git
  // folder has a config file with [core]. Anything else (often the home page served for every path) doesn't count.
  if (mine) {
    for (const path of ["/.env", "/.env.local", "/.env.production"]) {
      const r = await get(new URL(path, origin).href, fetchOpts({ max: 4096 }));
      if (r.status === 200 && !/^\s*</.test(r.text) && /^[A-Z][A-Z0-9_]*=/m.test(r.text)) {
        add({ id: `exposed:${path}`, severity: "critical", where: path, title: `Your ${path} file is public`, why: "This file usually holds every secret key the app uses, and anyone can download it.", fix: `Stop deploying ${path}, then revoke every key it contained.`, ...P.envFile(path) });
        break;
      }
    }
    const g = await get(new URL("/.git/config", origin).href, fetchOpts({ max: 4096 }));
    if (g.status === 200 && /\[core\]/.test(g.text))
      add({ id: "exposed:git", severity: "high", where: "/.git/", title: "Your code history (.git folder) is public", why: "Anyone can download your full source code and every past version of it, including keys that were committed once and later removed.", fix: "Deploy only the build output, never the .git folder.", ...P.gitDir() });
  }

  // Your own app only: Supabase settings that quietly make "signed-in users only" mean "anyone".
  if (mine && supabase?.url && supabase.anon) {
    const h = { apikey: supabase.anon, ...(supabase.anon.startsWith("eyJ") && { authorization: `Bearer ${supabase.anon}` }) };
    const st = await get(`${supabase.url}/auth/v1/settings`, fetchOpts({ headers: h, max: 65536 }));
    try {
      const cfg = JSON.parse(st.text);
      if (st.status === 200 && cfg.disable_signup === false && cfg.mailer_autoconfirm === true)
        add({ id: "supabase:open-signup", severity: "high", where: "Supabase Auth settings", title: "Anyone can sign up with any email, without confirming it", why: "Rules that only check \"is the user signed in?\" protect nothing: a stranger can make an account in seconds, even with someone else's email address.", fix: "Turn on email confirmation in Supabase Auth, and make every policy check who owns the row, not just that someone is signed in.", ...P.signup() });
    } catch {}
    // Storage: which common buckets list their files to anyone? Asks for one file name, never the file.
    for (const bucket of [...new Set(["avatars", "uploads", "files", "documents", "images", "attachments", "receipts", "invoices", "private", ...bucketsInCode])].slice(0, 24)) {
      const r = await get(`${supabase.url}/storage/v1/object/list/${encodeURIComponent(bucket)}`, fetchOpts({ method: "POST", headers: { ...h, "content-type": "application/json" }, body: JSON.stringify({ prefix: "", limit: 1, offset: 0 }), max: 65536 }));
      let n = 0;
      try {
        n = Array.isArray(JSON.parse(r.text)) ? JSON.parse(r.text).length : 0;
      } catch {}
      if (r.status === 200 && n > 0)
        add({ id: `supabase:storage:${bucket}`, severity: /receipt|invoice|document|private|attachment/.test(bucket) ? "critical" : "high", where: `Supabase storage bucket "${bucket}"`, title: `Anyone can list the files in the storage bucket "${bucket}"`, why: "Strangers can see every file name in it and, if the files are readable too, download them. Greenlit asked for one file name and opened nothing.", fix: `In Supabase → Storage → Policies, limit "${bucket}" so users list and read only their own files.`, ...P.storage(bucket) });
    }
  }

  // Firebase: is the Realtime Database or a common Firestore collection open to anyone?
  let firebaseOpen = null;
  if (mine && firebase?.project) {
    firebaseOpen = [];
    if (firebase.db) {
      // shallow=true returns only the top-level key names, each mapped to true; we count them and drop them.
      const r = await get(`${firebase.db}/.json?shallow=true`, fetchOpts());
      let keys = 0;
      try {
        const v = JSON.parse(r.text);
        keys = v && typeof v === "object" ? Object.keys(v).length : v != null ? 1 : 0;
      } catch {}
      if (r.status === 200 && keys > 0) {
        firebaseOpen.push({ where: "Realtime Database", keys });
        add({ id: "firebase:rtdb", severity: "critical", where: "Firebase Realtime Database", title: "Anyone on the internet can read your Firebase Realtime Database", why: `Its rules let visitors who aren't signed in read it (${keys} top-level ${keys > 1 ? "branches" : "branch"} visible). Everything under them is open.`, fix: "In Firebase → Realtime Database → Rules, require sign-in and limit each user to their own data.", ...P.rtdb() });
      }
    }
    for (const coll of FIRESTORE_GUESSES) {
      // pageSize=1 and a mask on a field that doesn't exist: at most one document name comes back, no fields.
      const q = `pageSize=1&mask.fieldPaths=__greenlit_none${firebase.key ? `&key=${firebase.key}` : ""}`;
      const r = await get(`https://firestore.googleapis.com/v1/projects/${firebase.project}/databases/(default)/documents/${coll}?${q}`, fetchOpts());
      let n = 0;
      try {
        n = (JSON.parse(r.text).documents || []).length;
      } catch {}
      if (r.status === 200 && n > 0) {
        firebaseOpen.push({ where: `Firestore "${coll}"` });
        add({ id: `firebase:firestore:${coll}`, severity: PERSONAL.test(coll) ? "critical" : "high", where: `Firestore collection "${coll}"`, title: `Anyone on the internet can read the Firestore collection "${coll}"`, why: "Your Firestore rules let visitors who aren't signed in read it. Greenlit asked for one document name and no fields; a stranger would take everything.", fix: `In Firebase → Firestore → Rules, close "${coll}" to everyone except its owner.`, ...P.firestore(coll) });
      }
    }
  }

  // --- launch basics: things that stop a live app working, read from what was already downloaded ---
  const hostName = new URL(origin).hostname;
  const isLocal = /^(localhost|127\.0\.0\.1|\[::1\])$/.test(hostName);
  const secure = origin.startsWith("https:");
  const scripts = bundles.slice(1);
  const inScripts = (re) => scripts.map((b) => b.text.match(re)).find(Boolean);
  if (!isLocal) {
    const inPage = page.text.match(/(?:src|href|action)=["'](https?:\/\/(?:localhost|127\.0\.0\.1)(?::\d+)?[^"']*)["']/i);
    // Libraries ship their own local defaults (Supabase auth on 9999, telemetry on 4317/4318, Sentry on 8969); those aren't the app's.
    // A bare http://localhost:3000 in a list is usually an allow-list (Lovable's own preview code has one), so only an address
    // with a path, or one used as a fallback or an API base, counts.
    const inCode = scripts
      .flatMap((b) => [...b.text.matchAll(/["'`](https?:\/\/(?:localhost|127\.0\.0\.1):(\d{2,5})(\/[A-Za-z0-9_][^"'`\s]{0,80})?)["'`]/g)].map((m) => ({ m, before: b.text.slice(Math.max(0, m.index - 40), m.index) })))
      .find(({ m, before }) => !["9999", "4317", "4318", "8969"].includes(m[2]) && (m[3] || /(?:fetch\(|axios\.\w+\(|baseURL\s*:|(?:api|base|server|backend)\w*\s*[:=]|\|\||\?\?)\s*$/i.test(before)))?.m;
    if (inPage) add({ id: "launch:localhost", severity: "high", where: "the page itself", title: "Your live app loads from an address that only works on a developer's computer", why: `The page points at ${inPage[1].slice(0, 80)}. Visitors' browsers can't reach that, so this part of the app is broken for everyone but its builder.`, fix: "Replace localhost addresses with the live address.", ...P.localhost(inPage[1].slice(0, 80)) });
    else if (inCode) add({ id: "launch:localhost", severity: "low", where: "your app's scripts", title: "Your app's code mentions a developer-only address", why: `The code contains ${inCode[1].slice(0, 80)}. If the live app ever uses it, that part won't work for visitors. It may only be a fallback, so check it.`, fix: "Make sure the live app never falls back to a localhost address.", ...P.localhost(inCode[1].slice(0, 80)) });
  }
  if (secure && /<(?:script|link|iframe)[^>]+(?:src|href)=["']http:\/\/(?!localhost|127\.)/i.test(page.text))
    add({ id: "launch:mixed", severity: "medium", where: "the page itself", title: "The page loads something over plain http", why: "Browsers block scripts, styles and frames loaded over http:// on an https:// page, so part of your app may silently not load.", fix: "Change the address to https://.", ...P.mixed() });
  const allCode = [page.text, ...scripts.map((b) => b.text)];
  if (allCode.some((t) => /\bpk_test_[0-9A-Za-z]{20,}/.test(t)) && !allCode.some((t) => /\bpk_live_[0-9A-Za-z]{20,}/.test(t)))
    add({ id: "launch:test-payments", severity: "medium", where: "your app's scripts", title: "Payments are still in test mode", why: "The app ships a Stripe test key (pk_test_) and no live key. Real customers can't pay you until it uses live keys.", fix: "Switch to your live Stripe keys.", ...P.testPayments() });
  const title = (page.text.match(/<title[^>]*>([^<]{0,120})<\/title>/i) || [])[1];
  if (title && DEFAULT_TITLE.test(title))
    add({ id: "launch:default-title", severity: "low", where: "the page itself", title: `Your app still has its default title, "${title.trim()}"`, why: "This is what shows in the browser tab, in Google and when someone shares your link.", fix: "Give the app a real title and description.", ...P.title(title.trim()) });
  if (/<meta[^>]+name=["']robots["'][^>]+content=["'][^"']*noindex/i.test(page.text) || /noindex/i.test(page.headers?.get("x-robots-tag") || ""))
    add({ id: "launch:noindex", severity: "low", where: "the page itself", title: "Your app tells Google not to list it", why: "A \"noindex\" setting is on. That's right for a private tool, and a problem if you want people to find the app by searching.", fix: "Remove the noindex setting if the app should be found.", ...P.noindex() });
  if (inScripts(AI_DIRECT))
    add({ id: "launch:ai-direct", severity: "low", where: "your app's scripts", title: "Your app seems to call an AI provider straight from the browser", why: "Calls made from the browser need the secret key in the browser, where anyone can copy it and run up your bill. If these calls really go through your own backend, this is fine.", fix: "Send AI calls through a backend function that checks the user and limits use.", ...P.aiDirect() });
  if (allCode.some((t) => /onboarding@resend\.dev/i.test(t)))
    add({ id: "launch:test-sender", severity: "low", where: "your app's scripts", title: "Your app's email still uses a test sender", why: "The code mentions onboarding@resend.dev, Resend's test address. Email from it reaches only your own inbox, so real users won't get sign-up or reset emails.", fix: "Send from an address on your own verified domain.", ...P.testSender() });
  for (const c of page.headers?.getSetCookie?.() || []) {
    const name = c.split("=")[0].trim();
    if (!secure || PLATFORM_COOKIE.test(name) || !/sess|sid|auth|token|jwt|login/i.test(name)) continue;
    if (/;\s*secure/i.test(c) && /;\s*httponly/i.test(c)) continue;
    add({ id: `launch:cookie:${name}`, severity: "medium", where: "response headers", title: `The sign-in cookie "${name}" isn't locked down`, why: "Without the Secure and HttpOnly flags, the cookie can travel over plain http or be read by any script on the page, which is how sessions get stolen.", fix: "Set Secure, HttpOnly and SameSite on session cookies.", ...P.cookie(name) });
    break;
  }
  if (bundles.length > 1 && !unread && !cut && !allCode.some((t) => /privacy/i.test(t)))
    add({ id: "launch:no-privacy", severity: "info", where: "the page and its scripts", title: "Greenlit couldn't see a privacy policy", why: "Nothing in the page or its code mentions one. If your app collects emails, names or payments, most countries expect a privacy policy that visitors can open.", fix: "Add a privacy policy page and link it from the footer and the sign-up form.", first: null, prompt: null, checkPrompt: "Add a privacy policy page and a terms page to my app, linked from the footer and from the sign-up form. Draft them from what the app actually collects and which services it sends data to, list those for me, and mark anything a lawyer should check." });

  // Two single requests: does plain http send visitors to https, and will the app hand a signed-in visitor's data to any site?
  if (secure && !isLocal) {
    // The CLI passes its own probe (see node-probe.mjs); on the web, fetch follows the redirect and reports where it ended.
    const plainUrl = `http://${new URL(origin).host}/`;
    const plain = httpProbe ? await httpProbe(plainUrl) : await get(plainUrl, fetchOpts({ max: 2048, timeout: 6000 }));
    if (httpProbe ? plain.status === 200 : plain.status === 200 && /^http:/i.test(plain.url || ""))
      add({ id: "launch:no-https-redirect", severity: "medium", where: "your host", title: "The plain http address doesn't send visitors to https", why: "Someone who types your address without https gets an unprotected page, where passwords can be read on shared Wi-Fi.", fix: "Turn on \"always use HTTPS\" in your host's settings.", ...P.httpsRedirect() });
    const probe = "https://greenlit-origin-check.example";
    const cors = await get(pageUrl, fetchOpts({ max: 2048, timeout: 6000, headers: { origin: probe } }));
    if (cors.headers?.get("access-control-allow-origin") === probe && /true/i.test(cors.headers?.get("access-control-allow-credentials") || ""))
      add({ id: "launch:cors", severity: "high", where: "response headers", title: "Any website can read your app's responses as a signed-in visitor", why: "The app repeats back whatever site asks and allows logins to be attached. A malicious page your user visits could read their data from your app.", fix: "Allow only your own site's address in the CORS settings.", ...P.cors() });
  }

  // Lovable's own hosting sets the response headers, and this protection can't be added from inside an app
  // (a meta tag can't do it). What the owner can't change is shown, and costs no points.
  const hostSetsHeaders = /\.lovable\.app$/i.test(new URL(origin).hostname);
  // --- your own domain: can your email be trusted? Looked up in public DNS; skipped on a builder's address. ---
  const onBuilderHost = BUILDER_HOST.test(hostName);
  if (onBuilderHost)
    add({ id: "domain:builder", severity: "info", where: "your address", title: "You're still on the builder's address", why: `${hostName} belongs to your builder or host. Until the app is on a domain you own, you can't send email in your own name, and the host decides its security settings${hostSetsHeaders && !page.headers?.get("x-frame-options") && !/frame-ancestors/i.test(page.headers?.get("content-security-policy") || "") ? " (for example, other sites can show this app in a frame, and only the host can change that, so it costs you no points)" : ""}.`, fix: "Connect your own domain before you launch widely. Then check again here: Greenlit will also check the domain's email records.", first: null, prompt: null });
  else if (!isLocal && hostName.includes(".")) {
    const apex = siteKey(hostName);
    const txt = async (name) => {
      const r = await get(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=TXT`, fetchOpts({ max: 65536, timeout: 6000, headers: { accept: "application/dns-json" } }));
      try {
        const j = JSON.parse(r.text);
        if (j.Status !== 0 && j.Status !== 3) return null;
        return (j.Answer || []).filter((a) => a.type === 16).map((a) => String(a.data).replace(/^"|"$/g, "").replace(/"\s+"/g, ""));
      } catch {
        return null; // the lookup didn't work, which is not the same as "no record"
      }
    };
    const dmarc = await txt(`_dmarc.${apex}`);
    if (dmarc && !dmarc.some((t) => /^v=DMARC1/i.test(t)))
      add({ id: "email:no-dmarc", severity: "medium", where: `DNS for ${apex}`, title: `Anyone can send email pretending to be ${apex}`, why: "The domain has no DMARC record, the setting that tells Gmail and Outlook what to do with fakes. Without it, your real sign-up and reset emails are also more likely to land in spam.", fix: `Add a DMARC record at _dmarc.${apex}.`, ...P.dmarc(apex) });
    const spf = (await txt(apex))?.filter((t) => /^v=spf1/i.test(t));
    if (spf && (spf.length > 1 || spf.some((t) => /\+all\b/i.test(t))))
      add({ id: "email:spf-broken", severity: "medium", where: `DNS for ${apex}`, title: `The email sender record for ${apex} is broken`, why: spf.length > 1 ? "The domain has more than one SPF record. Mail servers treat that as an error, so your emails can fail their checks." : "The SPF record ends in +all, which tells the world that anyone may send email as you.", fix: "Keep exactly one SPF record, ending in ~all or -all.", ...P.spf(apex) });
  }

  if (!page.headers?.get("content-security-policy") && !/http-equiv=["']Content-Security-Policy/i.test(page.text))
    add({ id: "csp", severity: "low", where: "response headers", title: "No Content-Security-Policy", why: "If an attacker gets a script into the page (through a comment, a profile field or a dependency), nothing stops it from sending your users' data out.", fix: "Add a Content-Security-Policy header in your host's settings.", ...P.csp([...thirdParty].slice(0, 6)) });

  const csp = page.headers?.get("content-security-policy") || "";
  if (!page.headers?.get("x-frame-options") && !/frame-ancestors/i.test(csp)) {
    if (!hostSetsHeaders)
      add({ id: "framing", severity: "low", where: "response headers", title: "Other sites can put your app in a frame", why: "A malicious page can show your app inside an invisible frame and trick your users into clicking buttons they can't see (clickjacking).", fix: "Add the header Content-Security-Policy: frame-ancestors 'self' (or X-Frame-Options: DENY).", ...P.framing() });
  }

  // Small things add up to 20 points at most, so missing headers alone can never fail an app.
  // One critical problem is an F whatever else is right: it can't be averaged away.
  const sum = (kinds) => findings.reduce((a, f) => a + (kinds.includes(f.severity) ? SEVERITY[f.severity] : 0), 0);
  const penalty = sum(["critical", "high"]) + Math.min(20, sum(["medium", "low"]));
  const blocker = findings.some((f) => f.severity === "critical");
  const score = Math.min(Math.max(0, 100 - penalty), blocker ? 39 : 100);
  // With none of the app's code read and nothing serious seen, there's no honest grade to give.
  const ungraded = noCodeRead && penalty < SEVERITY.high;
  const grade = ungraded ? "?" : blocker ? "F" : score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";
  // A good grade says only what was looked at, so it can't be read as "the database is safe too".
  const good = grade === "A" || grade === "B";
  const incomplete = unread > 0 || cut > 0;
  const verdict = ungraded
    ? "Not graded: Greenlit couldn't read this app's code."
    : good && (dbBlind || supabasePartial)
      ? `Nothing serious in the ${incomplete ? "code Greenlit read" : "code"}. Your database tables weren't checked.`
      : good && database && !mine
        ? `Nothing serious in the ${incomplete ? "code Greenlit read" : "code"}. Your database still needs checking.`
      : good && incomplete
        ? "Nothing serious in the code Greenlit read. Some of it wasn't read."
        : VERDICT[grade];
  const order = ["critical", "high", "medium", "low", "info"];
  findings.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
  return {
    url: origin,
    builder,
    score: ungraded ? null : score,
    grade,
    verdict,
    mine,
    scripts: bundles.length - 1,
    scriptsUnread: unread,
    supabase: supabase ? { project: supabase.ref, checked: Boolean(mine && tables && !dbBlind), tablesTested, tablesListed, readable: tables, functions: [...functions].slice(0, 50), edgeFunctions: [...edge].slice(0, 50) } : null,
    firebase: firebase ? { project: firebase.project, checked: mine, readable: firebaseOpen } : null,
    findings,
    pasteInto: builder || "your AI app builder or coding agent",
    // Only for the report endpoint, which looks for the owner's tag in the page.
    ...(wantPage && { page: page.text.slice(0, 200000) }),
  };
}

// Every fix prompt in one, worst first, for people who'd rather paste once. The builder still gets one
// problem at a time, and checks in after each.
export function allPrompts(r) {
  const list = r.findings.filter((f) => f.prompt);
  if (!list.length) return "";
  const head = `My app has ${list.length} security problem${list.length > 1 ? "s" : ""} to fix. Work through them in this order, one at a time. After each one, tell me what you changed before moving on. Don't change anything unrelated.`;
  return [head, ...list.map((f, i) => `${i + 1}. ${f.title}.\n${f.prompt}`)].join("\n\n");
}

export const VERDICT = {
  A: "Nothing serious a stranger can use against you.",
  B: "No open doors, a few loose ends.",
  C: "Fix these before you share the link widely.",
  D: "A stranger can do real damage. Fix the red items today.",
  F: "Your users' data or your accounts are exposed right now. Fix the red items before anything else.",
};

// --- re-check ------------------------------------------------------------------------------------
// What changed between two runs: fixed, still open, new.
export function compare(prev, result) {
  if (!prev) return null;
  const now = new Map(result.findings.map((f) => [f.id, f]));
  const before = new Map(prev.findings.map((f) => [f.id, f]));
  return {
    since: prev.at,
    before: { score: prev.score, grade: prev.grade },
    after: { score: result.score, grade: result.grade },
    fixed: prev.findings.filter((f) => !now.has(f.id)).map((f) => f.title),
    open: result.findings.filter((f) => before.has(f.id)).map((f) => f.title),
    new: result.findings.filter((f) => !before.has(f.id)).map((f) => f.title),
  };
}

// --- the report a person reads ---------------------------------------------------------------------
const wrap = (s, w = 92, pad = "    ") => {
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

export function renderSite(r, change, { color = true, mine = r.mine } = {}) {
  const k = (code) => (s) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
  const red = k("31"), green = k("32"), yellow = k("33"), dim = k("2"), bold = k("1"), cyan = k("36");
  const col = { critical: red, high: red, medium: yellow, low: dim, info: dim };
  const gcol = r.grade === "A" || r.grade === "B" ? green : r.grade === "C" || r.grade === "?" ? yellow : red;
  const L = [];
  L.push("", `${bold("Greenlit check")} · ${r.url}${r.builder ? ` · built with ${r.builder}` : ""} · ${r.scripts} scripts read${r.supabase ? " · Supabase" : ""}${r.firebase ? " · Firebase" : ""}`, "");
  L.push(`  Grade ${gcol(bold(r.grade))}  ${r.score == null ? "" : `${gcol(`${r.score}/100`)}  `}${r.verdict}`);
  if (change) {
    const arrow = change.after.score > change.before.score ? green : change.after.score < change.before.score ? red : dim;
    L.push(`  ${arrow(`Was ${change.before.grade} (${change.before.score}) on ${change.since.slice(0, 10)}, now ${change.after.grade} (${change.after.score}).`)}`);
    for (const t of change.fixed) L.push(`  ${green("✓ fixed")}  ${t}`);
    for (const t of change.new) L.push(`  ${red("+ new")}    ${t}`);
    if (!change.fixed.length && !change.new.length) L.push(dim("  Nothing changed since the last check."));
  }
  L.push("");
  if (!r.findings.length) L.push(green("  Nothing found."), "");
  let n = 0;
  for (const f of r.findings) {
    const num = f.prompt ? `${++n}.` : "  ";
    L.push(`${num.padStart(3)} ${col[f.severity](f.severity.toUpperCase().padEnd(8))} ${bold(f.title)} ${dim(`(${f.where})`)}`);
    L.push(wrap(f.why, 88, "             "));
    if (f.first) L.push(wrap(`${yellow("Do this yourself first:")} ${f.first}`, 88, "             "));
    if (f.prompt) {
      L.push(`             ${cyan(`Then paste this into ${r.pasteInto}:`)}`);
      L.push(wrap(f.prompt, 84, `             ${dim("│")} `));
    } else {
      L.push(wrap(`${green("Next:")} ${f.fix}`, 88, "             "));
      if (f.checkPrompt) {
        L.push(`             ${cyan(`Or paste this into ${r.pasteInto} to have it check:`)}`);
        L.push(wrap(f.checkPrompt, 84, `             ${dim("│")} `));
      }
    }
    L.push("");
  }
  if (r.supabase?.checked) L.push(dim(`Supabase: ${r.supabase.tablesTested} table${r.supabase.tablesTested === 1 ? "" : "s"} tested with the public key, ${r.supabase.readable.length} readable by anyone.${r.supabase.tablesListed ? "" : " Only tables named in your app's code could be tested; Supabase's Security Advisor lists them all."}`));
  else if (mine && r.supabase) L.push(dim("Supabase: no tables were tested. See the note above."));
  L.push(dim(`Read only what the site serves to every visitor${mine ? "; database checked with counts and names only, never data" : ""}.`));
  if (n) {
    L.push(dim(`Fix the red items first, one prompt at a time. Copy one prompt: npx greenlitlab ${new URL(r.url).host}${mine ? " --mine" : ""} --prompt 1 | pbcopy  (or --prompt all for every fix in one)`));
    L.push(dim("After the fixes are live, run this same command again: it shows what got fixed."));
  }
  return L.join("\n");
}
