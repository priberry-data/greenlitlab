// Supabase's own Security Advisor knows things nobody can see from outside: which rules are too loose, which
// functions strangers may run. Its results are written for database people. This turns them into Greenlit
// findings: plain words, worst first, a fix prompt for each. Input is the advisor's JSON (from the Supabase
// dashboard, the Supabase MCP server's get_advisors tool, or the Management API). Nothing is sent anywhere.
// Advisor text is written as SQL strings, with escaped backticks and underscores.
const clean = (t) => String(t).replace(/\\/g, "").replace(/`/g, "");
const thing = (l) => l.metadata?.name || l.metadata?.entity || (l.detail || "").match(/[`"\\]+([\w.]+)[`"\\]+/)?.[1] || "your database";

// name: [severity, title, why]
const KNOWN = {
  rls_disabled_in_public: ["critical", (t) => `Anyone may be able to read and change "${t}"`, "Row Level Security is switched off for this table, so the app's public key reaches every row."],
  policy_exists_rls_disabled: ["critical", (t) => `The rules on "${t}" are written but switched off`, "The table has security policies, but Row Level Security isn't enabled, so none of them apply."],
  sensitive_columns_exposed: ["critical", (t) => `"${t}" exposes personal or secret columns to anyone`, "The table holds columns such as emails, passwords or tokens and has no Row Level Security."],
  auth_users_exposed: ["critical", (t) => `Your list of users is exposed through "${t}"`, "A view or table gives the public key a way to read your sign-in records."],
  rls_policy_always_true: ["high", (t) => `A rule on "${t}" lets everyone through`, "A policy uses a condition that is always true, so Row Level Security is on but protects nothing for that action."],
  rls_references_user_metadata: ["high", (t) => `A rule on "${t}" trusts data users can edit themselves`, "The policy reads user_metadata, which any signed-in user can change, so anyone can give themselves access."],
  security_definer_view: ["high", (t) => `The view "${t}" skips your security rules`, "It runs with its creator's rights, so anyone who can read the view sees rows the rules would hide."],
  anon_security_definer_function_executable: ["high", (t) => `Strangers can run the admin-rights function "${t}"`, "This function runs with elevated rights and can be called without signing in."],
  authenticated_security_definer_function_executable: ["medium", (t) => `Any signed-in user can run the admin-rights function "${t}"`, "This function runs with elevated rights. Check that it tests who is calling before it acts."],
  public_bucket_allows_listing: ["high", (t) => `Anyone can list the files in the bucket "${t}"`, "A public bucket has a policy that lets anyone see every file name in it."],
  rls_enabled_no_policy: ["low", (t) => `"${t}" is locked to everyone, including your app`, "Row Level Security is on with no policy, so nothing can read it through the app. Safe, but a feature may be broken."],
  function_search_path_mutable: ["low", (t) => `The function "${t}" should pin its search path`, "Without a fixed search_path, a function can be tricked into running someone else's code."],
  auth_leaked_password_protection: ["low", () => "Passwords known to be leaked are accepted", "Supabase can refuse passwords found in past breaches, and that check is off."],
  auth_otp_long_expiry: ["low", () => "Sign-in codes stay valid too long", "Email codes and links that last more than an hour give a thief more time to use them."],
  auth_insufficient_mfa_options: ["low", () => "Two-step sign-in is barely available", "Too few second-factor options are enabled for your users."],
  vulnerable_postgres_version: ["medium", () => "Your database version has security fixes waiting", "Supabase has a patched Postgres version for this project."],
};
const BY_LEVEL = { ERROR: "high", WARN: "medium", INFO: "low" };
const ORDER = ["critical", "high", "medium", "low", "info"];

export function fromAdvisor(input) {
  let raw = input;
  if (typeof input === "string") {
    try {
      raw = JSON.parse(input);
    } catch {
      throw new Error("that isn't JSON. Pass the advisor's results as exported: a list of lints.");
    }
  }
  const lints = [raw, raw?.lints, raw?.result?.lints, raw?.result, raw?.data?.lints, raw?.data].find(Array.isArray);
  // An error message or an empty object is not "the advisor found nothing".
  if (!lints) throw new Error(`that doesn't look like Supabase advisor output (expected a list of lints)${raw?.message || raw?.error ? `. It says: ${String(raw.message || raw.error).slice(0, 120)}` : ""}`);
  const findings = [];
  const seen = new Set();
  let skipped = 0;
  for (const l of lints) {
    if (!l || typeof l !== "object" || !(l.name || l.title)) {
      skipped++;
      continue;
    }
    const lint = l.name || String(l.title).toLowerCase().replace(/[^a-z0-9]+/g, "_");
    const speed = (l.categories || []).includes("PERFORMANCE") && !(l.categories || []).includes("SECURITY");
    const t = thing(l);
    const k = KNOWN[lint];
    // Two policies on one table, or one table name in two schemas, are separate results.
    const id = `advisor:${lint}:${l.cache_key || `${l.metadata?.schema || ""}.${t}:${l.detail || ""}`}`.slice(0, 200);
    if (seen.has(id)) continue;
    seen.add(id);
    const severity = k ? k[0] : speed ? "low" : BY_LEVEL[l.level] || "low";
    const title = k ? k[1](t) : `${l.title || l.name}${t !== "your database" ? `: ${t}` : ""}`;
    const why = `${k ? k[2] : l.description || "Reported by Supabase's advisor."}${l.detail ? ` Supabase says: ${clean(l.detail)}` : ""}`;
    const prompt = `Supabase's ${speed ? "Performance" : "Security"} Advisor reports "${l.title || l.name}" for ${t}. ${l.detail ? `${clean(l.detail)} ` : ""}Fix it${l.remediation ? ` following ${l.remediation}` : ""}. Don't loosen or remove any existing policy, keep each user limited to their own rows, and show me the SQL you ran. If fixing it could break a feature of the app, tell me which before you change anything.`;
    findings.push({ id, severity, where: speed ? "Supabase Performance Advisor" : "Supabase Security Advisor", title, why, fix: l.remediation || "See Supabase → Advisors.", first: null, prompt });
  }
  if (lints.length && skipped === lints.length) throw new Error("none of those items look like advisor results (each should have a name or a title)");
  findings.sort((a, b) => ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity));
  return { source: "Supabase advisor", lints: lints.length, skipped, findings };
}

// The words an agent or a person needs to get the advisor output in the first place.
export const ADVISOR_HOW = `Where to get the advisor results:
  - With a coding agent that has the Supabase MCP server: ask it to run get_advisors (type "security") for your project and pass the result to greenlit_advisor.
  - By hand: Supabase dashboard → Advisors → Security Advisor → copy or export the results as JSON, save them to a file, and run: npx greenlitlab advisor results.json`;
