// Real leaks the simulator replays. The pretend app gets the same setting; the headline is the public record, and
// `match` picks the incident in data/patterns.json, so the date, source and link always come from there.
// scripts/sim-cards.mjs builds a share card and a share page (case/<id>/) for each one from this file.
window.CASES = {
  moltbook: { label: "Moltbook: Row Level Security never switched on", pattern: "no-rls", match: "Moltbook", open: ["no-rls"],
    headline: "1.5 million API tokens and 35,000 email addresses, readable and writable by anyone" },
  crissy: { label: "the scan of 159,041 Lovable projects", pattern: "no-rls", match: "Crissy Field", open: ["no-rls", "open-policy"],
    headline: "24,664 of 34,545 projects using Supabase handed records to a visitor with no login" },
  tea: { label: "Tea: the ID-photo bucket left open", pattern: "public-storage", match: "Tea app", open: ["public-storage"],
    headline: "72,000 images accessed, 13,000 of them verification selfies and IDs" },
  supersecret: { label: '"supersecretkey": one login secret in over a thousand apps', pattern: "hardcoded-auth-secret", match: "Invicti", open: ["hardcoded-auth-secret"],
    headline: 'the string "supersecretkey" in 1,182 of 20,656 AI-generated apps' },
};
