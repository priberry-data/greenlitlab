// What no check can see: seven things only the owner knows. Answers are never graded, because Greenlit can't
// verify them. Each "not yet" answer comes with the platform fact that makes it matter and a prompt or step to fix it.
export const QUESTIONS = [
  {
    id: "backup",
    ask: "If your database were wiped tonight, could you get yesterday's data back?",
    options: [
      { key: "yes", label: "Yes, and I've tried a restore", ok: true },
      { key: "auto", label: "The platform backs it up, I've never restored", ok: false, note: "A backup you have never restored is a hope, not a backup. Supabase's free plan keeps no automatic backups at all, and files in storage are never in database backups on any plan.", prompt: "Walk me through restoring my database from a backup into a separate test project, step by step for my provider, so I know it works. Don't touch the live database." },
      { key: "no", label: "No / I don't know", ok: false, note: "Supabase's free plan has no automatic backups, and free projects can be paused after a week of low activity. One bad AI edit or one deleted table is permanent.", prompt: "Set up a backup for my database that I control. If I'm on a free plan, give me a scheduled export (for Supabase: a pg_dump run from a GitHub Action to private storage, with the connection string kept in a secret). Tell me how to restore from it, and remind me which files in storage are not included." },
    ],
  },
  {
    id: "separate",
    ask: "Can your AI builder or coding agent change the live database directly?",
    options: [
      { key: "no", label: "No, it works on a separate test database", ok: true },
      { key: "yes", label: "Yes, there is only one database", ok: false, note: "In July 2025 an AI agent deleted a company's production database during a code freeze, because test and live shared one database. The platform's fix was to separate them.", prompt: "Set up a separate development database for this app, so that changes are tried there first and the live database is only changed by a reviewed migration. Make sure you (the AI) hold no credentials that can delete or reset the live database, and tell me how to confirm that." },
      { key: "unsure", label: "I don't know", ok: false, note: "If you can't tell, assume there is only one. Ask your builder: \"Do preview and live use the same database?\"", prompt: "Tell me whether my preview/development environment and my live app use the same database, and whether you can run destructive commands (drop, truncate, reset) on the live one. Change nothing." },
    ],
  },
  {
    id: "spend",
    ask: "Is there a hard monthly spending limit on every paid service (AI, email, SMS, hosting)?",
    options: [
      { key: "yes", label: "Yes, hard limits everywhere", ok: true },
      { key: "alerts", label: "Only alerts, no hard limit", ok: false, note: "An alert tells you after the money is gone. A three-person team reported an $82,314 AI bill in about 48 hours after a key was stolen. Firebase's own checklist warns that budget alerts don't cap spending.", prompt: "List every paid service my app uses (AI providers, email, SMS, hosting, database). For each, tell me exactly where to set a hard monthly limit or usage cap in its dashboard, and what happens to my app when the cap is reached." },
      { key: "no", label: "No / I don't know", ok: false, note: "One leaked key or one loop can spend without limit. Set a hard cap in each provider's billing page (OpenAI: Limits; Anthropic: spend limits; Google Cloud: quotas, not just budgets).", prompt: "List every paid service my app uses (AI providers, email, SMS, hosting, database). For each, tell me exactly where to set a hard monthly limit or usage cap in its dashboard, and what happens to my app when the cap is reached. Then add a per-user daily limit in my backend for every AI and email call." },
    ],
  },
  {
    id: "payments",
    ask: "If you take payments: does your server check that payment messages really come from the payment company?",
    options: [
      { key: "na", label: "I don't take payments", ok: true },
      { key: "yes", label: "Yes, signatures are verified and live mode is set up", ok: true },
      { key: "no", label: "No / I don't know", ok: false, note: "Without signature checks anyone can send your app a fake \"payment succeeded\" message and unlock paid features. Stripe's go-live checklist also requires a webhook registered for the live address with its own signing secret.", prompt: "Check my payment integration and change nothing yet. Tell me: does the webhook handler verify the Stripe-Signature header using the raw request body and the signing secret from a server secret; is \"paid\" decided on the server from that verified message and never from the browser; and is a webhook registered in live mode for my live address? Then fix whatever fails and list what you changed." },
    ],
  },
  {
    id: "down",
    ask: "If the app went down right now, would you know within an hour?",
    options: [
      { key: "yes", label: "Yes, something alerts me", ok: true },
      { key: "no", label: "No, I'd hear it from users", ok: false, note: "Free uptime monitors check every few minutes and email you. Without one, most small apps learn about outages from an angry message.", prompt: "Add a simple health check address to my app that returns OK only when the app can reach its database. Then tell me how to point a free uptime monitor at it so I get an email when it fails, and add error tracking so I see errors my users hit." },
    ],
  },
  {
    id: "email",
    ask: "Which address do your sign-up and password-reset emails come from?",
    options: [
      { key: "own", label: "An address on my own domain, through an email service", ok: true },
      { key: "none", label: "The app sends no email", ok: true },
      { key: "builtin", label: "The platform's built-in sender / I never set it up", ok: false, note: "Supabase's built-in email is for testing: about 2 messages an hour, and only to members of your own project team. Real users won't get their confirmation or reset emails.", prompt: "Set up real email sending for my app's sign-up and password-reset messages: connect an email service (such as Resend) as custom SMTP in my auth settings, send from an address on my own domain, and tell me exactly which DNS records (SPF, DKIM, DMARC) to add at my domain provider. Then tell me how to test that a reset email arrives." },
    ],
  },
  {
    id: "plan",
    ask: "Is your database on a free plan?",
    options: [
      { key: "paid", label: "No, a paid plan", ok: true },
      { key: "free", label: "Yes, free", ok: false, note: "Fine for building. For a launch, know the limits: Supabase may pause a free project after a week of low activity, keeps no automatic backups, and caps connections. A busy launch day can hit those.", prompt: "Tell me which limits of my database's free plan my app is most likely to hit after launch (pausing, backups, connections, storage, bandwidth, email), how I would notice each, and what the cheapest plan that removes them costs." },
      { key: "unsure", label: "I don't know", ok: false, note: "Check the billing page of your database provider. On a free plan there are usually no automatic backups.", prompt: "Tell me which plan my database is on and what its limits are. Change nothing." },
    ],
  },
];

export function advise(answers = {}) {
  return QUESTIONS.map((q) => {
    const o = q.options.find((o) => o.key === answers[q.id]);
    return { id: q.id, ask: q.ask, answer: o?.label || null, ok: o ? o.ok : null, note: o?.note || null, prompt: o?.prompt || null };
  });
}
