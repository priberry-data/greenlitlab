# Changelog

## 0.2.1 (9 November 2026)

- Reads all of an app's code: lazy-loaded pages (Vite and Next.js chunk lists), every import form, chains of any depth, scripts with `?v=` addresses, and scripts on the app's own CDN. It used to stop after two rounds, so most code in larger apps went unread.
- Says what it didn't read. If a check runs out of room it reports how many scripts were left. If none of the app's code could be read, it gives no grade instead of an A.
- Grades match the danger: one critical problem means D at best, one high problem means C at best (a leaked master key used to earn a C, and a public `.git` folder a B).
- An A or B no longer sounds like an all-clear when the database wasn't checked, and there's now a prompt that has your builder check the database, for people without a terminal.
- A builder's "website not found" page, served with status 200, is now reported as not found instead of graded A.
- Clear errors in the CLI too, including for an address that doesn't exist.
- Web: the script and stylesheet addresses carry the version, because the 4-hour browser cache otherwise left returning visitors on old code after a deploy.
- Web: progress and errors now appear under the box instead of off screen. Results refresh after 2 minutes instead of 10, and the limit is 30 checks an hour.

## 0.2.0 (8 November 2026)

- 18 more kinds of leaked keys: Supabase secret keys (sb_secret_) and access tokens, OpenRouter, xAI, Perplexity, Hugging Face, Replicate, Pinecone, GitLab, npm, Shopify, Brevo, Mailchimp, Mailgun, Telegram bots, secret Mapbox tokens, private keys and Google service-account JSON. `sk_live_` keys are named for Stripe, Clerk and similar.
- Clickjacking: flags a site any other site can put in a frame.
- With `--mine`: Supabase sign-up open to anyone without email confirmation (which turns "signed-in only" rules into "anyone"), storage buckets that list files to anyone, and public `.env` files or `.git` folders. Hosts that answer every path with the home page don't count.
- "Copy all fixes": every fix prompt in one, worst first, on the web, with `--prompt all`, and as `allFixes` in the MCP tool.

## 0.1.1 (8 November 2026)

- Hosts that answer every missing file with the home page (Lovable, Netlify, Vercel) are no longer reported as publishing source maps.
- Using a database is a note, not a problem: it costs no points.
- A broken script address in a page, or a huge file, no longer stops or slows the check. Scripts load six at a time.
- The web check keeps results and visitor limits in Cloudflare's cache, so a busy day can't use up the free plan's storage writes. Errors are in plain words.
- Clear error for anything that isn't a web address.

## 0.1.0 (8 November 2026)

First release. Greenlit grew out of `crumple site` and is now its own product.

- Grades a deployed app A to F: secret keys in its JavaScript, a Supabase service_role key, source maps, security headers.
- With `--mine`: Supabase tables and Firebase data anyone can read, counted without reading data.
- Recognises Lovable, Bolt, Replit, Emergent, Base44 and v0, and writes each fix prompt for that builder.
- Shows what got fixed since the last check.
- Web check at greenlit.priberry.com, and an MCP server with one tool, `greenlit_check`.
