# Changelog

## 0.4.0 (10 November 2026)

Greenlit now checks launch readiness, not only leaks. Only things it confirmed move the grade; what it couldn't see is said, and what only you know is asked.

- Launch basics, read from what is already downloaded: a page that loads from a developer-only address, plain-http content on an https page, Stripe still in test mode, a default page title, an accidental "noindex", AI calls made straight from the browser, a test email sender, sign-in cookies without Secure and HttpOnly, and no privacy policy in sight. Two single requests check that plain http redirects to https and that the app doesn't hand a signed-in visitor's data to any website.
- Two more secret shapes: database addresses with a password, and Stripe webhook signing secrets (32 kinds in all).
- Your own domain: no DMARC record, or a broken SPF record, found through public DNS. Skipped on a builder's address, where it says so.
- `--mine`: for tables strangers can read, asks whether personal columns (email, phone, password and the like) exist, never for their values, and names them. Backend functions the app calls are listed with a prompt to check each; Greenlit never calls them.
- `greenlit advisor results.json`: Supabase's own Security Advisor in plain words with a fix prompt for each result. This is how to find rules that are too loose, and tables strangers can change, without Greenlit ever writing to a database.
- `greenlit scan [folder]`: reads your project's files for always-true policies, tables created without Row Level Security, functions with the sign-in check off, unverified Stripe webhooks, secrets behind a public prefix, a tracked .env file and a writable database connection in an agent's config. Reads names in .env files, never values.
- `greenlit questions`: seven things only you know (backups, a separate test database, spending limits, payment checks, outage alerts, email sender, database plan). Never graded. Also on the web result.
- Web: an owner can publish a dated report page and a badge for their own app, after adding a tag that proves it is theirs. Both show the date and expire after 30 days.
- The MCP server has three new tools: `greenlit_scan`, `greenlit_advisor`, `greenlit_questions`.
- After an independent review of this release, before it reached npm: example values in library text (placeholder passwords, `whsec_xxxx…`) are never reported as leaks; a table is "about people" only by whole words in its name, so `leaderboard` and `border_styles` are not; only secret columns make a readable table critical on their own; the public key now names the real Supabase project when the code mentions several; a refused key and a table that times out are said, not counted as closed; the owner's domain is found on country domains such as `.ne.jp` and `.me.uk`; shared hosts such as `herokuapp.com` are nobody's to fix; plain links and canonical tags load nothing; CSRF cookies are left alone; an app served only over http is said to be; checks that got no answer are listed; `--fail-on` exits 3 when the code couldn't be read; `scan` reads Supabase's `"public"."table"` form, skips comments, private schemas and service-role policies, and only names ending in a secret word are secrets; `advisor` refuses an error message instead of calling it clean.
- Reports: nothing is stored until a tagged page has been seen; the tag must be in the page's `<head>`; a report is removed when the tag is gone and kept 90 days at most; the page says anyone can refresh it.
- The CLI asks for the plain-http address the way a browser does, because some sites answer Node's own fetch differently.

## 0.3.0 (10 November 2026)

- Fixed: `--mine` was reporting nothing open when it had tested nothing. Supabase stopped listing a project's tables for the public key in 2026, and Greenlit relied on that list. It now takes table names from the app's own code, reports how many tables it tested, and says plainly when it could test none.
- Storage buckets named in the app's code are checked too, not only the nine common names. Database functions the app calls are listed in the JSON result and never called.
- An app that shows signs of Supabase without both its address and public key is reported as "database not checked" instead of nothing.
- Grades: one critical problem is now an F whatever else is right. Medium and low findings together take 20 points at most, so missing headers alone can never fail an app.
- Fairness: on a lovable.app address, missing frame protection is shown but costs no points, because the host sets those headers.

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
