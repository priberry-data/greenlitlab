# Changelog

## 0.1.0 (8 November 2026)

First release. Greenlit grew out of `crumple site` and is now its own product.

- Grades a deployed app A to F: secret keys in its JavaScript, a Supabase service_role key, source maps, security headers.
- With `--mine`: Supabase tables and Firebase data anyone can read, counted without reading data.
- Recognises Lovable, Bolt, Replit, Emergent, Base44 and v0, and writes each fix prompt for that builder.
- Shows what got fixed since the last check.
- Web check at greenlit.priberry.com, and an MCP server with one tool, `greenlit_check`.
- Hosts that answer every missing file with the home page (Lovable, Netlify, Vercel) are no longer reported as publishing source maps.
- Using a database is a note, not a problem: it costs no points.
- A broken script address in a page, or a huge file, no longer stops or slows the check. Scripts load six at a time.
- The web check keeps results and visitor limits in Cloudflare's cache, so a busy day can't use up the free plan's storage writes. Errors are in plain words.
