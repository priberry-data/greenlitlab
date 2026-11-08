# Security and scanning policy

## How Greenlit checks a site

- The web check and `npx greenlitlab <url>` read only what the site serves to every visitor: the page and the JavaScript it loads from its own address. They never sign in and never send data to the app.
- Database checks run only with `--mine`, on the person's own computer, for an app they say is theirs. They ask Supabase for a row count with a `HEAD` request and Firebase for one document name with no fields. They never read rows or documents.
- The web check never runs database checks, refuses internal addresses, IP addresses and unusual ports, limits each visitor to 20 checks an hour, and caches each result for ten minutes so nobody can use it to hammer a site.
- When a secret key is found, the web result never shows any part of it.
- We don't publish grades for other people's apps.

## Reporting a vulnerability

Please open a private security advisory on GitHub: https://github.com/priberry-data/greenlitlab/security/advisories/new
