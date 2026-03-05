# nets.w4trc.org

Cloudflare Worker for W4TRC net logging — net control submission, signup scheduling, admin views, and email notifications via Resend.

## Stack

- **Runtime:** Cloudflare Workers (TypeScript)
- **Database:** Cloudflare D1 (SQLite) — binding `DB`, database `w4trc_netlogs`
- **Email:** [Resend](https://resend.com) API
- **CAPTCHA:** Cloudflare Turnstile
- **Error tracking:** Sentry (`@sentry/cloudflare`)
- **Tests:** Vitest + `@cloudflare/vitest-pool-workers`

---

## Dev Commands

```bash
# Install dependencies
npm install

# Local dev server (Wrangler)
npm run dev

# Deploy to Cloudflare
npm run deploy

# Run tests
npm test

# Regenerate Worker type bindings (after wrangler.jsonc changes)
npm run cf-typegen
```

---

## Secrets (set via Wrangler)

These must be added as secrets — never put them in `wrangler.jsonc`.

```bash
wrangler secret put ADMIN_PASSWORD          # password for /view detail pages
wrangler secret put RESEND_API_KEY          # Resend API key for outbound email
wrangler secret put TURNSTILE_SECRET_KEY    # Cloudflare Turnstile private key
wrangler secret put SIGNUP_NOTIFY_TOKEN     # shared secret for /signup/notify/upcoming
wrangler secret put SENTRY_DSN              # Sentry DSN (optional)
```

---

## Vars (set in wrangler.jsonc)

Non-secret config already in `wrangler.jsonc`:

| Var | Value | Notes |
|-----|-------|-------|
| `DISTRO` | `netcontrol@w4trc.org` | Comma-separated email distribution list for net log emails |
| `MAIL_PROVIDER` | `resend` | Mail backend |
| `MAIL_FROM` | `W4TRC Nets <no-reply@w4trc.org>` | Must use a domain verified in Resend |
| `TURNSTILE_SITE_KEY` | `0x4AAAAAAB73shYt-jPMhXXB` | Public Turnstile key |
| `SENTRY_ENVIRONMENT` | `production` | |
| `SENTRY_RELEASE` | `nets-w4trc-org@1.0.0` | |

---

## Database (D1)

Database name: `w4trc_netlogs`
Database ID: `f24a2ef6-a6d7-4042-92fe-1649fb093dd0`

### Apply migrations

```bash
# Local (dev)
wrangler d1 execute w4trc_netlogs --local --file=migrations/0001_init.sql

# Production
wrangler d1 execute w4trc_netlogs --file=migrations/0001_init.sql
```

### Query production DB

```bash
wrangler d1 execute w4trc_netlogs --command="SELECT * FROM nets ORDER BY net_date DESC LIMIT 10;"
```

---

## Routes

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Home / landing page |
| GET | `/submit` | Net log submission form |
| POST | `/submit` | Submit net log |
| GET | `/view` | Net log list (requires auth) |
| GET | `/view?id=<n>` | Net log detail (requires auth) |
| POST | `/view?id=<n>` | Edit/delete net log detail (requires auth) |
| GET | `/signup` | Upcoming signup schedule |
| GET | `/signup/new` | Signup form |
| POST | `/signup/new` | Submit signup |
| GET/POST | `/signup/notify/upcoming` | Send upcoming schedule email (token-protected) |
| GET | `/signup/admin` | Signup admin panel (requires auth) |
| POST | `/signup/admin/login` | Signup admin login |
| POST | `/signup/admin/logout` | Signup admin logout |
| POST | `/signup/admin/delete` | Delete a signup |
| GET | `/api/stats` | JSON stats |
| GET | `/api/nets` | JSON net log list |

---

## Authentication

- **Net log detail / admin view:** Uses `ADMIN_PASSWORD` secret. Session cookie `net_auth=1` lasts 30 minutes.
- **Signup admin:** Separate cookie `signup_admin=1`, same password.
- **Signup notify endpoint:** Bearer token or `?token=` query param matching `SIGNUP_NOTIFY_TOKEN`.

---

## Project Structure

```
src/
  worker.ts         # Entire Worker — routes, HTML, handlers, email, DB
migrations/
  0001_init.sql     # D1 schema (nets table + index)
test/
  index.spec.ts     # Vitest tests
public/             # Static assets (if any)
wrangler.jsonc      # Wrangler config (bindings, vars)
```

---

## Useful Wrangler Commands

```bash
# Tail live logs
wrangler tail

# List D1 databases
wrangler d1 list

# List secrets
wrangler secret list

# Open D1 local shell
wrangler d1 execute w4trc_netlogs --local --command="SELECT name FROM sqlite_master WHERE type='table';"
```
