# CyberShield AI

**Scan. Understand. Protect.** A managed full-stack cybersecurity education and explainable scanning project built with React, TypeScript, Vite, Express, tRPC, Drizzle ORM and MySQL.

## Features

- Six connected scanners: website/URL, email, SMS/message, link context, APK static indicators and authorized passive API configuration review.
- One deterministic rule engine returns risk score/band, matched indicators, explanation and recommendations. Results are indicators—not probabilities or a guarantee of safety.
- User dashboard, search/filter scan history, PDF reports, threat tickets, in-app notifications, awareness quiz and profile/settings.
- Database-backed administrator console for users/roles/status, scan activity, ticket risk/details/assignments/legal transitions/private screenshots, threat intelligence, analytics and security audit/outbox records.
- Local email/password registration plus optional Manus OAuth. Local passwords are stored as salted Node `scrypt` hashes only; roles are loaded and checked from the database.
- Safe handling: arbitrary URLs are never fetched/opened, redirects are not followed, API scans do not contact targets, APK files are never executed/installed, ticket screenshots are tightly bounded and owner/admin-only, and common secrets are redacted before history is stored. State-changing web requests use Fetch Metadata and a double-submit CSRF token.

## Run locally

Prerequisites: Node.js 22, `pnpm`, and a MySQL-compatible database. From the project root:

```sh
cp .env.example .env
# Set DATABASE_URL, MANUS_PROJECT_ID and MANUS_JWT_SECRET for app sessions.
# Set the additional MANUS_OAUTH_* values only if you want the Manus OAuth option locally.
pnpm install
pnpm db:migrate
pnpm dev
```

The app listens on `PORT` (default `3000`). `/api/health` is the service health endpoint. Commands include `pnpm check`, `pnpm test`, `pnpm build`, `pnpm start`, `pnpm db:push` and `pnpm db:migrate`.

### Environment

- `DATABASE_URL`: MySQL DSN. In managed WebDev environments it is injected by the platform.
- `PORT`: HTTP listener port, default `3000`.
- `MANUS_PROJECT_ID` and `MANUS_JWT_SECRET`: application session claims and signing key. Managed projects inject these; never commit the values.
- `MANUS_OAUTH_PORTAL_URL` and `MANUS_OAUTH_API_URL`: optional Manus OAuth endpoints for the additional federated login button.
- `OWNER_OPEN_ID` is an optional trusted deployment identity supported by the starter. It is not a name/email match; manually provision additional admins by verified account record.

`.env.example` contains placeholders only. Never commit `.env`, tokens, database credentials or actual scanned secrets.

## Accounts, passwords and administrator provisioning

Registration requires full name, email, password and confirmation. Emails are normalized, duplicates rejected, and passwords must contain 12–128 characters with uppercase and lowercase letters, a number and a symbol. A new local account receives an opaque `openId`; a dedicated `local_credentials` table stores its unique normalized email and a salted scrypt hash. Plaintext passwords are never stored, returned in admin lists, or written to audit logs. Login failures are generic (`Invalid email or password.`), and in-memory rate limits apply to registration and login attempts. Sessions use the starter's validated signed `webdev_app_session` cookie (`SameSite=None; Secure` for HTTPS Preview). Manus OAuth remains an optional alternative login.

`pnpm db:push` generates and applies an additive Drizzle migration. New users start as `role='user'`, `status='active'`. Neither Admin Login nor a display name/email can grant admin privileges; every protected admin API checks the stored database role.

To provision **Keerthi, Vishal and Pooja**, first have each person create/sign in to the correct account, then let a trusted database operator verify the account rows and promote those exact accounts. The method is the same for local and OAuth accounts; do not promote by an unverified name or email alone:

```sql
SELECT id, openId, name, email, role, status FROM users;
UPDATE users SET role = 'admin', status = 'active' WHERE openId = '<verified-open-id>';
```

Repeat the update for each verified administrator. Protect database access and audit role changes. A current admin cannot remove their own admin access or suspend their own account from the UI.

## Scanner scope and interpretation

- **URL/link:** lexical URL/domain checks, configured lookalike-brand heuristics and internal confirmed/blocked indicator matching (exact host or true subdomain only). Official alternatives are suggested only for a high-confidence brand match. No DNS/reputation lookup, page fetch, redirect expansion or Safe Browsing verification is performed.
- **Email/SMS/message:** deterministic pattern checks for sender lines, urgency, account/financial language, password/OTP requests, reward/job cues, attachment references and embedded URLs. Sender text is not cryptographically authenticated; phone/email ownership and attachments are not independently verified.
- **APK:** maximum 10 MB, APK extension, SHA-256 and bounded byte/string/permission indicators. No execution, install, full Android manifest/signature verification, antivirus reputation or runtime analysis. Uploaded bytes are analyzed in memory and not saved as a public file.
- **API:** requires an authorization acknowledgement. Reviews endpoint URL and any response-header/error snapshot the user supplies. It does not connect to, fuzz, exploit or test the API.

Risk thresholds are 0–10 Very Low, 11–30 Low, 31–50 Medium, 51–70 High, 71–90 Very High and 91–100 Critical. Treat results as decision aids, not guarantees.

## Reports, notifications and email behavior

PDF reports include scan and owner-account identifiers, time, type, input reference, risk, threat, indicators, explanation and the persisted recommended action; common passwords/tokens/API-key values are redacted. An admin may export any saved scan; a user can export only their own. Ticket evidence accepts only PNG/JPEG/WebP data URLs with matching file signatures, up to 400 KB; evidence is held in private database rows and served only to the ticket owner or a database-authorized admin. Ticket status changes follow a server-enforced graph; terminal `resolved` tickets cannot be reopened. In-app notifications are stored in the database. Welcome, login, high-risk scan, report and admin-assignment email events are recorded in `email_outbox` with status `provider_not_configured`; the safe intent subject/body are stored for inspection, but **no email is actually delivered** until a transactional provider is deliberately configured. No mail credentials are hard-coded or included in the frontend.

## Demo and test guidance

The project includes engine/action/PDF, password-helper, ticket-transition, CSRF and screenshot-validation tests. Use synthetic examples only (e.g. `https://g00gle.com/login`, a fake OTP message or `https://example.invalid`); never paste real passwords, OTPs, personal mailboxes or production credentials. The database is not seeded with real data or pre-provisioned admin accounts. No trained ML model, third-party reputation feed, email-delivery provider, dynamic page fetcher or active API testing is wired into this project; analysis is explicitly deterministic and explainable.

## Routes

`client/public/manus-routes.json` declares the actual public, user and admin pages. Admin APIs enforce server-side role checks; UI navigation alone is not authorization.
