# CyberShield AI — Implementation Plan

## Product and architecture

Implement the attached CyberShield AI specification as an integrated full-stack cybersecurity education and analysis application. The existing managed project is React 19 + TypeScript + Vite, Wouter, Express, tRPC, Drizzle ORM and a managed MySQL database. Keep this stack, use the configured server/database resources, preserve Manus OAuth, and also implement the explicitly requested email/password registration and login. Local credentials live in a dedicated table with salted scrypt hashes; local users receive an opaque internal identity and use the same signed, validated application session as OAuth users. Persist user-owned scans with actions, tickets including risk/priority and optional private evidence, awareness attempts, notifications, email-outbox intents and audit records in MySQL. Admin operations use backend `adminProcedure` plus the database role; neither the login choice nor a user's name can grant admin privileges. Admin identities named in the brief must be manually provisioned as role `admin` by a trusted operator.

## Implementation decisions and safety boundaries

- Use deterministic, feature-based rules for transparent risk indicators and a bounded score; no fabricated randomness, unverified ML claims, or unsupported probability claims. Explain that heuristic scores are indicators, not guarantees.
- URL/link inspection is lexical and checks exact or proper subdomain matches in the app's confirmed/blocked-indicator database; it does not fetch arbitrary domains, follow redirects, or open the link. This avoids SSRF and unsafe browsing. HTTPS is not treated as proof of trust.
- Email/message scanning is local text analysis for urgency, credentials/OTP/payment language, known scam patterns and extracted URL indicators.
- APK/file review validates a narrow file allowlist and size, hashes bytes and inspects only safe static byte/string indicators; never executes, installs, or publicly exposes an upload. State clearly which binary properties cannot be verified by the lightweight static analyzer.
- The authorized API scanner requires an explicit authorization attestation and performs only passive URL/configuration review; it does not fuzz, exploit, authenticate to, or otherwise attack a target. It should not make network requests to user-supplied hosts in this implementation.
- Support both existing Manus OAuth and explicitly requested local email/password accounts. Validate full name, email format, password strength, password confirmation and duplicate email; store only salted scrypt password hashes; use generic login failures, rate limits and the same signed validated app session. Protect state-changing web requests with Fetch Metadata and double-submit CSRF. Never create a demo session or grant a role based on account name/email. If no email provider is configured, show durable in-app notifications and record email intent in a development-safe outbox/log rather than claim delivery.
- PDF reports are generated from persisted scan findings and exclude credentials, tokens and secrets. Safe official-domain alternatives appear only for high-confidence brand matches.
- Store route manifest as `client/public/manus-routes.json` and keep it synchronized with real client page routes.

## Design system

- **Design movement:** calm, editorial security operations software—less “hacker terminal,” more trustworthy modern security product.
- **Core principles:** signal over noise; explain every risk; calm controls for high-stakes choices; consistent human-readable severity language.
- **Color philosophy:** begin with the mockup's **Light Teal** option: warm white and pale mint surfaces, deep ink-teal text, ownable saturated teal actions, and restrained amber/red severity accents. This accessible palette remains easy to change globally if the user later selects another option.
- **Layout paradigm:** persistent slim left navigation with a wider, asymmetric main workspace; prominent scan composer, then a narrow evidence/insight rail and readable history/table sections. Landing page uses broad editorial sections rather than a centered card grid.
- **Signature elements:** shield-with-check wordmark mark; thin signal-line separators / subtle scan pulse; high-contrast severity lozenges with explicit labels and iconography.
- **Interaction philosophy:** direct, predictable actions; show loading, empty, warning and error states; require an explicit authorization checkbox for API inspection; avoid automatically navigating to flagged links.
- **Animation:** restrained 120–220 ms fades and progress transitions; honor reduced-motion preferences; no perpetual glow or blinking.
- **Typography:** system/Inter-like sans for UI with a compact mono face only for domains, IDs and hashes. Clear display/title/body/caption hierarchy; generous line-height for explanations.
- **Brand essence:** a practical multi-channel safety desk that turns suspicious digital content into understandable next steps; **clear, reassuring, vigilant**.
- **Brand voice:** specific, calm and non-alarmist. Examples: “Check before you click.” “We found indicators worth reviewing—here’s what triggered them.”
- **Wordmark & logo:** small geometric shield/check symbol paired with a custom-spaced CyberShield AI wordmark; implement the mark as an icon treatment, not generic default-font text alone.
- **Signature brand color:** deep teal.

## Feature implementation

1. Replace starter screen with a responsive landing page, functional app shell, page routes, local email/password registration/login plus optional Manus OAuth, logout and protected user/admin surfaces.
2. Implement a central cyber engine and six scan modes: URL/website, email, SMS/message, link/context, static APK/file and authorized API review. Results share risk band, actual indicator-derived score, persisted `allow`/`warn`/`strong_warning`/`prevent_opening` action, threat classification, evidence, recommendations, cautious official-alternative suggestions, history and reporting actions.
3. Add persistent schema/query layer and tRPC procedures for scans, user history/details, PDF report, tickets, private screenshot evidence, awareness, notifications and administrator views/changes. Enforce legal ticket transitions and use validation and ownership filters on every user-level read/write.
4. Implement user dashboard, scan history, reports, tickets, notifications, awareness quiz and score/profile. Implement admin dashboard, users, tickets, threat intelligence, analytics and security logs, all protected server-side.
5. Connect ticket decisions to confirmed-threat intelligence and notifications. Provide a truthful email-outbox/development note if no transactional sender exists.
6. Add `.env.example`, migration/setup instructions, safe seed/demo guidance, tests for engine and key access rules, run build/type checks, and package source into a ZIP that excludes `node_modules`, secrets and generated machine-only state.

## Project structure

- `client/src/pages/`: landing, user workspace, scanners, history, reports, awareness, and admin views.
- `client/src/components/`: shell, shared scanner/result/severity/table/form components.
- `client/src/lib/`: tRPC client and presentation helpers.
- `client/src/index.css`: shared palette, responsive layout and accessible visual system.
- `server/engine/`: deterministic rule, analysis and PDF modules; `server/tickets/` validates private static image evidence.
- `server/routers.ts`: typed API surface, password registration/login, user ownership and admin-only procedures.
- `server/_core/passwords.ts` and `drizzle/schema.ts`: scrypt hash/verification helpers and separate `local_credentials` table; users/admin queries never select password hashes.
- `server/db.ts`: parameterized Drizzle query functions.
- `drizzle/schema.ts` and `drizzle/`: persistent schema and additive migrations.
- `client/public/manus-routes.json`: complete page route manifest.
- `README.md`, `.env.example`, `TODO.md`, `plan.md`: setup, deployment, tracked outcomes and decisions.

## Scope boundaries

The optional browser extension is deferred until the integrated platform is stable. A real third-party email sender, paid external threat-intelligence feed, trained ML model, dynamic URL crawling/redirect following, and active API vulnerability testing are not configured by the project brief and will not be simulated. Provide safe extension points/instructions and accurately label those limits. The requested deliverable is the runnable source project ZIP; this does not by itself mean the application has been published.


## Implementation refinement

- The default interface uses **Light Teal**; Settings lets each user switch among Light Teal, Midnight Cyan or Graphite Violet in the current browser. These palette choices do not affect analysis or permissions.
- Admin analytics include scan types, threat classes, risk buckets, ticket states and high-risk counts over daily, weekly and monthly intervals.
- An administrator scan-activity view is a distinct page; ticket workflow updates, indicator management and user role/status changes remain database-backed and audited.
