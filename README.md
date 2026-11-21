# 200M Security Operations Center Platform

One workspace for the SOC: alerts, cases, approvals-gated response, servers, assets, vulnerabilities, compliance, threat intel,
runbooks, reports, automation and tool integrations (Wazuh, TheHive, Cortex, MISP, Velociraptor, OpenVAS/GVM, Shuffle, OPSI,
Bareos, Uptime Kuma, Prometheus, ClickUp, Slack, Telegram, email, Keycloak).

- `backend/`  FastAPI + SQLAlchemy 2 + Alembic (Python 3.12+)
- `frontend/` React 18 + TypeScript + Vite (new 200M design, light/dark)
- `docker-compose.yml`  PostgreSQL 16, Redis 7, Keycloak 26, backend, nginx-served frontend

## Run locally (development, SQLite, local users + TOTP)

```bash
cd backend
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"            # add ,pdf for PDF reports (needs pango libraries)
export SOC_COOKIE_SECURE=false          # plain http on localhost only
python -m app.cli init-db
python -m app.cli seed-demo             # demo users (password Demo-Passw0rd!) and sample data; prints TOTP secrets
python -m app.cli totp admin@demo.local # current 6-digit code
uvicorn app.main:create_app --factory --port 8000

cd ../frontend && npm ci && npm run dev  # http://localhost:5173 (proxies /api to :8000, override with SOC_API)
```

Demo logins: `admin@demo.local`, `l2@demo.local`, `l1@demo.local`, `viewer@demo.local`. Dev auth is refused when `SOC_ENVIRONMENT=production`.

## Checks

```bash
cd backend  && pytest -q && ruff check app tests && mypy app
cd frontend && npm run typecheck && npm run lint && npm test && npm run build
```

## Run with Docker (everything, including Keycloak SSO)

```bash
sh scripts/setup.sh                # once: writes .env with random secrets and prints the logins
docker compose up --build       # first start takes a few minutes (Keycloak imports the realm)
```

| Service | URL |
|---|---|
| SOC platform | http://localhost:8080 |
| Keycloak admin console | http://localhost:8081 |

There is **one login to start with: the super admin**, whose email and password you enter when running `setup.sh`. Sign in with
**Continue with company SSO**. On the first sign-in Keycloak makes you change the password and enrol an authenticator app (TOTP); after that you
need the code at every sign-in.

Super admins and admins can manage other people: **Administration > Users > Add user** creates the account in Keycloak (with a temporary
password you give them, which they must change at first login, plus authenticator enrolment) and in the platform, with the role you pick
(viewer, l1, l2 or admin) and the clients they may see. Administrators can also edit names/emails, change roles, set client access and permission overrides, and enable/disable accounts there.
Profiles, roles and account state sync to Keycloak; client access and permission overrides are stored in SOC. Linked users are managed by their Keycloak ID, so email changes do not break account editing. User administration applies directly after fresh MFA verification. The super admin account remains protected from admin edits, password resets, session termination and token revocation; administrators cannot change their own account from this page.
There is exactly one `superadmin` role; the app never assigns it.

In **Administration > Users**, administrators can **Reset password** with fresh MFA verification. In Keycloak mode this sets a temporary
password, requires a change at the next sign-in, and ends existing Keycloak and SOC sessions. The account's authenticator stays enrolled.
For an older local/pending SOC account missing from Keycloak, select **Create in Keycloak** in the password dialog; this preserves its SOC ID,
client access and history. If it already exists in Keycloak, leave that option off and reset its password to link it.
In the Keycloak admin console, select the `soc` realm (or your configured `SOC_KC_REALM`) to find SOC users.
Development mode creates local SOC users only; it does not synchronize users to Keycloak. The owner's own password is changed on the Keycloak account page.


Roles come from the `soc_role` claim. Sensitive actions trigger a step-up re-verification (fresh TOTP, `acr=mfa-webauthn`, `auth_time` within 2 minutes).
The app talks to Keycloak's Admin API through the `soc-admin` service account (it only has user-management rights in the `soc` realm).

How it fits together: the browser talks to nginx (`web`) and to Keycloak directly. The backend validates ID tokens against the public issuer but fetches
tokens and keys over the internal network (`SOC_OIDC_INTERNAL_ISSUER`). Keycloak has its own PostgreSQL. Compose project name is `soc`; data lives in the
`pgdata`, `kcdata`, `redisdata`, `reports` volumes (`docker compose down -v` wipes them).

Limits: `KC_SUPERADMIN_PASSWORD` in `.env` is only the initial password; it stops working once you change it, so delete it from `.env` afterwards if you like. Signing out redirects to Keycloak's logout page, which asks "Do you want to log out?" once (no `id_token_hint` is kept server side). 

### Going to production

1. Put a TLS reverse proxy in front of `web` (127.0.0.1:8080) and `keycloak` (127.0.0.1:8081).
2. In `.env` set `SOC_PUBLIC_URL`, `KC_PUBLIC_URL` to the HTTPS hostnames, `SOC_COOKIE_SECURE=true`, `SOC_ENVIRONMENT=production`, and your egress allow-list.
3. The realm import only runs when the realm does not exist yet. If the public URLs change later, edit the client's redirect URIs in the Keycloak console.
4. Production refuses to start unless: OIDC auth, secure cookies, a secrets key (or Vault), PostgreSQL, and HTTP connectors disabled.
5. First run: use the one-time `SOC_BOOTSTRAP_TOKEN` with `/api/setup/*` (API only; there is no setup screen yet), then add Wazuh and TheHive under **Integrations**.


## Security model (summary)

HttpOnly SameSite=Strict server-side sessions (idle 15 min, absolute 8 h), CSRF token + Origin check, OIDC auth code + PKCE with pinned algorithms,
step-up MFA for sensitive changes, RBAC with client scoping, request-approve-execute response engine (no self-approval, payload-hash binding,
two approvals for critical actions, kill switch), hash-chained audit log, secrets encrypted (Fernet) or in Vault and never returned, SSRF egress policy on every
connector call, signed/bearer webhooks with replay protection, rate limits, CSP and security headers.

## Known limits (read before go-live)

- Not exercised against real tools: tests use mocked HTTP for connectors, `fakeredis`, and a locally generated OIDC key. Validate each integration with **Test connection** against your real instances.
- Velociraptor (gRPC) and OpenVAS (GMP) connectors report "library not installed"; `pyvelociraptor` / `python-gvm` still need wiring.
- Migrations and the app were tested on SQLite; run the suite against PostgreSQL (and review `alembic upgrade head`) before production.
- Slack/Telegram notifiers call those SaaS APIs directly (outside the egress allow-list). Scheduled reports are generated but not emailed. Workers run in-process (not arq). OpenSearch is not used yet (alert search uses the database).
- There is no first-run setup screen and no per-user TOTP enrolment page (OIDC mode delegates MFA to Keycloak).
