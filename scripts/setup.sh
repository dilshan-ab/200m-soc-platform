#!/usr/bin/env sh
# Creates .env with random secrets and the ONE super admin login. Refuses to overwrite an existing .env.
# Non-interactive: SUPERADMIN_EMAIL=you@company.com SUPERADMIN_PASSWORD='...' sh scripts/setup.sh
set -eu
cd "$(dirname "$0")/.."
[ -f .env ] && { echo ".env already exists; delete it first to regenerate (this resets passwords)."; exit 1; }
rand() { head -c 48 /dev/urandom | od -An -tx1 | tr -d ' \n' | cut -c1-"${1:-40}"; }
fernet() { head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '\n'; }   # Fernet key = 32 random bytes, url-safe base64

EMAIL="${SUPERADMIN_EMAIL:-}"
if [ -z "$EMAIL" ]; then printf "Super admin email: "; read -r EMAIL; fi
case "$EMAIL" in *[!A-Za-z0-9@._+-]*|"") echo "Enter a plain email address (letters, digits, . _ + - @)."; exit 1;; esac
case "$EMAIL" in *@*.*) ;; *) echo "That does not look like an email address."; exit 1;; esac

PW="${SUPERADMIN_PASSWORD:-}"
GENERATED=0
if [ -z "$PW" ]; then
  if [ -t 0 ]; then
    printf "Initial super admin password (12+ chars, upper, lower, digit; Enter = generate one): "
    stty -echo 2>/dev/null || true; read -r PW; stty echo 2>/dev/null || true; echo
  fi
  if [ -z "$PW" ]; then PW="Sa-$(rand 14)-X9"; GENERATED=1; fi
fi
case "$PW" in *[!A-Za-z0-9._@!+=-]*) echo "Password may only use letters, digits and . _ @ ! + = -"; exit 1;; esac
[ "${#PW}" -ge 12 ] && printf %s "$PW" | grep -q '[A-Z]' && printf %s "$PW" | grep -q '[a-z]' && printf %s "$PW" | grep -q '[0-9]' \
  || { echo "Password needs 12+ characters with an upper-case letter, a lower-case letter and a digit."; exit 1; }

KCADMIN="$(rand 24)"
sed \
  -e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$(rand 32)|" \
  -e "s|^KC_DB_PASSWORD=.*|KC_DB_PASSWORD=$(rand 32)|" \
  -e "s|^REDIS_PASSWORD=.*|REDIS_PASSWORD=$(rand 32)|" \
  -e "s|^KC_ADMIN_PASSWORD=.*|KC_ADMIN_PASSWORD=$KCADMIN|" \
  -e "s|^KC_CLIENT_SECRET=.*|KC_CLIENT_SECRET=$(rand 40)|" \
  -e "s|^KC_ADMIN_CLIENT_SECRET=.*|KC_ADMIN_CLIENT_SECRET=$(rand 40)|" \
  -e "s|^KC_SUPERADMIN_EMAIL=.*|KC_SUPERADMIN_EMAIL=$EMAIL|" \
  -e "s|^KC_SUPERADMIN_PASSWORD=.*|KC_SUPERADMIN_PASSWORD=$PW|" \
  -e "s|^SOC_SECRETS_KEY=.*|SOC_SECRETS_KEY=$(fernet)|" \
  -e "s|^SOC_AUDIT_HMAC_KEY=.*|SOC_AUDIT_HMAC_KEY=$(rand 48)|" \
  -e "s|^SOC_BOOTSTRAP_TOKEN=.*|SOC_BOOTSTRAP_TOKEN=$(rand 32)|" \
  -e "s|^SOC_METRICS_TOKEN=.*|SOC_METRICS_TOKEN=$(rand 32)|" \
  .env.example > .env
chmod 600 .env
echo
echo "Created .env"
echo "  Super admin   : $EMAIL   (sign in at http://localhost:8080)"
[ "$GENERATED" = 1 ] && echo "  Password      : $PW   (generated; shown only now and stored in .env)"
echo "  You must change this password and enrol an authenticator app at first login."
echo "  Keycloak admin: http://localhost:8081  user kcadmin  (password in .env: KC_ADMIN_PASSWORD)"
echo "  Next          : docker compose up --build"
echo "  Then sign in and use Administration > Users > Add user to create other users and admins."
