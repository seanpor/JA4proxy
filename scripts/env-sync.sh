#!/usr/bin/env bash
# Top up an EXISTING .env with any newly-required variables.
#
# WHY THIS EXISTS
# ---------------
# docker-compose.poc.yml declares its secrets as ${VAR:?...} — required, hard
# fail. start-poc.sh generates a complete .env, but ONLY when the file is
# absent (`if [ ! -f .env ]`). So the moment a new required variable lands on
# main, every existing checkout breaks on `make build` while a fresh clone
# works fine. There was no upgrade path, because nothing ever edits an .env
# that already exists.
#
# ANALYTICS_HMAC_SECRET (phase-826) is the instance that surfaced it, but this
# is a class: the same drift hit MANAGEMENT_JWT_SECRET and the ACL-user
# passwords before it, and the existing guard tests all check the from-scratch
# path only.
#
# The required list is DERIVED from the compose file rather than restated here.
# Restating it is what caused the drift in the first place — a new variable
# then has to be remembered in six places instead of one.
#
# Never overwrites a value that is already set. Never prints a secret.
set -euo pipefail

ENV_FILE="${1:-.env}"
COMPOSE_FILE="${COMPOSE_FILE:-deploy/docker/docker-compose.poc.yml}"

if [ ! -f "$COMPOSE_FILE" ]; then
    echo "env-sync: $COMPOSE_FILE not found — run from the repo root" >&2
    exit 1
fi

if [ ! -f "$ENV_FILE" ]; then
    echo "env-sync: $ENV_FILE not found."
    echo "  A complete .env is generated on first start. Run:  make start-poc"
    echo "  (or 'make init' for the guided wizard, or 'cp template.env .env')"
    exit 1
fi

# Every ${VAR:?...} in the compose file is a hard requirement.
# shellcheck disable=SC2016  # the single quotes are the point: tr deletes the
# literal characters $ { : ? from "${VAR:?", leaving the bare variable name.
required=$(grep -oE '\$\{[A-Z0-9_]+:\?' "$COMPOSE_FILE" | tr -d '${:?' | sort -u)

gen_secret() { openssl rand -hex 32; }
gen_password() { openssl rand -base64 24 | tr -d '/+=' | head -c 32; }

added=()
unhandled=()

for var in $required; do
    # An empty assignment counts as missing: compose's :? rejects it too, and
    # a blank secret is never what anyone meant.
    if grep -qE "^${var}=.+" "$ENV_FILE"; then
        continue
    fi

    case "$var" in
        MANAGEMENT_ADMIN_USER) value="admin" ;;                 # not a secret
        *_PASSWORD)            value="$(gen_password)" ;;
        *_SECRET|*_KEY|*_TOKEN) value="$(gen_secret)" ;;
        *)
            # Deliberately not guessed. A required variable this script cannot
            # classify is usually deployment-specific (a hostname, an API key
            # from a third party) and inventing a value would produce a stack
            # that starts and is silently wrong.
            unhandled+=("$var")
            continue
            ;;
    esac

    # Strip any empty assignment first so we do not end up with two lines.
    if grep -qE "^${var}=$" "$ENV_FILE"; then
        sed -i "/^${var}=$/d" "$ENV_FILE"
    fi
    printf '%s=%s\n' "$var" "$value" >> "$ENV_FILE"
    added+=("$var")
done

chmod 600 "$ENV_FILE"

if [ ${#added[@]} -gt 0 ]; then
    echo "env-sync: added ${#added[@]} missing required variable(s) to $ENV_FILE:"
    for var in "${added[@]}"; do echo "  + $var  [generated]"; done
    echo "  Values are generated and stored in $ENV_FILE (chmod 600); not printed."
fi

if [ ${#unhandled[@]} -gt 0 ]; then
    echo "" >&2
    echo "env-sync: these required variables need a value you must choose:" >&2
    for var in "${unhandled[@]}"; do echo "  ! $var" >&2; done
    echo "" >&2
    echo "Add them to $ENV_FILE, then re-run. See template.env for guidance." >&2
    exit 1
fi

if [ ${#added[@]} -eq 0 ]; then
    echo "env-sync: $ENV_FILE already has every required variable"
fi
