#!/bin/sh
# deploy/docker/redis-entrypoint.sh — Phase 813
#
# Renders config/redis_acl.conf.template (bind-mounted read-only at
# /etc/redis/redis_acl.conf.template) into a real ACL file by substituting
# each ${..._REDIS_PASSWORD} placeholder with the matching Docker secret's
# content, then execs redis-server with --aclfile pointing at the rendered
# copy. --requirepass-file is deliberately not used anywhere -- it is not a
# real Redis directive (verified: it crash-loops the container with a FATAL
# CONFIG FILE ERROR) and is unnecessary anyway, since the ACL file's
# `user default off nopass ~* -@all` already disables the unauthenticated
# default user; all real authentication goes through the named ACL users
# this script renders.
#
# Deliberately dependency-free (no envsubst/gettext -- not present in
# redis:7.4.9-alpine) and deliberately does not use eval/sh -c on secret
# content, to avoid any secret value being interpreted as shell syntax.
#
# The rendered file is written to /tmp/redis_acl.conf. Every compose service
# using this image mounts /tmp as tmpfs (noexec,nosuid,nodev) despite
# read_only: true on the container root -- writable, and never persisted to
# disk, which is the right place for rendered secret material. noexec is
# irrelevant here: redis-server only reads this file as data, never executes
# it.
set -eu

TEMPLATE="/etc/redis/redis_acl.conf.template"
RENDERED="/tmp/redis_acl.conf"

render_var() {
    # $1 = placeholder name (e.g. REDIS_PASSWORD), $2 = secret file path
    var_name="$1"
    secret_file="$2"
    [ -f "$secret_file" ] || {
        echo "redis-entrypoint: missing secret file $secret_file for \${$var_name}" >&2
        exit 1
    }
    # Substitute occurrences of the literal placeholder using awk (not sed --
    # avoids the secret value ever being interpreted as a sed
    # pattern/replacement with its own delimiter or backreference syntax;
    # awk's index()/substr() splice is plain string replacement only). The
    # secret is passed via ENVIRON, not `awk -v`: POSIX awk -v processes
    # C-style backslash escapes (\n, \t, ...) in its argument, which would
    # silently corrupt a secret value containing a literal backslash --
    # ENVIRON values are not escape-processed. `key` is a fixed, code-defined
    # placeholder string (never secret-derived), so -v is fine for it.
    REDIS_ACL_SECRET_VALUE=$(cat "$secret_file") \
      awk -v key="\${${var_name}}" '
        {
            out = ""
            line = $0
            val = ENVIRON["REDIS_ACL_SECRET_VALUE"]
            while ((idx = index(line, key)) > 0) {
                out = out substr(line, 1, idx - 1) val
                line = substr(line, idx + length(key))
            }
            print out line
        }
    ' "$RENDERED" > "${RENDERED}.next"
    mv "${RENDERED}.next" "$RENDERED"
}

cp "$TEMPLATE" "$RENDERED"
render_var REDIS_PASSWORD /run/secrets/redis_password
render_var MANAGEMENT_REDIS_PASSWORD /run/secrets/management_redis_password
render_var ANALYTICS_REDIS_PASSWORD /run/secrets/analytics_redis_password
render_var JA4TAP_REDIS_PASSWORD /run/secrets/ja4tap_redis_password
render_var EXPORTER_REDIS_PASSWORD /run/secrets/exporter_redis_password
chmod 600 "$RENDERED"

exec redis-server --aclfile "$RENDERED" "$@"
