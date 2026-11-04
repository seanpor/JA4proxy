FROM python:3.15.2-alpine3.24@sha256:20a82dbc2783112ddb91d1534603f802d222a3e63e593cd002eb2ac534e70211
LABEL dockerfile.location="module" \
      dockerfile.module="tarpit" \
      dockerfile.build-context="module-local"

# Alpine base (Phase 229): no Debian perl-base, so the no-fix perl CVEs
# (CVE-2026-42496 / -8376) that required .trivyignore exceptions are gone.
# Patch remaining OS packages to clear known CVEs.
RUN apk upgrade --no-cache

RUN --mount=type=cache,target=/root/.cache/pip,sharing=locked \
    pip install prometheus_client && \
    pip uninstall -y pip setuptools wheel && \
    rm -rf /usr/local/lib/python3.*/ensurepip \
           /usr/local/lib/python3.*/site-packages/pip* \
           /usr/local/lib/python3.*/site-packages/setuptools* \
           /usr/local/lib/python3.*/site-packages/wheel* \
           /usr/local/bin/pip* && \
    ! python3 -m pip --version 2>/dev/null

RUN adduser -D -H -s /sbin/nologin tarpit
USER tarpit

COPY tarpit-server.py /app/tarpit-server.py
WORKDIR /app

EXPOSE 8888 9099

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:9099')" || exit 1

CMD ["python", "-u", "tarpit-server.py"]
