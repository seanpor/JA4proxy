FROM python:3.14.6-alpine3.24@sha256:26730869004e2b9c4b9ad09cab8625e81d256d1ce97e72df5520e806b1709f92
LABEL dockerfile.location="module" \
      dockerfile.module="tarpit" \
      dockerfile.build-context="module-local"

# Alpine base (Phase 229): no Debian perl-base, so the no-fix perl CVEs
# (CVE-2026-42496 / -8376) that required .trivyignore exceptions are gone.
# Patch remaining OS packages to clear known CVEs.
RUN apk upgrade --no-cache

RUN --mount=type=cache,target=/root/.cache/pip,sharing=locked \
    pip install prometheus_client

RUN adduser -D -H -s /sbin/nologin tarpit
USER tarpit

COPY tarpit-server.py /app/tarpit-server.py
WORKDIR /app

EXPOSE 8888 9099

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:9099')" || exit 1

CMD ["python", "-u", "tarpit-server.py"]
