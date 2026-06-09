FROM python:3.14.0-alpine@sha256:8373231e1e906ddfb457748bfc032c4c06ada8c759b7b62d9c73ec2a3c56e710
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
