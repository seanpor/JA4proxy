# Analytics Node Dockerfile
# Phase 12a: Foundation · Phase 229: alpine base (perl-free)

FROM python:3.14.6-alpine3.24@sha256:26730869004e2b9c4b9ad09cab8625e81d256d1ce97e72df5520e806b1709f92
LABEL dockerfile.location="module" \
      dockerfile.module="src/analytics" \
      dockerfile.build-context="root"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=on
ENV PIP_DEFAULT_TIMEOUT=100

# Alpine base (Phase 229): no Debian perl-base, so the no-fix perl CVEs
# (CVE-2026-42496 / -8376) that required .trivyignore exceptions are gone.
RUN apk upgrade --no-cache

# Security: Create non-root user
RUN addgroup -S analytics && adduser -S -G analytics analytics

WORKDIR /app

# Install Python deps. build-base/openssl-dev are needed only to compile any
# native wheels (e.g. numpy) on musl; install them as a virtual package and
# remove them afterwards so the runtime image carries no compilers.
COPY requirements-analytics.txt ./
RUN --mount=type=cache,target=/root/.cache/pip,sharing=locked \
    apk add --no-cache --virtual .build-deps build-base openssl-dev && \
    pip install --upgrade pip && \
    pip install -r requirements-analytics.txt && \
    apk del .build-deps

# Copy application code
COPY src/analytics /app/src/analytics
# JA4PROXY-2026-0097: src/analytics/main.py imports `src.utils.logging_config`,
# but only src/analytics was copied — so the container crash-looped on startup
# with `ModuleNotFoundError: No module named 'src.utils'`. src/utils is
# self-contained (no further src.* imports), so copying just this subtree is
# sufficient. tests/unit/test_analytics_image_imports.py guards against any
# future src.* import landing without its subtree being copied here.
COPY src/utils /app/src/utils
COPY config /app/config

# Set up entry point
COPY src/analytics/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

RUN chown -R analytics:analytics /app

USER analytics

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

ENTRYPOINT ["/entrypoint.sh"]

CMD ["python", "-m", "src.analytics.main"]
