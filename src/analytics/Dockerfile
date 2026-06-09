# Analytics Node Dockerfile
# Phase 12a: Foundation · Phase 229: alpine base (perl-free)

FROM python:3.14.0-alpine
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
COPY config /app/config

# Set up entry point
COPY src/analytics/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

RUN chown -R analytics:analytics /app

USER analytics

EXPOSE 8080

ENTRYPOINT ["/entrypoint.sh"]

CMD ["python", "-m", "src.analytics.main"]
