# Analytics Node Dockerfile
# Phase 12a: Foundation

FROM python:3.11.11-slim as base

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV PIP_NO_CACHE_DIR=off
ENV PIP_DISABLE_PIP_VERSION_CHECK=on
ENV PIP_DEFAULT_TIMEOUT=100

# Security: Create non-root user
RUN groupadd -r analytics && useradd -r -g analytics analytics

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create and set working directory
WORKDIR /app

# Install Python dependencies
COPY requirements-analytics.txt ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements-analytics.txt

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