FROM python:3.11.11-slim

# Security hardening - user/group may already exist in base image
RUN groupadd -r proxy 2>/dev/null || true
RUN useradd -r -g proxy proxy 2>/dev/null || true

# Install system dependencies
# curl removed — wget used in HEALTHCHECK instead (smaller attack surface)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpcap-dev \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Upgrade pip and install packaging to resolve dependency conflicts
RUN pip install --no-cache-dir --upgrade pip setuptools wheel packaging

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY proxy.py .
COPY config/ config/
COPY security/ security/
COPY src/ src/
COPY geoip/ geoip/

# Install IP2Location for country lookups
RUN pip install --no-cache-dir IP2Location

# Create necessary directories
RUN mkdir -p logs && \
    chown -R proxy:proxy /app

# Switch to non-root user
USER proxy

ENV PYTHONUNBUFFERED=1

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD wget --spider -q http://localhost:9090/metrics || exit 1

# Expose ports
EXPOSE 8080 9090

# Run the application
CMD ["python", "proxy.py"]