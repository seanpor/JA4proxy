FROM python:3.11-slim

# Security hardening
RUN groupadd -r proxy || true && useradd -r -g proxy proxy 2>/dev/null || useradd -r -G proxy proxy

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libpcap-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY proxy.py .
COPY config/ config/
COPY security/ security/

# Create necessary directories
RUN mkdir -p logs && \
    chown -R proxy:proxy /app

# Switch to non-root user
USER proxy

# SECURITY FIX: Enhanced health check with actual HTTP request
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:9090/metrics || exit 1

# Expose ports
EXPOSE 8080 9090

# Run the application
CMD ["python", "proxy.py"]