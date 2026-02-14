FROM python:3.11-slim

# Security hardening
RUN addgroup --system proxy && adduser --system --group proxy

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY proxy.py .
COPY config/ config/

# Create necessary directories
RUN mkdir -p logs && \
    chown -R proxy:proxy /app

# Switch to non-root user
USER proxy

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD python -c "import socket; s=socket.socket(); s.connect(('localhost', 8080)); s.close()" || exit 1

# Expose ports
EXPOSE 8080 9090

# Run the application
CMD ["python", "proxy.py"]