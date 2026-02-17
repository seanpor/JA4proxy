FROM python:3.11-slim

RUN pip install --no-cache-dir prometheus_client

RUN useradd -r -s /bin/false tarpit
USER tarpit

COPY tarpit-server.py /app/tarpit-server.py
WORKDIR /app

EXPOSE 8888 9099

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:9099')" || exit 1

CMD ["python", "-u", "tarpit-server.py"]
