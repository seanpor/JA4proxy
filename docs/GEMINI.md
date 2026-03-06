# GEMINI.md

## Project Overview

This project is a security proxy called **JA4proxy**. It's designed to sit between clients and a backend server, analyzing TLS traffic to block malicious connections without decrypting the traffic itself.

The core technology is **JA4 TLS fingerprinting**, a method for identifying client applications based on the parameters of their TLS ClientHello message. This allows the proxy to distinguish between legitimate browsers and malicious tools like C2 frameworks (e.g., Cobalt Strike, Sliver) or bots.

The proxy is written in Python using `asyncio` for high-performance, non-blocking I/O. It uses Redis for distributed state management, including security lists (whitelists/blacklists), rate limiting counters, and session data. The entire application is containerized using Docker and orchestrated with Docker Compose.

The architecture is designed for scalability and high availability, with HAProxy for load balancing across multiple proxy instances. A comprehensive monitoring stack is included, featuring Prometheus for metrics, Grafana for dashboards, and Loki for log aggregation.

## Building and Running

The project is managed through a combination of shell scripts and a `Makefile`.

### Key Commands

*   **Start all services (Proxy + Monitoring):**
    ```bash
    ./start-all.sh
    ```

*   **Start only the core proxy services (for development/testing):**
    ```bash
    ./start-poc.sh
    ```

*   **Stop all services:**
    ```bash
    ./stop-all.sh
    ```

*   **Generate test traffic:**
    The `generate-tls-traffic.sh` script simulates a mix of legitimate and malicious traffic to test the proxy's effectiveness.
    ```bash
    # Usage: ./generate-tls-traffic.sh <duration_seconds> <legitimate_traffic_%> <num_workers>
    ./generate-tls-traffic.sh 60 10 20
    ```

*   **Run tests:**
    The project includes a suite of tests that can be run via Docker Compose.
    ```bash
    docker compose -f docker-compose.poc.yml run --rm test
    ```

*   **View logs:**
    ```bash
    # View proxy logs
    docker compose -f docker-compose.poc.yml logs -f proxy

    # View all logs
    docker compose -f docker-compose.poc.yml -f docker-compose.monitoring.yml logs -f
    ```

### Configuration

*   The main proxy configuration is in `config/proxy.yml`.
*   Environment variables are managed in the `.env` file (copied from `.env.example`).
*   The HAProxy configuration is in `ha-config/haproxy.cfg`.
*   The monitoring stack configuration is in the `monitoring/` directory.

## Development Conventions

*   **Code Style:** The Python code follows PEP 8 style guidelines. The use of type hints is prevalent throughout the codebase.
*   **Testing:** The project has a strong emphasis on testing, with unit, integration, security, and fuzz tests located in the `tests/` directory. The `pytest` framework is used for running tests.
*   **Dependencies:** Python dependencies are managed in `requirements.txt` and `requirements-test.txt`.
*   **Documentation:** The project is well-documented, with a `docs/` directory containing detailed information on architecture, security, operations, and more.
*   **Security:** The project follows security best practices, including the principle of least privilege in its Docker containers, secure default configurations, and detailed security documentation.
