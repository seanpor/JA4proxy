"""
Locust performance test file for JA4 Proxy
Tests backend performance and proxy metrics endpoints
"""
from locust import HttpUser, task, between, events
import random
import json


class BackendUser(HttpUser):
    """Simulates users hitting the backend service."""
    wait_time = between(0.1, 0.5)  # Wait 100-500ms between requests
    host = "http://backend:80"
    
    @task(10)
    def get_homepage(self):
        """Test homepage endpoint (most common)."""
        self.client.get("/")
    
    @task(5)
    def get_health(self):
        """Test health endpoint."""
        self.client.get("/api/health")
    
    @task(3)
    def get_echo(self):
        """Test echo endpoint with data."""
        data = {"test": f"data_{random.randint(1, 1000)}"}
        self.client.get("/api/echo", params=data)
    
    @task(2)
    def post_echo(self):
        """Test POST to echo endpoint."""
        data = {
            "message": f"test_message_{random.randint(1, 1000)}",
            "timestamp": random.randint(1000000, 9999999)
        }
        self.client.post(
            "/api/echo",
            json=data,
            headers={"Content-Type": "application/json"}
        )
    
    @task(1)
    def get_with_delay(self):
        """Test delay endpoint (less frequent, simulates slow operations)."""
        delay = random.choice([0.1, 0.2, 0.5])
        self.client.get(f"/api/delay/{delay}")
    
    @task(1)
    def get_status_codes(self):
        """Test different status codes."""
        status = random.choice([200, 201, 400, 404, 500])
        with self.client.get(f"/api/status/{status}", catch_response=True) as response:
            # We expect these status codes, so mark as success
            if response.status_code == status:
                response.success()


class ProxyMetricsUser(HttpUser):
    """Simulates monitoring systems checking proxy metrics."""
    wait_time = between(5, 15)  # Check metrics every 5-15 seconds
    host = "http://proxy:9090"
    
    @task
    def get_metrics(self):
        """Fetch Prometheus metrics."""
        with self.client.get("/metrics", catch_response=True) as response:
            if response.status_code == 200 and "ja4_" in response.text:
                response.success()
            else:
                response.failure(f"Metrics check failed: {response.status_code}")


class MixedWorkloadUser(HttpUser):
    """Simulates mixed workload patterns."""
    wait_time = between(0.5, 2.0)
    
    def on_start(self):
        """Initialize user - set random backend host."""
        self.backend_host = "http://backend:80"
        self.metrics_host = "http://proxy:9090"
    
    @task(20)
    def backend_request(self):
        """Make requests to backend."""
        endpoints = [
            "/",
            "/api/health",
            "/api/echo?test=data",
        ]
        endpoint = random.choice(endpoints)
        self.client.get(f"{self.backend_host}{endpoint}")
    
    @task(1)
    def check_metrics(self):
        """Periodically check metrics."""
        self.client.get(f"{self.metrics_host}/metrics")


@events.quitting.add_listener
def on_quit(environment, **kwargs):
    """Print summary on quit."""
    print("\n" + "="*60)
    print("Performance Test Summary")
    print("="*60)
    stats = environment.stats
    print(f"Total Requests: {stats.total.num_requests}")
    print(f"Total Failures: {stats.total.num_failures}")
    print(f"Requests/sec: {stats.total.total_rps:.2f}")
    print(f"Avg Response Time: {stats.total.avg_response_time:.2f}ms")
    print(f"Min Response Time: {stats.total.min_response_time:.2f}ms")
    print(f"Max Response Time: {stats.total.max_response_time:.2f}ms")
    print("="*60)
