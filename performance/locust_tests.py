#!/usr/bin/env python3
"""
Performance testing for JA4 Proxy using Locust
"""

import time
import random
import ssl
import socket
from locust import HttpUser, TaskSet, task, between
from locust.clients import HttpSession
import struct


class TLSClient:
    """Custom TLS client for testing JA4 fingerprinting."""
    
    def __init__(self, host, port):
        self.host = host
        self.port = port
    
    def create_client_hello(self, ja4_variant="standard"):
        """Create different Client Hello variants for testing."""
        
        # Different cipher suite combinations for testing
        cipher_suites = {
            "standard": [0x1301, 0x1302, 0x1303, 0x130a, 0x130b],
            "legacy": [0xc02b, 0xc02f, 0xc00a, 0xc009, 0xc013],
            "modern": [0x1301, 0x1302, 0x1303],
            "mixed": [0x1301, 0xc02b, 0x1302, 0xc02f, 0x1303]
        }
        
        # Different extension combinations
        extensions = {
            "standard": [0, 10, 11, 13, 16, 43, 51],
            "minimal": [0, 10, 13],
            "extended": [0, 10, 11, 13, 16, 18, 21, 23, 35, 43, 45, 51, 65281]
        }
        
        selected_ciphers = cipher_suites.get(ja4_variant, cipher_suites["standard"])
        selected_extensions = extensions.get(ja4_variant, extensions["standard"])
        
        # Build Client Hello packet (simplified)
        client_hello = bytearray()
        
        # TLS Record Header
        client_hello.extend([0x16, 0x03, 0x01])  # Content Type, Version
        client_hello.extend([0x00, 0x00])       # Length (placeholder)
        
        # Handshake Header
        client_hello.extend([0x01])             # Client Hello
        client_hello.extend([0x00, 0x00, 0x00]) # Length (placeholder)
        
        # Client Hello Body
        client_hello.extend([0x03, 0x03])       # TLS 1.2
        client_hello.extend([random.randint(0, 255) for _ in range(32)])  # Random
        client_hello.extend([0x00])             # Session ID Length
        
        # Cipher Suites
        cipher_suite_length = len(selected_ciphers) * 2
        client_hello.extend(struct.pack('>H', cipher_suite_length))
        for cipher in selected_ciphers:
            client_hello.extend(struct.pack('>H', cipher))
        
        # Compression Methods
        client_hello.extend([0x01, 0x00])       # One method: null
        
        # Extensions (simplified)
        extensions_data = bytearray()
        for ext_type in selected_extensions:
            extensions_data.extend(struct.pack('>H', ext_type))  # Extension Type
            extensions_data.extend([0x00, 0x00])                # Extension Length
        
        client_hello.extend(struct.pack('>H', len(extensions_data)))
        client_hello.extend(extensions_data)
        
        # Update lengths
        handshake_length = len(client_hello) - 9
        record_length = len(client_hello) - 5
        
        struct.pack_into('>H', client_hello, 3, record_length)
        struct.pack_into('>I', client_hello, 6, handshake_length)
        
        return bytes(client_hello)
    
    def send_tls_handshake(self, ja4_variant="standard"):
        """Send TLS handshake to proxy."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.host, self.port))
            
            client_hello = self.create_client_hello(ja4_variant)
            sock.send(client_hello)
            
            # Receive response
            response = sock.recv(4096)
            sock.close()
            
            return len(response) > 0
            
        except Exception as e:
            print(f"TLS handshake failed: {e}")
            return False


class ProxyUser(HttpUser):
    """Locust user for testing proxy performance."""
    
    wait_time = between(1, 3)
    
    def on_start(self):
        """Initialize user session."""
        self.tls_client = TLSClient("localhost", 8080)
    
    @task(3)
    def test_standard_request(self):
        """Test standard HTTP request through proxy."""
        start_time = time.time()
        try:
            response = self.client.get("/", timeout=30)
            total_time = int((time.time() - start_time) * 1000)
            
            if response.status_code == 200:
                self.environment.events.request_success.fire(
                    request_type="HTTP",
                    name="standard_request",
                    response_time=total_time,
                    response_length=len(response.content)
                )
            else:
                self.environment.events.request_failure.fire(
                    request_type="HTTP",
                    name="standard_request",
                    response_time=total_time,
                    response_length=0,
                    exception=f"HTTP {response.status_code}"
                )
                
        except Exception as e:
            total_time = int((time.time() - start_time) * 1000)
            self.environment.events.request_failure.fire(
                request_type="HTTP",
                name="standard_request",
                response_time=total_time,
                response_length=0,
                exception=str(e)
            )
    
    @task(2)
    def test_tls_fingerprinting(self):
        """Test TLS fingerprinting performance."""
        ja4_variants = ["standard", "legacy", "modern", "mixed"]
        variant = random.choice(ja4_variants)
        
        start_time = time.time()
        success = self.tls_client.send_tls_handshake(variant)
        total_time = int((time.time() - start_time) * 1000)
        
        if success:
            self.environment.events.request_success.fire(
                request_type="TLS",
                name=f"tls_handshake_{variant}",
                response_time=total_time,
                response_length=1
            )
        else:
            self.environment.events.request_failure.fire(
                request_type="TLS",
                name=f"tls_handshake_{variant}",
                response_time=total_time,
                response_length=0,
                exception="TLS handshake failed"
            )
    
    @task(1)
    def test_multiple_requests(self):
        """Test multiple rapid requests."""
        start_time = time.time()
        success_count = 0
        total_requests = 5
        
        try:
            for i in range(total_requests):
                response = self.client.get(f"/test/{i}", timeout=10)
                if response.status_code == 200:
                    success_count += 1
                time.sleep(0.1)  # Small delay between requests
            
            total_time = int((time.time() - start_time) * 1000)
            
            if success_count == total_requests:
                self.environment.events.request_success.fire(
                    request_type="HTTP",
                    name="multiple_requests",
                    response_time=total_time,
                    response_length=success_count
                )
            else:
                self.environment.events.request_failure.fire(
                    request_type="HTTP",
                    name="multiple_requests",
                    response_time=total_time,
                    response_length=success_count,
                    exception=f"Only {success_count}/{total_requests} succeeded"
                )
                
        except Exception as e:
            total_time = int((time.time() - start_time) * 1000)
            self.environment.events.request_failure.fire(
                request_type="HTTP",
                name="multiple_requests",
                response_time=total_time,
                response_length=success_count,
                exception=str(e)
            )


class StressTestUser(HttpUser):
    """High-load stress testing user."""
    
    wait_time = between(0.1, 0.5)  # Aggressive timing
    
    @task
    def stress_test(self):
        """Aggressive stress testing."""
        endpoints = ["/", "/api/status", "/health", "/metrics"]
        endpoint = random.choice(endpoints)
        
        self.client.get(endpoint, timeout=5)


class SecurityTestUser(HttpUser):
    """Security-focused testing user."""
    
    wait_time = between(2, 5)
    
    def on_start(self):
        """Initialize security testing."""
        self.malicious_payloads = [
            "/../../../etc/passwd",
            "/admin",
            "/?cmd=whoami",
            "/login?user=admin&pass=admin"
        ]
    
    @task
    def test_malicious_requests(self):
        """Test security filtering."""
        payload = random.choice(self.malicious_payloads)
        
        try:
            response = self.client.get(payload, timeout=10)
            # We expect these to be blocked or handled safely
            
        except Exception:
            pass  # Expected for blocked requests


# Custom test scenarios
class LoadTestTaskSet(TaskSet):
    """Custom load testing task set."""
    
    @task(10)
    def normal_browsing(self):
        """Simulate normal browsing patterns."""
        pages = ["/", "/about", "/products", "/contact"]
        for page in pages:
            self.client.get(page)
            self.wait()
    
    @task(5)
    def api_usage(self):
        """Simulate API usage patterns."""
        endpoints = ["/api/v1/data", "/api/v1/status", "/api/v1/health"]
        endpoint = random.choice(endpoints)
        self.client.get(endpoint)
    
    @task(2)
    def file_downloads(self):
        """Simulate file download patterns."""
        files = ["/download/file1.pdf", "/download/file2.zip", "/download/image.jpg"]
        file_path = random.choice(files)
        self.client.get(file_path, timeout=60)


class LoadTestUser(HttpUser):
    """User for comprehensive load testing."""
    
    tasks = [LoadTestTaskSet]
    wait_time = between(1, 5)
    
    def on_start(self):
        """User session initialization."""
        self.client.get("/")  # Initial page load


# Performance test configurations
class PerformanceTestConfig:
    """Performance test configuration and utilities."""
    
    @staticmethod
    def run_benchmark_test():
        """Run benchmark performance test."""
        import subprocess
        
        # Basic performance test
        cmd = [
            "locust",
            "-f", __file__,
            "--host", "http://localhost:8080",
            "--users", "100",
            "--spawn-rate", "10",
            "--run-time", "5m",
            "--headless",
            "--csv", "reports/performance"
        ]
        
        subprocess.run(cmd)
    
    @staticmethod
    def run_stress_test():
        """Run stress test."""
        import subprocess
        
        cmd = [
            "locust",
            "-f", __file__,
            "--host", "http://localhost:8080",
            "-u", "StressTestUser",
            "--users", "500",
            "--spawn-rate", "50",
            "--run-time", "10m",
            "--headless",
            "--csv", "reports/stress"
        ]
        
        subprocess.run(cmd)


if __name__ == "__main__":
    # Run basic performance test
    PerformanceTestConfig.run_benchmark_test()