#!/usr/bin/env python3
"""
Integration tests for JA4 Proxy with mock backend
Tests the full proxy stack in Docker environment
"""

import pytest
import requests
import time
import os


# Get service URLs from environment or use defaults
PROXY_HOST = os.getenv('PROXY_HOST', 'localhost')
PROXY_PORT = int(os.getenv('PROXY_PORT', '8080'))
BACKEND_HOST = os.getenv('BACKEND_HOST', 'localhost')
BACKEND_PORT = int(os.getenv('BACKEND_PORT', '8081'))
METRICS_PORT = 9090


class TestProxyIntegration:
    """Integration tests for the full proxy stack."""
    
    def test_backend_health(self):
        """Test that mock backend is accessible."""
        response = requests.get(f'http://{BACKEND_HOST}:{BACKEND_PORT}/api/health', timeout=5)
        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'ok'
        assert 'timestamp' in data
        assert data['service'] == 'mock-backend'
    
    def test_backend_homepage(self):
        """Test backend homepage."""
        response = requests.get(f'http://{BACKEND_HOST}:{BACKEND_PORT}/', timeout=5)
        assert response.status_code == 200
        assert 'Mock Backend Server' in response.text
    
    def test_backend_echo(self):
        """Test backend echo endpoint."""
        response = requests.get(f'http://{BACKEND_HOST}:{BACKEND_PORT}/api/echo', timeout=5)
        assert response.status_code == 200
        data = response.json()
        assert data['method'] == 'GET'
        assert data['path'] == '/api/echo'
        assert 'headers' in data
    
    def test_backend_delay(self):
        """Test backend delay endpoint."""
        start_time = time.time()
        response = requests.get(f'http://{BACKEND_HOST}:{BACKEND_PORT}/delay/2', timeout=10)
        elapsed = time.time() - start_time
        
        assert response.status_code == 200
        assert elapsed >= 2.0
        data = response.json()
        assert data['delayed'] == 2
    
    def test_backend_status_codes(self):
        """Test backend can return different status codes."""
        # 200 OK
        response = requests.get(f'http://{BACKEND_HOST}:{BACKEND_PORT}/status/200', timeout=5)
        assert response.status_code == 200
        
        # 404 Not Found
        response = requests.get(f'http://{BACKEND_HOST}:{BACKEND_PORT}/status/404', timeout=5)
        assert response.status_code == 404
        
        # 500 Internal Server Error
        response = requests.get(f'http://{BACKEND_HOST}:{BACKEND_PORT}/status/500', timeout=5)
        assert response.status_code == 500
    
    def test_backend_post_request(self):
        """Test backend POST endpoint."""
        payload = {'test': 'data', 'value': 123}
        response = requests.post(
            f'http://{BACKEND_HOST}:{BACKEND_PORT}/api/echo',
            json=payload,
            timeout=5
        )
        assert response.status_code == 200
        data = response.json()
        assert data['method'] == 'POST'
        assert 'test' in data['body'] or data['body'] == str(payload)
    
    def test_proxy_metrics_endpoint(self):
        """Test that proxy metrics endpoint is accessible."""
        response = requests.get(f'http://{PROXY_HOST}:{METRICS_PORT}/metrics', timeout=5)
        assert response.status_code == 200
        assert 'python_info' in response.text or 'process_' in response.text
    
    @pytest.mark.skip(reason="Depends on proxy implementation details")
    def test_proxy_health_endpoint(self):
        """Test proxy health endpoint."""
        response = requests.get(f'http://{PROXY_HOST}:{PROXY_PORT}/health', timeout=5)
        assert response.status_code == 200


class TestEndToEnd:
    """End-to-end tests through the full stack."""
    
    @pytest.mark.skip(reason="Requires proxy to be configured to forward to backend")
    def test_request_through_proxy(self):
        """Test making a request through the proxy to the backend."""
        # This test requires the proxy to be configured to forward requests
        # to the backend. Implementation depends on proxy configuration.
        proxies = {
            'http': f'http://{PROXY_HOST}:{PROXY_PORT}',
        }
        
        response = requests.get(
            f'http://{BACKEND_HOST}/api/health',
            proxies=proxies,
            timeout=10
        )
        assert response.status_code == 200
    
    @pytest.mark.skip(reason="Requires JA4 fingerprinting to be active")
    def test_ja4_fingerprint_captured(self):
        """Test that JA4 fingerprints are captured."""
        # Make request through proxy
        proxies = {
            'http': f'http://{PROXY_HOST}:{PROXY_PORT}',
        }
        
        requests.get(
            f'http://{BACKEND_HOST}/api/health',
            proxies=proxies,
            timeout=10
        )
        
        # Check metrics for fingerprint data
        response = requests.get(f'http://{PROXY_HOST}:{METRICS_PORT}/metrics', timeout=5)
        metrics = response.text
        
        # Should have JA4-related metrics
        assert 'ja4_' in metrics.lower()


class TestServiceHealth:
    """Tests for service health and availability."""
    
    def test_all_services_responding(self):
        """Test that all services are responding."""
        services = {
            'backend': f'http://{BACKEND_HOST}:{BACKEND_PORT}/api/health',
            'proxy_metrics': f'http://{PROXY_HOST}:{METRICS_PORT}/metrics',
        }
        
        for service_name, url in services.items():
            try:
                response = requests.get(url, timeout=5)
                assert response.status_code == 200, f"{service_name} not responding"
            except requests.exceptions.RequestException as e:
                pytest.fail(f"{service_name} is not accessible: {e}")
    
    def test_service_response_times(self):
        """Test that services respond within acceptable time."""
        start_time = time.time()
        requests.get(f'http://{BACKEND_HOST}:{BACKEND_PORT}/api/health', timeout=5)
        elapsed = time.time() - start_time
        
        assert elapsed < 1.0, "Backend response too slow"


class TestDockerEnvironment:
    """Tests specific to Docker environment."""
    
    def test_environment_variables_set(self):
        """Test that required environment variables are set."""
        assert PROXY_HOST is not None
        assert PROXY_PORT > 0
        assert BACKEND_HOST is not None
        assert BACKEND_PORT > 0
    
    def test_network_connectivity(self):
        """Test that services can communicate."""
        # Test backend is reachable
        try:
            response = requests.get(
                f'http://{BACKEND_HOST}:{BACKEND_PORT}/api/health',
                timeout=5
            )
            assert response.status_code == 200
        except requests.exceptions.ConnectionError:
            pytest.fail(f"Cannot connect to backend at {BACKEND_HOST}:{BACKEND_PORT}")


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
