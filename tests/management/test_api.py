import json
import pytest
from fastapi.testclient import TestClient
from src.management.app import app, redis_manager
from unittest.mock import AsyncMock, patch

client = TestClient(app)

@pytest.fixture
def mock_redis():
    with patch("src.management.app.redis_manager", autospec=True) as mock:
        yield mock

def test_health_ok(mock_redis):
    mock_redis.get_dial.return_value = 50
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "redis_connected": True,
        "dial": 50
    }

def test_get_dial(mock_redis):
    mock_redis.get_dial.return_value = 25
    response = client.get("/api/v1/dial")
    assert response.status_code == 200
    assert response.json() == {"dial": 25}

def test_update_dial(mock_redis):
    response = client.put("/api/v1/dial", json={"value": 75})
    assert response.status_code == 200
    mock_redis.set_dial.assert_called_once_with(75)
    assert response.json()["dial"] == 75

def test_get_ja4_list(mock_redis):
    mock_redis.get_list.return_value = ["fp1", "fp2"]
    response = client.get("/api/v1/lists/ja4/whitelist")
    assert response.status_code == 200
    assert response.json() == {"entries": ["fp1", "fp2"]}
    mock_redis.get_list.assert_called_once_with("whitelist")

def test_add_ja4_entry(mock_redis):
    response = client.post("/api/v1/lists/ja4/blacklist", json={"fingerprint": "new_fp"})
    assert response.status_code == 200
    mock_redis.add_to_list.assert_called_once_with("blacklist", "new_fp")

def test_remove_ja4_entry(mock_redis):
    response = client.delete("/api/v1/lists/ja4/whitelist/fp_to_del")
    assert response.status_code == 200
    mock_redis.remove_from_list.assert_called_once_with("whitelist", "fp_to_del")
