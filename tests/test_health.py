import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from guardette import Guardette, presidio
from guardette.config import ConfigManager

PRESIDIO_POLICY = """version: "1"
sources:
  - host: example.test
    rules:
      - route: "GET /item/{itemId}"
        actions:
          - kind: presidio_anonymize
            json_paths:
              - $.title
"""


def _client(policy_path):
    app = FastAPI()
    Guardette(policy_path=str(policy_path)).to_fastapi(app)
    return TestClient(app)


@pytest.fixture
def presidio_client(tmp_path):
    policy = tmp_path / "policy.yml"
    policy.write_text(PRESIDIO_POLICY)
    return _client(policy)


@pytest.fixture
def mock_presidio(monkeypatch):
    """Replace the shared Presidio client; set `status` to the health status both services return."""
    state = {"status": 200, "paths": []}

    def handler(request):
        state["paths"].append(request.url.path)
        return httpx.Response(state["status"], json={})

    monkeypatch.setattr(presidio, "_shared_client", httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    return state


def test_health_needs_no_secret_and_reveals_no_policy():
    response = _client("tests/test_policy.yml").get("/_guardette/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_ready_without_presidio_policy_skips_presidio(mock_presidio):
    response = _client("tests/test_policy.yml").get("/_guardette/ready")

    assert response.status_code == 200
    assert mock_presidio["paths"] == []


def test_ready_when_presidio_is_healthy(presidio_client, mock_presidio):
    response = presidio_client.get("/_guardette/ready")

    assert response.status_code == 200
    assert response.json() == {"status": "ready"}
    assert mock_presidio["paths"] == ["/health", "/health"]


def test_ready_returns_503_when_presidio_is_down(presidio_client, mock_presidio):
    mock_presidio["status"] = 503

    response = presidio_client.get("/_guardette/ready")

    assert response.status_code == 503
    assert response.json() == {"status": "unavailable", "reason": "presidio"}


def test_startup_does_not_fail_when_presidio_is_unreachable(tmp_path, monkeypatch):
    monkeypatch.setenv("PRESIDIO_ANALYZER_URL", "http://127.0.0.1:9")
    monkeypatch.setenv("PRESIDIO_ANONYMIZER_URL", "http://127.0.0.1:9")
    policy = tmp_path / "policy.yml"
    policy.write_text(PRESIDIO_POLICY)

    with _client(policy) as client:
        assert client.get("/_guardette/health").status_code == 200


def test_shutdown_closes_the_shared_presidio_client():
    with _client("tests/test_policy.yml"):
        shared = presidio.get_shared_client(ConfigManager())
        assert not shared.is_closed

    assert shared.is_closed
    assert presidio._shared_client is None
