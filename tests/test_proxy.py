from unittest.mock import patch

import httpx
from fastapi import FastAPI
from fastapi.testclient import TestClient

from guardette import Guardette
from guardette.constants import PROXY_ERROR_HEADER, PROXY_HOST_HEADER
from guardette.datastructures import ProxyRequest, ProxyResponse
from guardette.exceptions import GuardetteException

app = FastAPI()

guardette = Guardette(policy_path="tests/test_policy.yml")
guardette.to_fastapi(app)

client = TestClient(app)

test_client_secret = "test"


async def get_secret(key, *args, **kwargs):
    return "test"


@patch("guardette.secrets.ConfigSecretsManager.get", side_effect=get_secret)
def test_yc(mock_get):
    response = client.get(
        "/v0/item/8863.json",
        headers={
            PROXY_HOST_HEADER: "hacker-news.firebaseio.com",
            "Authorization": test_client_secret,
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["title"] == guardette.config.REDACT_TOKEN


@patch("guardette.secrets.ConfigSecretsManager.get", side_effect=GuardetteException("Secret retrieval failed"))
def test_internal_error(mock_get):
    response = client.get(
        "/some/path",
        headers={
            PROXY_HOST_HEADER: "example.com",
            "Authorization": test_client_secret,
        },
    )
    assert response.status_code == 500
    assert response.json()["error"]["source"] == "proxy"
    assert response.headers.get(PROXY_ERROR_HEADER) == "proxy"


def mock_http_bin_match(*args, **kwargs):
    return {
        "target": {"host": "httpbin.org"},
        "rule": {"actions": []},
        "path_params": {},
    }


def mock_transform_404_request(*args, **kwargs):
    return ProxyRequest(
        url="https://httpbin.org/status/404",
        headers={},
        json_data=None,
    )


def mock_transform_404_response(*args, **kwargs):
    return ProxyResponse(
        status_code=404,
        headers={},
        json_data={"detail": "Not Found"},
    )


@patch("guardette.matching.Matcher.match", return_value=mock_http_bin_match())
@patch("guardette.proxy.ProxyTransformer.transform_request", return_value=mock_transform_404_request())
@patch("guardette.proxy.ProxyTransformer.transform_response", return_value=mock_transform_404_response())
@patch("guardette.secrets.ConfigSecretsManager.get", side_effect=get_secret)
def test_proxied_error(mock_match, mock_transform_request, mock_transform_response, mock_get):
    response = client.get(
        "/some/nonexistent/path",
        headers={
            PROXY_HOST_HEADER: "httpbin.org",
            "Authorization": test_client_secret,
        },
    )
    assert response.status_code == 404
    assert response.json()["detail"] == "Not Found"
    assert PROXY_ERROR_HEADER not in response.headers


@patch("httpx.AsyncClient.get", side_effect=httpx.TimeoutException("Request timed out"))
@patch("guardette.matching.Matcher.match", return_value=mock_http_bin_match())
@patch("guardette.proxy.ProxyTransformer.transform_request", return_value=mock_transform_404_request())
@patch("guardette.secrets.ConfigSecretsManager.get", side_effect=get_secret)
def test_proxy_timeout(mock_get, mock_match, mock_transform_request, mock_secrets_get):
    response = client.get(
        "/some/path",
        headers={
            PROXY_HOST_HEADER: "httpbin.org",
            "Authorization": test_client_secret,
        },
    )
    assert response.status_code == 500, response.text
    assert response.json()["error"]["source"] == "proxy"
    assert "details" not in response.json()["error"]
    assert response.headers.get(PROXY_ERROR_HEADER) == "proxy"


@patch("guardette.secrets.ConfigSecretsManager.get", side_effect=get_secret)
def test_meta_route(mock_get):
    response = client.get("/_guardette/meta", headers={"Authorization": test_client_secret})
    assert response.status_code == 200, response.text
    data = response.json()

    # Verify that the response contains the expected keys
    assert "version" in data, "Response should contain 'version'"
    assert "policy" in data, "Response should contain 'policy'"


@patch("guardette.secrets.ConfigSecretsManager.get", side_effect=get_secret)
def test_meta_route_requires_auth(mock_get):
    response = client.get("/_guardette/meta")
    assert response.status_code == 401
    assert response.json()["error"]["message"] == "Unauthorized"
    assert response.headers.get(PROXY_ERROR_HEADER) == "proxy"


def test_health_route_does_not_require_auth():
    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def mock_html_response():
    return httpx.Response(
        status_code=200,
        headers={"content-type": "text/html"},
        content=b"<html><body>Error</body></html>",
    )


@patch("httpx.AsyncClient.get", return_value=mock_html_response())
@patch("guardette.matching.Matcher.match", return_value=mock_http_bin_match())
@patch("guardette.proxy.ProxyTransformer.transform_request", return_value=mock_transform_404_request())
@patch("guardette.secrets.ConfigSecretsManager.get", side_effect=get_secret)
def test_non_json_upstream_response_is_blocked(mock_get, mock_match, mock_transform_request, mock_secrets_get):
    response = client.get(
        "/some/path",
        headers={
            PROXY_HOST_HEADER: "httpbin.org",
            "Authorization": test_client_secret,
        },
    )
    assert response.status_code == 500
    assert response.json()["error"]["source"] == "proxy"
    assert response.headers.get(PROXY_ERROR_HEADER) == "proxy"
