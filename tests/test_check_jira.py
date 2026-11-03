import importlib.util
from pathlib import Path

import pytest
import requests

module_spec = importlib.util.spec_from_file_location("check_jira", Path(__file__).parents[1] / "scripts/check_jira.py")
assert module_spec is not None
assert module_spec.loader is not None
check_jira = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(check_jira)


def test_do_request_returns_json_and_preserves_timeout(monkeypatch):
    response = requests.Response()
    response.status_code = 200
    response._content = b'{"ok": true}'

    def fake_get(url, *args, **kwargs):
        assert url == "https://jira.example.test/api"
        assert kwargs["timeout"] == 5
        return response

    monkeypatch.setattr(check_jira.requests, "get", fake_get)

    assert check_jira.do_request("https://jira.example.test/api", timeout=5) == {"ok": True}


def test_do_request_raises_for_non_success_response(monkeypatch):
    response = requests.Response()
    response.status_code = 503
    response._content = b"upstream unavailable"

    monkeypatch.setattr(check_jira.requests, "get", lambda *_args, **_kwargs: response)

    try:
        check_jira.do_request("https://jira.example.test/api")
    except requests.HTTPError as error:
        assert "503" in str(error)
        assert error.response is response
    else:
        raise AssertionError("Expected requests.HTTPError")


def test_fetch_issue_requests_only_the_given_issue(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    calls = []

    def fake_request(url, **kwargs):
        calls.append((url, kwargs.get("params")))
        return {"key": "ABC-123"}

    monkeypatch.setattr(check_jira, "do_request", fake_request)

    check_jira.fetch_issue("token", "jira.example.test", "http://proxy.test", "ABC-123")

    assert calls == [
        ("http://proxy.test/rest/api/3/issue/ABC-123", {"fields": "*all", "expand": "renderedFields,changelog"})
    ]
    assert (tmp_path / ".guardette" / "jira_issue_response.json").is_file()


@pytest.mark.parametrize("key", ["abc-123", "ABC", "ABC-123/../x", "ABC-123?expand=x", ""])
def test_fetch_issue_rejects_non_issue_keys(monkeypatch, key):
    monkeypatch.setattr(check_jira, "do_request", lambda *_a, **_k: pytest.fail("request should not be sent"))

    with pytest.raises(ValueError, match="Not a Jira issue key"):
        check_jira.fetch_issue("token", "jira.example.test", "http://proxy.test", key)


def test_extended_apis_creates_output_files(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    def fake_request(url, **_kwargs):
        if url.endswith("/rest/agile/1.0/board"):
            return {"values": [{"id": 42}]}
        if "/rest/agile/1.0/board/42/issue" in url:
            return {"issues": []}
        return {}

    monkeypatch.setattr(check_jira, "do_request", fake_request)

    check_jira.extended_apis("token", "jira.example.test", "http://proxy.test")

    assert (tmp_path / ".guardette" / "jira_boards_response.json").is_file()
    assert (tmp_path / ".guardette" / "jira_board_issues_response.json").is_file()
