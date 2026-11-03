import json

import httpx
import pytest

from guardette.config import ConfigManager
from guardette.presidio import PresidioClient


def _transport(handler):
    return httpx.MockTransport(handler)


@pytest.mark.anyio
async def test_anonymize_text_calls_both_services_in_order_and_trims_results():
    calls = []

    def handler(request):
        calls.append(request.url.path)
        body = json.loads(request.content)
        if request.url.path == "/analyze":
            assert body == {"text": "My name is Jo", "language": "en", "score_threshold": 0.5}
            return httpx.Response(
                200,
                json=[{"entity_type": "PERSON", "start": 11, "end": 13, "score": 0.9, "analysis_explanation": None}],
            )
        assert body["text"] == "My name is Jo"
        assert body["anonymizers"] == {"DEFAULT": {"type": "replace", "new_value": "[REDACTED]"}}
        # Only the four required fields are forwarded (analysis_explanation dropped).
        assert body["analyzer_results"] == [{"entity_type": "PERSON", "start": 11, "end": 13, "score": 0.9}]
        return httpx.Response(200, json={"text": "My name is [REDACTED]", "items": []})

    client = PresidioClient(ConfigManager())
    async with httpx.AsyncClient(transport=_transport(handler)) as http:
        out = await client.anonymize_text(http, "My name is Jo", fail_closed=False)

    assert out == "My name is [REDACTED]"
    assert calls == ["/analyze", "/anonymize"]


@pytest.mark.anyio
async def test_anonymize_entity_placeholder_omits_new_value(monkeypatch):
    monkeypatch.setenv("PRESIDIO_PLACEHOLDER", "entity")
    sent = {}

    def handler(request):
        sent.update(json.loads(request.content))
        return httpx.Response(200, json={"text": "My name is <PERSON>", "items": []})

    client = PresidioClient(ConfigManager())
    results = [{"entity_type": "PERSON", "start": 11, "end": 13, "score": 0.9}]
    async with httpx.AsyncClient(transport=_transport(handler)) as http:
        out = await client.anonymize(http, "My name is Jo", results)

    assert sent["anonymizers"] == {"DEFAULT": {"type": "replace"}}
    assert out == "My name is <PERSON>"


@pytest.mark.anyio
async def test_ignored_entities_are_dropped_before_anonymize(monkeypatch):
    monkeypatch.setenv("PRESIDIO_IGNORE_ENTITIES", "PERSON,URL")
    sent = {}
    text = "Jo paid with 4111111111111111 via https://x.test"

    def handler(request):
        if request.url.path == "/analyze":
            return httpx.Response(
                200,
                json=[
                    {"entity_type": "PERSON", "start": 0, "end": 2, "score": 0.9},
                    {"entity_type": "CREDIT_CARD", "start": 13, "end": 29, "score": 1.0},
                    {"entity_type": "URL", "start": 34, "end": 48, "score": 0.6},
                ],
            )
        sent.update(json.loads(request.content))
        return httpx.Response(200, json={"text": "redacted", "items": []})

    client = PresidioClient(ConfigManager())
    async with httpx.AsyncClient(transport=_transport(handler)) as http:
        await client.anonymize_text(http, text, fail_closed=False)

    assert [r["entity_type"] for r in sent["analyzer_results"]] == ["CREDIT_CARD"]


@pytest.mark.anyio
@pytest.mark.parametrize("value", ["", "   ", None, 123])
async def test_anonymize_text_short_circuits_without_http(value):
    calls = []

    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(200, json=[])

    client = PresidioClient(ConfigManager())
    async with httpx.AsyncClient(transport=_transport(handler)) as http:
        out = await client.anonymize_text(http, value, fail_closed=False)

    assert out == value
    assert calls == []


@pytest.mark.anyio
async def test_anonymize_text_no_entities_still_calls_both():
    calls = []

    def handler(request):
        calls.append(request.url.path)
        if request.url.path == "/analyze":
            return httpx.Response(200, json=[])
        return httpx.Response(200, json={"text": "nothing here", "items": []})

    client = PresidioClient(ConfigManager())
    async with httpx.AsyncClient(transport=_transport(handler)) as http:
        out = await client.anonymize_text(http, "nothing here", fail_closed=False)

    assert out == "nothing here"
    assert calls == ["/analyze", "/anonymize"]


@pytest.mark.anyio
async def test_anonymize_text_fail_open_returns_original():
    def handler(request):
        raise httpx.ConnectError("down")

    client = PresidioClient(ConfigManager())
    async with httpx.AsyncClient(transport=_transport(handler)) as http:
        out = await client.anonymize_text(http, "My name is Jo", fail_closed=False)

    assert out == "My name is Jo"


@pytest.mark.anyio
async def test_anonymize_text_fail_closed_returns_replacement():
    def handler(request):
        raise httpx.ConnectError("down")

    config = ConfigManager()
    client = PresidioClient(config)
    async with httpx.AsyncClient(transport=_transport(handler)) as http:
        out = await client.anonymize_text(http, "My name is Jo", fail_closed=True)

    assert out == config.REDACT_TOKEN
    assert "Jo" not in out


@pytest.mark.anyio
async def test_anonymize_text_fail_mode_applies_on_http_error_status():
    def handler(request):
        if request.url.path == "/analyze":
            return httpx.Response(500, text="boom")
        return httpx.Response(200, json={"text": "unused", "items": []})

    client = PresidioClient(ConfigManager())
    async with httpx.AsyncClient(transport=_transport(handler)) as http:
        out = await client.anonymize_text(http, "My name is Jo", fail_closed=False)

    assert out == "My name is Jo"
