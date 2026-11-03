"""Unit tests for the `presidio_anonymize` action (Phase 4, plan §8.1).

Covers the gaps left by `test_presidio.py` (which tests `PresidioClient`):
- action-level `json_paths` batch write-back + both services called in order
- write-back across JSONPath flavours: recursive `$..`, wildcard `[*]`, filter `[?()]`
- non-string / empty leaves skipped
- ADF reconstruction (§6.6): one `/analyze` per field, one `/anonymize` per node,
  structure preserved, boundary-straddle, no-entity no-op, whitespace-node skip

The Presidio HTTP boundary is mocked with `httpx.MockTransport`; the mock
anonymizer performs real span replacement so surrounding text is asserted too.
"""

import json

import httpx
import pytest

import guardette.default_actions  # noqa: F401  (registers presidio_anonymize)
from guardette.actions import action_registry

PERSON = "PERSON"


def _handler(analyze_results, calls):
    """Mock /analyze (returns fixed results) and /anonymize (span-replaces)."""

    def handler(request):
        calls.append(request.url.path)
        if request.url.path == "/analyze":
            return httpx.Response(200, json=[dict(r) for r in analyze_results])
        body = json.loads(request.content)
        text = body["text"]
        for r in sorted(body.get("analyzer_results", []), key=lambda x: x["start"], reverse=True):
            text = text[: r["start"]] + "[REDACTED]" + text[r["end"] :]
        return httpx.Response(200, json={"text": text, "items": []})

    return handler


def _patch_shared_client(monkeypatch, handler):
    monkeypatch.setattr(
        "guardette.default_actions.presidio_anonymize.get_shared_client",
        lambda _config: httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )


def _action(**kwargs):
    return action_registry.get_action_cls("presidio_anonymize").model_validate(kwargs, strict=True)


def _text_node(text):
    return {"type": "text", "text": text}


def _adf_doc(*texts):
    return {
        "type": "doc",
        "version": 1,
        "content": [{"type": "paragraph", "content": [_text_node(t) for t in texts]}],
    }


def _nodes(doc):
    return doc["content"][0]["content"]


@pytest.mark.anyio
async def test_json_path_anonymizes_and_calls_both_in_order(action_context, monkeypatch):
    calls = []
    _patch_shared_client(monkeypatch, _handler([{"entity_type": PERSON, "start": 11, "end": 13, "score": 0.9}], calls))
    action_context.response.json_data = {"summary": "My name is Jo"}

    await _action(json_paths=["$.summary"]).response(action_context)

    assert action_context.response.json_data["summary"] == "My name is [REDACTED]"
    assert calls == ["/analyze", "/anonymize"]


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("data", "path", "redacted", "untouched"),
    [
        pytest.param(
            {"a": {"summary": "Jo"}, "b": {"c": {"summary": "Al"}}},
            "$..summary",
            [("a", "summary"), ("b", "c", "summary")],
            [],
            id="recursive-descent",
        ),
        pytest.param(
            {"issues": [{"fields": {"summary": "Jo"}}, {"fields": {"summary": "Al"}}]},
            "$.issues[*].fields.summary",
            [("issues", 0, "fields", "summary"), ("issues", 1, "fields", "summary")],
            [],
            id="wildcard",
        ),
        pytest.param(
            {"items": [{"k": "x", "v": "Jo"}, {"k": "y", "v": "Al"}]},
            '$.items[?(@.k=="x")].v',
            [("items", 0, "v")],
            [("items", 1, "v", "Al")],
            id="filter",
        ),
    ],
)
async def test_json_path_write_back_flavours(  # noqa: PLR0917
    action_context, monkeypatch, data, path, redacted, untouched
):
    calls = []
    # A full-span PERSON for the 2-char values ("Jo"/"Al").
    _patch_shared_client(monkeypatch, _handler([{"entity_type": PERSON, "start": 0, "end": 2, "score": 0.9}], calls))
    action_context.response.json_data = data

    await _action(json_paths=[path]).response(action_context)

    def _get(keys):
        node = action_context.response.json_data
        for k in keys:
            node = node[k]
        return node

    for keys in redacted:
        assert _get(keys) == "[REDACTED]"
    for *keys, expected in untouched:
        assert _get(keys) == expected


@pytest.mark.anyio
async def test_non_string_and_empty_leaves_skip_http(action_context, monkeypatch):
    calls = []
    _patch_shared_client(monkeypatch, _handler([{"entity_type": PERSON, "start": 0, "end": 2, "score": 0.9}], calls))
    action_context.response.json_data = {"empty": "", "blank": "   ", "num": 123, "nothing": None}

    await _action(json_paths=["$.empty", "$.blank", "$.num", "$.nothing"]).response(action_context)

    assert calls == []
    assert action_context.response.json_data == {"empty": "", "blank": "   ", "num": 123, "nothing": None}


@pytest.mark.anyio
async def test_adf_reconstruction_one_analyze_per_field_one_anonymize_per_node(action_context, monkeypatch):
    calls = []
    # Joined text is "John Smith"; a PERSON straddles both nodes (0..10).
    _patch_shared_client(monkeypatch, _handler([{"entity_type": PERSON, "start": 0, "end": 10, "score": 0.9}], calls))
    doc = _adf_doc("John", "Smith")
    action_context.response.json_data = {"fields": {"description": doc}}

    await _action(adf_paths=["$.fields.description"]).response(action_context)

    assert calls.count("/analyze") == 1
    assert calls.count("/anonymize") == 2
    nodes = _nodes(action_context.response.json_data["fields"]["description"])
    assert [n["text"] for n in nodes] == ["[REDACTED]", "[REDACTED]"]
    assert len(nodes) == 2  # structure preserved


@pytest.mark.anyio
async def test_adf_entity_in_single_node_leaves_other_node(action_context, monkeypatch):
    calls = []
    # Entity covers only "John" (0..4) within "John Smith".
    _patch_shared_client(monkeypatch, _handler([{"entity_type": PERSON, "start": 0, "end": 4, "score": 0.9}], calls))
    doc = _adf_doc("John", "Smith")
    action_context.response.json_data = {"fields": {"description": doc}}

    await _action(adf_paths=["$.fields.description"]).response(action_context)

    assert calls.count("/analyze") == 1
    assert calls.count("/anonymize") == 2
    assert [n["text"] for n in _nodes(action_context.response.json_data["fields"]["description"])] == [
        "[REDACTED]",
        "Smith",
    ]


@pytest.mark.anyio
async def test_adf_no_entities_is_noop_but_still_calls_services(action_context, monkeypatch):
    calls = []
    _patch_shared_client(monkeypatch, _handler([], calls))
    doc = _adf_doc("John", "Smith")
    action_context.response.json_data = {"fields": {"description": doc}}

    await _action(adf_paths=["$.fields.description"]).response(action_context)

    assert calls.count("/analyze") == 1
    assert calls.count("/anonymize") == 2
    assert [n["text"] for n in _nodes(action_context.response.json_data["fields"]["description"])] == ["John", "Smith"]


@pytest.mark.anyio
async def test_adf_whitespace_node_is_skipped(action_context, monkeypatch):
    calls = []
    _patch_shared_client(monkeypatch, _handler([{"entity_type": PERSON, "start": 0, "end": 4, "score": 0.9}], calls))
    doc = _adf_doc("John", "   ")
    action_context.response.json_data = {"fields": {"description": doc}}

    await _action(adf_paths=["$.fields.description"]).response(action_context)

    assert calls.count("/analyze") == 1
    assert calls.count("/anonymize") == 1  # whitespace node not sent
    assert [n["text"] for n in _nodes(action_context.response.json_data["fields"]["description"])] == [
        "[REDACTED]",
        "   ",
    ]


@pytest.mark.anyio
async def test_requires_at_least_one_target():
    with pytest.raises(ValueError, match="at least one of json_paths or adf_paths"):
        _action()


def _presidio_down(_request):
    return httpx.Response(503)


def test_fail_mode_defaults_to_closed(action_context):
    assert action_context.config.PRESIDIO_FAIL_MODE == "closed"


@pytest.mark.anyio
async def test_presidio_failure_redacts_json_and_adf_fields_by_default(action_context, monkeypatch):
    _patch_shared_client(monkeypatch, _presidio_down)
    action_context.response.json_data = {
        "fields": {"summary": "My name is Jo", "description": _adf_doc("John", "Smith")}
    }

    await _action(json_paths=["$.fields.summary"], adf_paths=["$.fields.description"]).response(action_context)

    token = action_context.config.REDACT_TOKEN
    fields = action_context.response.json_data["fields"]
    assert fields["summary"] == token
    assert [n["text"] for n in _nodes(fields["description"])] == [token, token]
    assert "Jo" not in json.dumps(action_context.response.json_data)


@pytest.mark.anyio
async def test_presidio_failure_passes_through_when_fail_mode_open(action_context, monkeypatch):
    _patch_shared_client(monkeypatch, _presidio_down)
    monkeypatch.setattr(action_context.config, "PRESIDIO_FAIL_MODE", "open")
    action_context.response.json_data = {"fields": {"summary": "My name is Jo", "description": _adf_doc("John")}}

    await _action(json_paths=["$.fields.summary"], adf_paths=["$.fields.description"]).response(action_context)

    fields = action_context.response.json_data["fields"]
    assert fields["summary"] == "My name is Jo"
    assert [n["text"] for n in _nodes(fields["description"])] == ["John"]
