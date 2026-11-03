import copy
import json

import httpx
import pytest

import guardette.default_actions  # noqa: F401  (registers actions used by the templates)
from guardette.policy import Policy

JIRA_DOMAIN = "example.atlassian.net"
KINDS = ["jira_basic_auth", "jira_oauth2"]
MVP_ROUTES = {
    "jira_basic_auth": {"GET /rest/api/3/issue/{issueIdOrKey}"},
    "jira_oauth2": {"GET /ex/jira/{cloudId}/rest/api/3/issue/{issueIdOrKey}"},
}
SECRET = "ghp_" + "a" * 36


def _render(render_policy, kind, **config):
    data = render_policy(kind, jira_domain=JIRA_DOMAIN, **config)
    # Validate a copy: Policy validation pops `kind` from the action dicts it is given.
    policy = Policy(**copy.deepcopy(data))
    routes = {rule["route"] for source in data["sources"] for rule in source["rules"]}
    return data, policy, routes


@pytest.mark.parametrize("kind", KINDS)
def test_jira_templates_default_to_single_issue_route(render_policy, kind):
    data, _, routes = _render(render_policy, kind)

    assert routes == MVP_ROUTES[kind]
    assert len(data["sources"]) == 1
    actions = [action["kind"] for action in data["sources"][0]["rules"][0]["actions"]]
    assert actions == ["nullify", "presidio_anonymize", "redact_regex"]


@pytest.mark.parametrize("kind", KINDS)
def test_jira_templates_extended_routes_are_opt_in(render_policy, kind):
    _, _, routes = _render(render_policy, kind, include_extended_routes=True)

    assert MVP_ROUTES[kind] < routes
    assert any(route.endswith("/rest/api/3/search/jql") for route in routes)
    assert any(route.endswith("/rest/agile/1.0/board/{boardId}/issue") for route in routes)
    assert "GET /rest/dev-status/1.0/issue/detail" in routes


def _presidio_no_entities(request):
    if request.url.path == "/analyze":
        return httpx.Response(200, json=[])
    return httpx.Response(200, json={"text": json.loads(request.content)["text"], "items": []})


def _issue():
    return {
        "fields": {"summary": f"key {SECRET}"},
        "versionedRepresentations": {
            "summary": {"1": f"key {SECRET}"},
            "description": {"1": {"type": "doc", "content": [{"type": "text", "text": SECRET}]}},
        },
    }


@pytest.mark.anyio
@pytest.mark.parametrize("kind", KINDS)
async def test_issue_routes_do_not_leak_versioned_representations(render_policy, kind, action_context, monkeypatch):
    monkeypatch.setattr(
        "guardette.default_actions.presidio_anonymize.get_shared_client",
        lambda _config: httpx.AsyncClient(transport=httpx.MockTransport(_presidio_no_entities)),
    )
    _, policy, _ = _render(render_policy, kind, include_extended_routes=True)
    issue_rules = [
        rule
        for source in policy.sources
        for rule in source.rules
        if rule.route.endswith(("/issue/{issueIdOrKey}", "/api/3/search", "/search/jql", "/board/{boardId}/issue"))
    ]
    assert len(issue_rules) == 4

    for rule in issue_rules:
        single = rule.route.endswith("/issue/{issueIdOrKey}")
        action_context.response.json_data = _issue() if single else {"issues": [_issue()]}
        for action in rule.actions:
            await action.response(action_context)

        assert SECRET not in json.dumps(action_context.response.json_data), rule.route
