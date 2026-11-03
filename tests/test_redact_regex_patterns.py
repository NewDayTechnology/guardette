import re

import pytest

from guardette.actions import action_registry

KINDS = ["jira_basic_auth", "jira_oauth2"]
# Neutral stand-in for an organisation keyword; real keywords live only in the gitignored policygen config.
KEYWORD_PATTERN = r"\bacme(?:'|" + "\u2019" + r"|&\#39;)?s"


def _regex_patterns(policy):
    return {
        action["regex_pattern"]
        for source in policy["sources"]
        for rule in source["rules"]
        for action in rule.get("actions") or []
        if action["kind"] == "redact_regex"
    }


def _shared_pattern(render_policy, **config):
    patterns = set()
    for kind in KINDS:
        policy = render_policy(kind, jira_domain="example.atlassian.net", include_extended_routes=True, **config)
        patterns |= _regex_patterns(policy)
    assert len(patterns) == 1, "every Jira route in both templates must use the same secret regex"
    return patterns.pop()


@pytest.fixture(scope="module")
def shipped_pattern(render_policy):
    """The secret regex exactly as the Jira templates ship it, with one configured keyword."""
    return _shared_pattern(render_policy, redact_keyword_patterns=[KEYWORD_PATTERN])


def test_templates_ship_no_keyword_by_default(render_policy):
    pattern = _shared_pattern(render_policy)

    assert "acme" not in pattern
    assert re.compile(pattern).search("acmes") is None
    assert re.compile(pattern).search("ghp_" + "a" * 36)


@pytest.fixture
def redact(action_context, shipped_pattern):
    async def _redact(value):
        action = action_registry.get_action_cls("redact_regex").model_validate(
            {"json_paths": ["$.text"], "regex_pattern": shipped_pattern}
        )
        action_context.response.json_data = {"text": value}
        await action.response(action_context)
        return action_context.response.json_data["text"]

    return _redact


@pytest.fixture
def token(action_context):
    return action_context.config.REDACT_TOKEN


@pytest.mark.anyio
@pytest.mark.parametrize(
    "card",
    [
        "4111 1111 1111 1111",
        "4111-1111-1111-1111",
        "4111111111111111",
        "5500 0000 0000 0004",
        "2223000048400011",
        "340000000000009",
        "6011000000000004",
    ],
)
async def test_card_numbers(redact, token, card):
    assert await redact(f"card {card} on file") == f"card {token} on file"


@pytest.mark.anyio
@pytest.mark.parametrize(
    "value",
    [
        "order 1234567890123 shipped",  # 13-digit id, no card prefix
        "ref 98765432109876 pending",  # 14-digit id, no card prefix
        "ticket 123456789 open",  # short numeric id
    ],
)
async def test_card_numbers_near_miss(redact, value):
    assert await redact(value) == value


@pytest.mark.anyio
@pytest.mark.parametrize(
    "value",
    [
        "api_key: ABCDEFGHIJKLMNOP1234",
        "access-key = abcdefghijklmnop1234",
        "client_secret: s3cr3t_value_ABCDEFGH",
        "Bearer abcdefghijklmnop1234",
    ],
)
async def test_api_keys_and_bearer(redact, token, value):
    assert await redact(value) == token


@pytest.mark.anyio
@pytest.mark.parametrize(
    "value",
    [
        "The bearer of this note may enter",  # prose, short token
        "The api_key field is required",  # label without a value
    ],
)
async def test_api_keys_and_bearer_near_miss(redact, value):
    assert await redact(value) == value


@pytest.mark.anyio
@pytest.mark.parametrize(
    "secret",
    [
        "ghp_" + "a" * 36,
        "gho_" + "b" * 36,
        "github_pat_" + "c" * 22,
        "glpat-" + "d" * 20,
        "xoxb-" + "e" * 20,
        "AKIAIOSFODNN7EXAMPLE",
        "ASIAIOSFODNN7EXAMPLE",
    ],
)
async def test_provider_tokens(redact, token, secret):
    assert await redact(f"token={secret} end") == f"token={token} end"


@pytest.mark.anyio
@pytest.mark.parametrize("value", ["ghp_short", "glpat-short", "AKIA123"])
async def test_provider_tokens_near_miss(redact, value):
    assert await redact(value) == value


@pytest.mark.anyio
async def test_private_key_block(redact, token):
    # Header and footer are split so secret scanners do not flag this fake key.
    begin, end = "-----BEGIN " + "RSA PRIVATE KEY-----", "-----END " + "RSA PRIVATE KEY-----"
    private_key = (
        f"{begin}\n"
        "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Q\n"
        "uKUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQIDAQAB\n"
        f"{end}"
    )
    assert await redact(f"key:\n{private_key}\nend") == f"key:\n{token}\nend"


@pytest.mark.anyio
async def test_jwt(redact, token):
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5Nq"
    assert await redact(f"auth {jwt} done") == f"auth {token} done"


@pytest.mark.anyio
async def test_jwt_near_miss(redact):
    assert await redact("eyJshort.notatoken") == "eyJshort.notatoken"


@pytest.mark.anyio
@pytest.mark.parametrize("keyword", ["acmes", "Acmes", "ACMES", "Acme's", "Acme\u2019s", "Acme&#39;s"])
async def test_keyword_matches(redact, token, keyword):
    assert await redact(f"raised for {keyword} today") == f"raised for {token} today"


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("acmesbank statement", "{token}bank statement"),
        ("see acmes_bank", "see {token}_bank"),
        ("www.acmes.com", "www.{token}.com"),
    ],
)
async def test_keyword_prefix_matches(redact, token, value, expected):
    assert await redact(value) == expected.format(token=token)


@pytest.mark.anyio
@pytest.mark.parametrize("value", ["Acme joined", "an acme sample", "placmes", "cacmes is unrelated"])
async def test_keyword_near_miss(redact, value):
    assert await redact(value) == value


@pytest.mark.anyio
async def test_several_kinds_in_one_value(redact, token):
    assert await redact("acmes card 4111 1111 1111 1111 kept note") == f"{token} card {token} kept note"


@pytest.mark.anyio
async def test_non_string_values_unchanged(action_context, shipped_pattern):
    action = action_registry.get_action_cls("redact_regex").model_validate(
        {"json_paths": ["$.number", "$.flag", "$.empty"], "regex_pattern": shipped_pattern}
    )
    data = {"number": 4111111111111111, "flag": True, "empty": None}
    action_context.response.json_data = dict(data)
    await action.response(action_context)
    assert action_context.response.json_data == data
