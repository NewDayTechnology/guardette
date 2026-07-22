import base64
import hashlib
import hmac

import pytest
from starlette.datastructures import MutableHeaders

from guardette.actions import ActionContext, action_registry
from guardette.config import ConfigManager
from guardette.datastructures import ProxyRequest, ProxyResponse
from guardette.exceptions import ConfigurationException
from guardette.secrets import ConfigSecretsManager


def _action_context(config: ConfigManager) -> ActionContext:
    return ActionContext(
        config=config,
        secrets=ConfigSecretsManager(config),
        request=ProxyRequest(url="http://test.com", headers=MutableHeaders({}), json_data={}),
        response=ProxyResponse(status_code=200, headers=MutableHeaders(), json_data={"email": "Alice@Example.com"}),
    )


def _expected_hmac_pseudonym(email: str, key: str) -> str:
    username, domain = email.lower().split("@")

    def digest(part: str, value: str) -> str:
        message = f"guardette:pseudonymize_email:v1:{part}:{value}".encode()
        result = hmac.new(key.encode(), message, hashlib.sha256).digest()
        return base64.b32encode(result).decode().rstrip("=").lower()

    return f"u-{digest('local', username)}@d-{digest('domain', domain)}.invalid"


@pytest.mark.anyio
async def test_pseudonymize_email_uses_hmac_when_enabled(monkeypatch):
    key = "hmac-key-" + "a" * 32
    monkeypatch.setenv("CLIENT_SECRET", "client-secret")
    monkeypatch.setenv("PSEUDONYMIZE_ALGORITHM", "hmac-sha256")
    monkeypatch.setenv("HMAC_KEY", key)

    config = ConfigManager()
    action_cls = action_registry.get_action_cls("pseudonymize_email")
    action_cls.validate_config(config)
    action = action_cls.model_validate({"json_paths": ["$.email"]})
    context = _action_context(config)

    await action.response(context)

    assert context.response.json_data["email"] == _expected_hmac_pseudonym("Alice@Example.com", key)


@pytest.mark.anyio
async def test_pseudonymize_email_legacy_mode_remains_default(monkeypatch):
    monkeypatch.setenv("CLIENT_SECRET", "client-secret")
    monkeypatch.delenv("PSEUDONYMIZE_ALGORITHM", raising=False)
    monkeypatch.setenv("PSEUDONYMIZE_SALT", "salt")

    config = ConfigManager()
    action_cls = action_registry.get_action_cls("pseudonymize_email")
    action_cls.validate_config(config)
    action = action_cls.model_validate({"json_paths": ["$.email"]})
    context = _action_context(config)

    await action.response(context)

    username, domain = "alice", "example.com"
    username_hash = base64.b32encode(hashlib.sha256((username + "salt").encode()).digest()).decode().rstrip("=")
    domain_hash = base64.b32encode(hashlib.sha256((domain + "salt").encode()).digest()).decode().rstrip("=")
    assert context.response.json_data["email"] == f"u-{username_hash}@d-{domain_hash}.invalid".lower()


def test_pseudonymize_email_hmac_requires_key(monkeypatch):
    monkeypatch.setenv("CLIENT_SECRET", "client-secret")
    monkeypatch.setenv("PSEUDONYMIZE_ALGORITHM", "hmac-sha256")
    monkeypatch.delenv("HMAC_KEY", raising=False)

    config = ConfigManager()
    action_cls = action_registry.get_action_cls("pseudonymize_email")

    with pytest.raises(ConfigurationException, match="HMAC_KEY"):
        action_cls.validate_config(config)


@pytest.mark.anyio
async def test_pseudonymize_email_hmac_rejects_short_key(monkeypatch):
    monkeypatch.setenv("CLIENT_SECRET", "client-secret")
    monkeypatch.setenv("PSEUDONYMIZE_ALGORITHM", "hmac-sha256")
    monkeypatch.setenv("HMAC_KEY", "short")

    config = ConfigManager()
    action = action_registry.get_action_cls("pseudonymize_email").model_validate({"json_paths": ["$.email"]})
    context = _action_context(config)

    with pytest.raises(ConfigurationException, match="at least 32 bytes"):
        await action.response(context)
