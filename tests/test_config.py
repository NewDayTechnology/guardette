import pytest

from guardette.config import ConfigManager
from guardette.exceptions import ConfigurationException


def test_config_manager_requires_client_secret(monkeypatch):
    monkeypatch.delenv("CLIENT_SECRET", raising=False)

    with pytest.raises(ConfigurationException, match="CLIENT_SECRET"):
        ConfigManager()


def test_config_manager_parses_environment_settings(monkeypatch):
    monkeypatch.setenv("CLIENT_SECRET", "client-secret")
    monkeypatch.setenv("PSEUDONYMIZE_SALT", "salt")
    monkeypatch.setenv("PSEUDONYMIZE_ALGORITHM", "hmac-sha256")
    hmac_key = "hmac-key-" + "a" * 32
    monkeypatch.setenv("HMAC_KEY", hmac_key)
    monkeypatch.setenv("PROXY_CLIENT_TIMEOUT_SECS", "30")
    monkeypatch.setenv("SECRET_MANAGER_CACHE_TTL_SECS", "45")
    monkeypatch.setenv("PSEUDONYMIZE_EMAIL_DOMAINS_ALLOWLIST", "Example.COM,internal.test")

    config = ConfigManager()

    assert config.CLIENT_SECRET == "client-secret"  # noqa: S105
    assert config.PSEUDONYMIZE_SALT == "salt"
    assert config.PSEUDONYMIZE_ALGORITHM == "hmac-sha256"
    assert hmac_key == config.HMAC_KEY
    assert config.PROXY_CLIENT_TIMEOUT_SECS == 30
    assert config.SECRET_MANAGER_CACHE_TTL_SECS == 45
    assert config.PSEUDONYMIZE_EMAIL_DOMAINS_ALLOWLIST == ("example.com", "internal.test")
    assert config.get("MISSING_SETTING", default="fallback") == "fallback"


def test_config_manager_rejects_invalid_pseudonymize_algorithm(monkeypatch):
    monkeypatch.setenv("CLIENT_SECRET", "client-secret")
    monkeypatch.setenv("PSEUDONYMIZE_ALGORITHM", "sometimes")

    with pytest.raises(ConfigurationException, match="PSEUDONYMIZE_ALGORITHM"):
        ConfigManager()
