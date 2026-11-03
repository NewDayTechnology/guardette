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
    monkeypatch.setenv("PRESIDIO_ANALYZER_URL", "https://analyzer.example.test/")
    monkeypatch.setenv("PRESIDIO_ANONYMIZER_URL", "http://anonymizer.example.test/")
    monkeypatch.setenv("PRESIDIO_LANGUAGE", " fr ")
    monkeypatch.setenv("PRESIDIO_SCORE_THRESHOLD", "0.75")
    monkeypatch.setenv("PRESIDIO_TIMEOUT_SECS", "4.5")
    monkeypatch.setenv("PRESIDIO_FAIL_MODE", "OPEN")
    monkeypatch.setenv("PRESIDIO_PLACEHOLDER", " Entity ")
    monkeypatch.setenv("PRESIDIO_IGNORE_ENTITIES", " person, URL ,,date_time ")
    monkeypatch.setenv("PRESIDIO_MAX_CONCURRENCY", "3")

    config = ConfigManager()

    assert config.CLIENT_SECRET == "client-secret"  # noqa: S105
    assert config.PSEUDONYMIZE_SALT == "salt"
    assert config.PSEUDONYMIZE_ALGORITHM == "hmac-sha256"
    assert hmac_key == config.HMAC_KEY
    assert config.PROXY_CLIENT_TIMEOUT_SECS == 30
    assert config.SECRET_MANAGER_CACHE_TTL_SECS == 45
    assert config.PSEUDONYMIZE_EMAIL_DOMAINS_ALLOWLIST == ("example.com", "internal.test")
    assert config.PRESIDIO_ANALYZER_URL == "https://analyzer.example.test"
    assert config.PRESIDIO_ANONYMIZER_URL == "http://anonymizer.example.test"
    assert config.PRESIDIO_LANGUAGE == "fr"
    assert config.PRESIDIO_SCORE_THRESHOLD == 0.75
    assert config.PRESIDIO_TIMEOUT_SECS == 4.5
    assert config.PRESIDIO_FAIL_MODE == "open"
    assert config.PRESIDIO_PLACEHOLDER == "entity"
    assert sorted(config.PRESIDIO_IGNORE_ENTITIES) == ["DATE_TIME", "PERSON", "URL"]
    assert config.PRESIDIO_MAX_CONCURRENCY == 3
    assert config.get("MISSING_SETTING", default="fallback") == "fallback"


def test_config_manager_presidio_defaults(monkeypatch):
    monkeypatch.setenv("CLIENT_SECRET", "client-secret")

    config = ConfigManager()

    assert config.PRESIDIO_ANALYZER_URL == "http://localhost:5002"
    assert config.PRESIDIO_ANONYMIZER_URL == "http://localhost:5001"
    assert config.PRESIDIO_LANGUAGE == "en"
    assert config.PRESIDIO_SCORE_THRESHOLD == 0.5
    assert config.PRESIDIO_TIMEOUT_SECS == 10
    assert config.PRESIDIO_FAIL_MODE == "closed"
    assert config.PRESIDIO_PLACEHOLDER == "token"
    assert not config.PRESIDIO_IGNORE_ENTITIES
    assert config.PRESIDIO_MAX_CONCURRENCY == 8


def test_config_manager_rejects_invalid_pseudonymize_algorithm(monkeypatch):
    monkeypatch.setenv("CLIENT_SECRET", "client-secret")
    monkeypatch.setenv("PSEUDONYMIZE_ALGORITHM", "sometimes")

    with pytest.raises(ConfigurationException, match="PSEUDONYMIZE_ALGORITHM"):
        ConfigManager()


@pytest.mark.parametrize(
    ("setting", "value", "message"),
    [
        ("PRESIDIO_ANALYZER_URL", "localhost:5002", "PRESIDIO_ANALYZER_URL"),
        ("PRESIDIO_ANONYMIZER_URL", "ftp://localhost:5001", "PRESIDIO_ANONYMIZER_URL"),
        ("PRESIDIO_SCORE_THRESHOLD", "1.1", "PRESIDIO_SCORE_THRESHOLD"),
        ("PRESIDIO_TIMEOUT_SECS", "0", "PRESIDIO_TIMEOUT_SECS"),
        ("PRESIDIO_FAIL_MODE", "sometimes", "PRESIDIO_FAIL_MODE"),
        ("PRESIDIO_PLACEHOLDER", "hash", "PRESIDIO_PLACEHOLDER"),
        ("PRESIDIO_IGNORE_ENTITIES", "PERSON,EMAIL ADDRESS", "PRESIDIO_IGNORE_ENTITIES"),
        ("PRESIDIO_MAX_CONCURRENCY", "0", "PRESIDIO_MAX_CONCURRENCY"),
    ],
)
def test_config_manager_rejects_invalid_presidio_settings(monkeypatch, setting, value, message):
    monkeypatch.setenv("CLIENT_SECRET", "client-secret")
    monkeypatch.setenv(setting, value)

    with pytest.raises(ConfigurationException, match=message):
        ConfigManager()
