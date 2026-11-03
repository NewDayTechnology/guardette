import os
import re
from urllib.parse import urlparse

from guardette.exceptions import ConfigurationException

_PSEUDONYMIZE_ALGORITHMS = frozenset({"sha256", "hmac-sha256"})
_ENTITY_NAME = re.compile(r"[A-Z][A-Z0-9_]*")


class ConfigManager:
    REDACT_TOKEN = "[REDACTED]"  # noqa: S105

    def __init__(self):
        self.PSEUDONYMIZE_SALT: str = os.environ.get("PSEUDONYMIZE_SALT", "")
        self.PSEUDONYMIZE_ALGORITHM: str = os.environ.get("PSEUDONYMIZE_ALGORITHM", "sha256").strip().lower()
        self.HMAC_KEY: str = os.environ.get("HMAC_KEY", "")
        self.CLIENT_SECRET: str = os.environ.get("CLIENT_SECRET", "")
        self.SECRET_MANAGER: str = os.environ.get("SECRET_MANAGER", "default")
        self.PROXY_CLIENT_TIMEOUT_SECS: int = int(os.environ.get("PROXY_CLIENT_TIMEOUT_SECS", "60"))
        self.SECRET_MANAGER_CACHE_TTL_SECS: int = int(os.environ.get("SECRET_MANAGER_CACHE_TTL_SECS", "120"))
        self.PRESIDIO_ANALYZER_URL: str = os.environ.get("PRESIDIO_ANALYZER_URL", "http://localhost:5002").rstrip("/")
        self.PRESIDIO_ANONYMIZER_URL: str = os.environ.get("PRESIDIO_ANONYMIZER_URL", "http://localhost:5001").rstrip(
            "/"
        )
        self.PRESIDIO_LANGUAGE: str = os.environ.get("PRESIDIO_LANGUAGE", "en").strip()
        self.PRESIDIO_SCORE_THRESHOLD: float = float(os.environ.get("PRESIDIO_SCORE_THRESHOLD", "0.5"))
        self.PRESIDIO_TIMEOUT_SECS: float = float(os.environ.get("PRESIDIO_TIMEOUT_SECS", "10"))
        self.PRESIDIO_FAIL_MODE: str = os.environ.get("PRESIDIO_FAIL_MODE", "closed").strip().lower()
        self.PRESIDIO_PLACEHOLDER: str = os.environ.get("PRESIDIO_PLACEHOLDER", "token").strip().lower()
        self.PRESIDIO_IGNORE_ENTITIES: frozenset[str] = frozenset(
            e.strip().upper() for e in os.environ.get("PRESIDIO_IGNORE_ENTITIES", "").split(",") if e.strip()
        )
        self.PRESIDIO_MAX_CONCURRENCY: int = int(os.environ.get("PRESIDIO_MAX_CONCURRENCY", "8"))
        self.PSEUDONYMIZE_EMAIL_DOMAINS_ALLOWLIST: tuple[str, ...] = tuple(
            [d.lower() for d in os.environ.get("PSEUDONYMIZE_EMAIL_DOMAINS_ALLOWLIST", "").split(",") if d]
        )

        if self.PSEUDONYMIZE_ALGORITHM not in _PSEUDONYMIZE_ALGORITHMS:
            raise ConfigurationException(
                "PSEUDONYMIZE_ALGORITHM must be one of: " + ", ".join(sorted(_PSEUDONYMIZE_ALGORITHMS))
            )
        for setting, url in (
            ("PRESIDIO_ANALYZER_URL", self.PRESIDIO_ANALYZER_URL),
            ("PRESIDIO_ANONYMIZER_URL", self.PRESIDIO_ANONYMIZER_URL),
        ):
            parsed_url = urlparse(url)
            if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
                raise ConfigurationException(f"{setting} must be an absolute HTTP or HTTPS URL.")
        if not self.PRESIDIO_LANGUAGE:
            raise ConfigurationException("PRESIDIO_LANGUAGE must be non-empty.")
        if not 0 <= self.PRESIDIO_SCORE_THRESHOLD <= 1:
            raise ConfigurationException("PRESIDIO_SCORE_THRESHOLD must be between 0 and 1.")
        if self.PRESIDIO_TIMEOUT_SECS <= 0:
            raise ConfigurationException("PRESIDIO_TIMEOUT_SECS must be greater than 0.")
        if self.PRESIDIO_FAIL_MODE not in {"open", "closed"}:
            raise ConfigurationException("PRESIDIO_FAIL_MODE must be either 'open' or 'closed'.")
        if self.PRESIDIO_PLACEHOLDER not in {"token", "entity"}:
            raise ConfigurationException("PRESIDIO_PLACEHOLDER must be either 'token' or 'entity'.")
        invalid_entities = sorted(e for e in self.PRESIDIO_IGNORE_ENTITIES if not _ENTITY_NAME.fullmatch(e))
        if invalid_entities:
            raise ConfigurationException(
                f"PRESIDIO_IGNORE_ENTITIES contains invalid entity names: {', '.join(invalid_entities)}"
            )
        if self.PRESIDIO_MAX_CONCURRENCY < 1:
            raise ConfigurationException("PRESIDIO_MAX_CONCURRENCY must be at least 1.")
        if not self.CLIENT_SECRET:
            raise ConfigurationException("CLIENT_SECRET environment variable must be set and non-empty.")

    def get(self, key, default=None):
        return os.environ.get(key, default=default)
