import os

from guardette.exceptions import ConfigurationException

_PSEUDONYMIZE_ALGORITHMS = frozenset({"sha256", "hmac-sha256"})


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
        self.PSEUDONYMIZE_EMAIL_DOMAINS_ALLOWLIST: tuple[str, ...] = tuple(
            [d.lower() for d in os.environ.get("PSEUDONYMIZE_EMAIL_DOMAINS_ALLOWLIST", "").split(",") if d]
        )

        if self.PSEUDONYMIZE_ALGORITHM not in _PSEUDONYMIZE_ALGORITHMS:
            raise ConfigurationException(
                "PSEUDONYMIZE_ALGORITHM must be one of: " + ", ".join(sorted(_PSEUDONYMIZE_ALGORITHMS))
            )
        if not self.CLIENT_SECRET:
            raise ConfigurationException("CLIENT_SECRET environment variable must be set and non-empty.")

    def get(self, key, default=None):
        return os.environ.get(key, default=default)
