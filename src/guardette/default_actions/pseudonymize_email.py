import base64
import hashlib
import hmac
from typing import Protocol

from guardette.actions import Action, ActionContext, action_registry
from guardette.config import ConfigManager
from guardette.exceptions import ConfigurationException

_HMAC_KEY_MIN_BYTES = hashlib.sha256().digest_size


class _EmailDigestStrategy(Protocol):
    def digest(self, part: str, value: str) -> bytes:
        raise NotImplementedError


class _LegacySaltedSha256:
    def __init__(self, secret: str):
        self.secret = secret.encode()

    def digest(self, part: str, value: str) -> bytes:  # noqa: ARG002
        return hashlib.sha256(value.encode() + self.secret).digest()


class _HmacSha256:
    def __init__(self, key: str):
        self.key = key.encode()
        if len(self.key) < _HMAC_KEY_MIN_BYTES:
            raise ConfigurationException("HMAC_KEY must contain at least 32 bytes.")

    def digest(self, part: str, value: str) -> bytes:
        message = f"guardette:pseudonymize_email:v1:{part}:{value}".encode()
        return hmac.new(self.key, message, hashlib.sha256).digest()


def _create_digest_strategy(config: ConfigManager, secret: str) -> _EmailDigestStrategy:
    if config.PSEUDONYMIZE_ALGORITHM == "hmac-sha256":
        return _HmacSha256(secret)
    if config.PSEUDONYMIZE_ALGORITHM == "sha256":
        return _LegacySaltedSha256(secret)
    raise ConfigurationException(f"Unsupported pseudonymization algorithm: {config.PSEUDONYMIZE_ALGORITHM}")


@action_registry.register("pseudonymize_email")
class PseudonymizeEmail(Action):
    json_paths: list[str]

    @classmethod
    def validate_config(cls, config: ConfigManager):
        if config.PSEUDONYMIZE_ALGORITHM == "hmac-sha256" and not config.HMAC_KEY:
            raise ConfigurationException(
                "HMAC_KEY environment variable must be set and non-empty when PSEUDONYMIZE_ALGORITHM is hmac-sha256."
            )
        if config.PSEUDONYMIZE_ALGORITHM == "sha256" and not config.PSEUDONYMIZE_SALT:
            raise ConfigurationException(
                "PSEUDONYMIZE_SALT environment variable must be set and non-empty when "
                "PSEUDONYMIZE_ALGORITHM is sha256."
            )

    async def response(self, ctx: ActionContext):
        secret_name = "HMAC_KEY" if ctx.config.PSEUDONYMIZE_ALGORITHM == "hmac-sha256" else "PSEUDONYMIZE_SALT"
        secret = await ctx.secrets.get(secret_name)
        digest_strategy = _create_digest_strategy(ctx.config, secret)

        def updater(email, _data, _k):
            if not isinstance(email, str):
                return email

            try:
                username, domain = email.lower().split("@")
            except ValueError:
                return email

            if domain in ctx.config.PSEUDONYMIZE_EMAIL_DOMAINS_ALLOWLIST:
                return email

            username_hash = base64.b32encode(digest_strategy.digest("local", username)).decode().rstrip("=")
            domain_hash = base64.b32encode(digest_strategy.digest("domain", domain)).decode().rstrip("=")
            return f"u-{username_hash}@d-{domain_hash}.invalid".lower()

        for path in self.json_paths:
            ctx.update_json_path(ctx.response.json_data, path, updater)
