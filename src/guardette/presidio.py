import logging

import httpx

logger = logging.getLogger("guardette")

_shared_client: httpx.AsyncClient | None = None


class PresidioClient:
    def __init__(self, config):
        self._analyzer_url = config.PRESIDIO_ANALYZER_URL.rstrip("/")
        self._anonymizer_url = config.PRESIDIO_ANONYMIZER_URL.rstrip("/")
        self._language = config.PRESIDIO_LANGUAGE
        self._score_threshold = config.PRESIDIO_SCORE_THRESHOLD
        self._ignore_entities = config.PRESIDIO_IGNORE_ENTITIES
        self._replacement = config.REDACT_TOKEN
        # "entity": Presidio's replace default of <ENTITY_TYPE>, distinguishable from regex redactions.
        self._operator = (
            {"type": "replace"}
            if config.PRESIDIO_PLACEHOLDER == "entity"
            else {"type": "replace", "new_value": self._replacement}
        )

    async def analyze(self, http: httpx.AsyncClient, text: str) -> list[dict]:
        resp = await http.post(
            f"{self._analyzer_url}/analyze",
            json={"text": text, "language": self._language, "score_threshold": self._score_threshold},
        )
        resp.raise_for_status()
        return [r for r in resp.json() if r["entity_type"] not in self._ignore_entities]

    async def anonymize(self, http: httpx.AsyncClient, text: str, results: list[dict]) -> str:
        resp = await http.post(
            f"{self._anonymizer_url}/anonymize",
            json={
                "text": text,
                "anonymizers": {"DEFAULT": self._operator},
                "analyzer_results": [
                    {"entity_type": r["entity_type"], "start": r["start"], "end": r["end"], "score": r["score"]}
                    for r in results
                ],
            },
        )
        resp.raise_for_status()
        return resp.json()["text"]

    async def anonymize_text(self, http: httpx.AsyncClient, text: str, *, fail_closed: bool, on_outcome=None) -> str:
        if not isinstance(text, str) or not text.strip():
            return text
        try:
            results = await self.analyze(http, text)
            anonymized = await self.anonymize(http, text, results)  # empty results is a safe no-op
        except Exception:
            logger.warning("presidio anonymize_text failed", extra={"fail_closed": fail_closed})
            if on_outcome is not None:
                on_outcome("failure" if fail_closed else "fail_open_passthrough")
            return self._replacement if fail_closed else text
        if on_outcome is not None:
            on_outcome("success")
        return anonymized


def get_shared_client(config) -> httpx.AsyncClient:
    global _shared_client  # noqa: PLW0603
    if _shared_client is None or _shared_client.is_closed:
        _shared_client = httpx.AsyncClient(
            timeout=config.PRESIDIO_TIMEOUT_SECS,
            limits=httpx.Limits(max_connections=config.PRESIDIO_MAX_CONCURRENCY),
        )
    return _shared_client


async def aclose_shared_client() -> None:
    global _shared_client  # noqa: PLW0603
    if _shared_client is not None and not _shared_client.is_closed:
        await _shared_client.aclose()
    _shared_client = None


async def presidio_ready(config, *, timeout_secs: float = 2.0) -> bool:
    http = get_shared_client(config)
    for name, url in (("analyzer", config.PRESIDIO_ANALYZER_URL), ("anonymizer", config.PRESIDIO_ANONYMIZER_URL)):
        try:
            (await http.get(f"{url}/health", timeout=timeout_secs)).raise_for_status()
        except httpx.HTTPError:
            logger.warning("presidio %s health check failed", name)
            return False
    return True
