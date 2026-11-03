import asyncio
import json
import os

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from guardette import Guardette
from guardette.config import ConfigManager
from guardette.constants import PROXY_HOST_HEADER
from guardette.presidio import PresidioClient

pytestmark = pytest.mark.skipif(
    os.environ.get("PRESIDIO_INTEGRATION") != "1",
    reason="Set PRESIDIO_INTEGRATION=1 with the Presidio containers running and network access to run.",
)

HN_HOST = "hacker-news.firebaseio.com"
HN_ITEM = 8863  # immutable classic 'Dropbox' story whose `url` field is a bare URL
HN_HEADLINE_COUNT = 10

POLICY = """version: "1"
sources:
  - host: hacker-news.firebaseio.com
    rules:
      - route: "GET /v0/item/{itemId}"
        actions:
          - kind: presidio_anonymize
            json_paths:
              - $.url
              - $.title
              - $.text
"""


def _require_reachable(url):
    try:
        httpx.get(url, timeout=10).raise_for_status()
    except Exception as exc:
        pytest.skip(f"precondition not reachable: {url} ({exc})")


@pytest.fixture
def hn_app(tmp_path, monkeypatch):
    monkeypatch.setenv("CLIENT_SECRET", "test")
    config = ConfigManager()
    _require_reachable(f"{config.PRESIDIO_ANALYZER_URL}/health")
    _require_reachable(f"{config.PRESIDIO_ANONYMIZER_URL}/health")
    _require_reachable(f"https://{HN_HOST}/v0/item/{HN_ITEM}.json")

    policy_path = tmp_path / "hn_policy.yml"
    policy_path.write_text(POLICY)
    app = FastAPI()
    Guardette(policy_path=str(policy_path)).to_fastapi(app)
    return app


def test_presidio_anonymizes_live_hacker_news_item(hn_app):
    raw = httpx.get(f"https://{HN_HOST}/v0/item/{HN_ITEM}.json", timeout=10).json()
    assert raw.get("url"), "test item is expected to carry a url field"

    client = TestClient(hn_app)
    resp = client.get(
        f"/v0/item/{HN_ITEM}.json",
        headers={PROXY_HOST_HEADER: HN_HOST, "Authorization": "test"},
    )

    assert resp.status_code == 200
    out = resp.json()

    # Presidio's URL recogniser detects the bare URL; the anonymiser replaces it.
    assert out["url"] != raw["url"]
    assert "getdropbox.com" not in out["url"]
    # Untargeted structural fields are forwarded unchanged.
    assert out["id"] == raw["id"]
    assert out["by"] == raw["by"]


def test_analyze_and_anonymize_top_hacker_news_headline(monkeypatch):
    monkeypatch.setenv("CLIENT_SECRET", "test")
    config = ConfigManager()
    _require_reachable(f"{config.PRESIDIO_ANALYZER_URL}/health")
    _require_reachable(f"{config.PRESIDIO_ANONYMIZER_URL}/health")

    top_story_ids = httpx.get(f"https://{HN_HOST}/v0/topstories.json", timeout=10).json()
    headlines = []
    for story_id in top_story_ids:
        response = httpx.get(f"https://{HN_HOST}/v0/item/{story_id}.json", timeout=10)
        response.raise_for_status()
        headline = response.json().get("title")
        if headline:
            headlines.append((story_id, headline))
        if len(headlines) == HN_HEADLINE_COUNT:
            break
    assert len(headlines) == HN_HEADLINE_COUNT

    presidio = PresidioClient(config)

    async def analyze_then_anonymize():
        processed = []
        async with httpx.AsyncClient(timeout=config.PRESIDIO_TIMEOUT_SECS) as client:
            for story_id, headline in headlines:
                results = await presidio.analyze(client, headline)
                anonymized = await presidio.anonymize(client, headline, results)
                processed.append((story_id, headline, results, anonymized))
        return processed

    print(f"\nProcessed {len(headlines)} Hacker News top-story headlines through Presidio:")  # noqa: T201
    for story_id, headline, results, anonymized in asyncio.run(analyze_then_anonymize()):
        print(f"\nHN headline (item {story_id}): {headline}")  # noqa: T201
        print("Analyzer found:")  # noqa: T201
        print(json.dumps(results, indent=2))  # noqa: T201
        print("Anonymized:")  # noqa: T201
        print(anonymized)  # noqa: T201
        assert isinstance(anonymized, str)
        if results:
            assert anonymized != headline
        else:
            assert anonymized == headline
