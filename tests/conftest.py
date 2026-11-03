import importlib.util
import os
from pathlib import Path

import pytest
import yaml
from starlette.datastructures import MutableHeaders

from guardette.actions import ActionContext
from guardette.config import ConfigManager
from guardette.datastructures import ProxyRequest, ProxyResponse
from guardette.secrets import ConfigSecretsManager

_POLICYGEN = Path(__file__).resolve().parent.parent / "scripts" / "policygen" / "policygen.py"


def pytest_configure(config):
    os.environ.setdefault("CLIENT_SECRET", "test")


@pytest.fixture(scope="session")
def render_policy():
    """Render one policygen source template to a policy dict, as policygen would write it."""
    spec = importlib.util.spec_from_file_location("policygen", _POLICYGEN)
    policygen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(policygen)

    def render(kind, **config):
        return yaml.safe_load(policygen.generate(policygen.Config(sources=[{"kind": kind, "config": config}])))

    return render


@pytest.fixture
def action_context():
    config = ConfigManager()
    secrets = ConfigSecretsManager(config)
    request = ProxyRequest(url="http://test.com", headers=MutableHeaders({}), json_data={})
    response = ProxyResponse(status_code=200, headers=MutableHeaders({}), json_data={})
    return ActionContext(config=config, secrets=secrets, request=request, response=response)


@pytest.fixture
def anyio_backend():
    return "asyncio"
