from dataclasses import dataclass
from typing import TYPE_CHECKING

from jsonpath_ng.ext import parse
from pydantic import BaseModel

from guardette.config import ConfigManager
from guardette.datastructures import ProxyRequest, ProxyResponse
from guardette.secrets import SecretsManager

if TYPE_CHECKING:
    from guardette.observability.events import MetricsRecorder

_json_path_cache = {}


@dataclass
class ActionContext:
    config: ConfigManager
    secrets: SecretsManager
    request: ProxyRequest
    response: ProxyResponse
    metrics: "MetricsRecorder | None" = None

    def get_json_path_expr(self, path):
        expr = _json_path_cache.get(path)
        if expr is None:
            expr = _json_path_cache[path] = parse(path)
        return expr

    def update_json_path(self, data, path, updater):
        expr = self.get_json_path_expr(path)
        expr.update(data, updater)

    def filter_json_path(self, data, path, filter_fn):
        expr = self.get_json_path_expr(path)
        expr.filter(filter_fn, data)

    async def update_json_path_async(self, data, path, async_updater):
        expr = self.get_json_path_expr(path)
        matches = expr.find(data)
        if not matches:
            return
        new_values = await async_updater([m.value for m in matches])
        for match, new_value in zip(matches, new_values, strict=True):
            match.full_path.update(data, new_value)


def collect_text_nodes(node, out=None):
    """Depth-first collect of ADF-style leaf dicts that carry a string `text`."""
    if out is None:
        out = []
    if isinstance(node, dict):
        if isinstance(node.get("text"), str):
            out.append(node)
        for child in node.get("content", []) or []:
            collect_text_nodes(child, out)
    elif isinstance(node, list):
        for child in node:
            collect_text_nodes(child, out)
    return out


class Action(BaseModel):
    @classmethod
    def validate_config(cls, config: ConfigManager):
        pass

    async def request(self, ctx: ActionContext): ...

    async def response(self, ctx: ActionContext): ...


class ActionRegistry:
    def __init__(self):
        self.actions: dict[str, type[Action]] = {}

    def get_action_cls(self, kind: str):
        return self.actions[kind]

    def register(self, kind: str):
        def decorator(action: type[Action]):
            if kind in self.actions:
                raise KeyError(f"Action already exists: '{kind}'")

            self.actions[kind] = action
            return action

        return decorator


action_registry = ActionRegistry()
