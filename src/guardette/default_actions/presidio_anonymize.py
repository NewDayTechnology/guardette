import asyncio
import logging
from collections import Counter

from pydantic import ConfigDict, Field, model_validator

from guardette.actions import Action, ActionContext, action_registry, collect_text_nodes
from guardette.presidio import PresidioClient, get_shared_client

logger = logging.getLogger("guardette")


@action_registry.register("presidio_anonymize")
class PresidioAnonymize(Action):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    json_paths: list[str] = Field(default_factory=list)
    adf_paths: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _require_targets(self):
        if not self.json_paths and not self.adf_paths:
            raise ValueError("presidio_anonymize requires at least one of json_paths or adf_paths")
        return self

    async def response(self, ctx: ActionContext):
        client = PresidioClient(ctx.config)
        http = get_shared_client(ctx.config)
        sem = asyncio.Semaphore(ctx.config.PRESIDIO_MAX_CONCURRENCY)
        fail_closed = ctx.config.PRESIDIO_FAIL_MODE == "closed"

        outcomes: Counter[str] = Counter()

        def record(outcome):
            outcomes[outcome] += 1
            if ctx.metrics is not None:
                ctx.metrics.record_presidio(outcome)

        async def run(text):
            async with sem:
                return await client.anonymize_text(http, text, fail_closed=fail_closed, on_outcome=record)

        for path in self.json_paths:

            async def batch(values, _run=run):
                return await asyncio.gather(*(_run(v) for v in values))

            await ctx.update_json_path_async(ctx.response.json_data, path, batch)

        for path in self.adf_paths:
            await _anonymize_adf_fields(ctx, path, client, http, sem, fail_closed, record)

        if outcomes:
            logger.debug("presidio_anonymize processed fields", extra={"outcomes": dict(outcomes)})


async def _anonymize_adf_fields(ctx, path, client, http, sem, fail_closed, record):  # noqa: PLR0917
    expr = ctx.get_json_path_expr(path)
    containers = [m.value for m in expr.find(ctx.response.json_data)]
    for container in containers:
        nodes = collect_text_nodes(container)
        if not nodes:
            continue

        # Reconstruct the field's text and record each node's window in the join.
        parts, spans, cursor = [], [], 0
        for node in nodes:
            text = node["text"]
            spans.append((cursor, cursor + len(text)))
            parts.append(text)
            cursor += len(text) + 1  # +1 for the single-space separator
        full = " ".join(parts)

        try:
            async with sem:
                results = await client.analyze(http, full)
        except Exception:
            outcome = "failure" if fail_closed else "fail_open_passthrough"
            for node in nodes:
                if not node["text"].strip():
                    continue
                if fail_closed:
                    node["text"] = ctx.config.REDACT_TOKEN
                record(outcome)
            continue  # fail-open: leave the field untouched

        async def anon_node(node, window, _results=results):
            if not node["text"].strip():
                return
            ns, ne = window
            local = [
                {
                    "entity_type": r["entity_type"],
                    "start": max(r["start"], ns) - ns,
                    "end": min(r["end"], ne) - ns,
                    "score": r["score"],
                }
                for r in _results
                if r["start"] < ne and r["end"] > ns
            ]
            async with sem:
                try:
                    node["text"] = await client.anonymize(http, node["text"], local)
                except Exception:
                    if fail_closed:
                        node["text"] = ctx.config.REDACT_TOKEN
                        record("failure")
                    else:
                        record("fail_open_passthrough")
                else:
                    record("success")

        await asyncio.gather(*(anon_node(n, w) for n, w in zip(nodes, spans, strict=True)))
