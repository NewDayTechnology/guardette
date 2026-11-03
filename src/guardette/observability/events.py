import logging
from dataclasses import dataclass, field
from typing import Any

from guardette.observability.config import ObservabilityConfig


class EventLogger:
    def __init__(self, config: ObservabilityConfig):
        self._config = config
        self._logger = logging.getLogger("guardette")

    def emit(self, event_name: str, fields: dict[str, Any]) -> None:
        if not self._config.active:
            return

        event = {
            "event": event_name,
            "service": self._config.service_name,
            "environment": self._config.environment,
            "version": self._config.version,
            **fields,
        }
        self._logger.info(event_name, extra={"observability_event": event})


class MetricsRecorder:
    def __init__(self, config: ObservabilityConfig, event_logger: EventLogger):
        self._config = config
        self._event_logger = event_logger

    def record_request(self, method: str, status_code: int, duration_seconds: float) -> None:
        if not self._config.metrics_active:
            return

        status_class = f"{status_code // 100}xx"
        self._record(
            "guardette_requests_total",
            1,
            {"method": method, "status_class": status_class},
        )
        self._record(
            "guardette_request_duration_seconds",
            duration_seconds,
            {"method": method, "status_class": status_class},
        )

    def record_upstream(self, outcome: str, status_code: int | None) -> None:
        if not self._config.metrics_active:
            return

        status_class = f"{status_code // 100}xx" if status_code is not None else "none"
        self._record(
            "guardette_upstream_requests_total",
            1,
            {"outcome": outcome, "status_class": status_class},
        )

    def record_auth_failure(self, failure_class: str) -> None:
        if not self._config.metrics_active:
            return

        self._record("guardette_auth_failures_total", 1, {"failure_class": failure_class})

    def record_presidio(self, outcome: str) -> None:
        if not self._config.metrics_active:
            return

        self._record("guardette_presidio_requests_total", 1, {"outcome": outcome})

    def _record(self, metric: str, value: float, attributes: dict[str, str]) -> None:
        self._event_logger.emit(
            "guardette.metric",
            {
                "metric": metric,
                "value": value,
                **attributes,
            },
        )


@dataclass(slots=True)
class Observability:
    config: ObservabilityConfig
    events: EventLogger = field(init=False)
    metrics: MetricsRecorder = field(init=False)

    def __post_init__(self) -> None:
        self.events = EventLogger(self.config)
        self.metrics = MetricsRecorder(self.config, self.events)
