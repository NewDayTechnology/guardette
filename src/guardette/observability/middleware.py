import time
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from guardette.constants import PROXY_REQUEST_ID_HEADER
from guardette.observability.events import Observability
from guardette.observability.headers import sanitize_headers


class ObservabilityMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: Callable[..., Awaitable[Any]], observability: Observability):
        super().__init__(app)
        self.observability = observability

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        request_id = str(uuid.uuid4())
        request.state.correlation_id = request_id
        started_at = time.perf_counter()

        try:
            response = await call_next(request)
        except Exception as exc:
            duration_seconds = time.perf_counter() - started_at
            self._record_request(request, request_id, 500, duration_seconds, type(exc).__name__)
            raise

        duration_seconds = time.perf_counter() - started_at
        response.headers[PROXY_REQUEST_ID_HEADER] = request_id
        self._record_request(request, request_id, response.status_code, duration_seconds, response=response)
        return response

    def _record_request(  # noqa: PLR0917
        self,
        request: Request,
        request_id: str,
        status_code: int,
        duration_seconds: float,
        error_class: str | None = None,
        response: Response | None = None,
    ) -> None:
        if self.observability.config.request_logging_active:
            fields = {
                "request_id": request_id,
                "method": request.method,
                "route": _normalized_route(request),
                "status_code": status_code,
                "status_class": f"{status_code // 100}xx",
                "duration_ms": round(duration_seconds * 1000, 3),
                "headers": {
                    "request": sanitize_headers(request.headers, request_id=request_id),
                    "response": sanitize_headers(response.headers) if response is not None else {},
                },
            }
            if error_class is not None:
                fields["error_class"] = error_class
            self.observability.events.emit("guardette.request.completed", fields)

        self.observability.metrics.record_request(request.method, status_code, duration_seconds)


def _normalized_route(request: Request) -> str:
    route = request.scope.get("route")
    route_path = getattr(route, "path", None)
    if isinstance(route_path, str):
        return route_path
    return "unmatched"
