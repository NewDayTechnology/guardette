import functools
import logging
import time
import uuid
from secrets import compare_digest

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.datastructures import URL, MutableHeaders

from guardette.actions import ActionContext, action_registry
from guardette.auth import AuthHandlerRegistry, auth_registry
from guardette.config import ConfigManager
from guardette.constants import PROXY_ERROR_HEADER, PROXY_HOST_HEADER
from guardette.datastructures import ProxyRequest, ProxyResponse
from guardette.exceptions import (
    AuthException,
    ConfigurationException,
    GuardetteException,
    HttpMethodNotSupportedException,
    MatchNotFoundException,
    ProxyClientTimeoutException,
    TransformationException,
)
from guardette.matching import Matcher, SourceMatcherResult
from guardette.observability import configure_observability
from guardette.policy import Policy
from guardette.secrets import (
    AwsSecretsManager,
    ConfigSecretsManager,
    SecretManagerType,
    SecretsManager,
)
from guardette.utils import copy_signature
from guardette.version import VERSION

STRIP_REQUEST_HEADERS = {
    PROXY_HOST_HEADER.lower(),
    "authorization",
    "host",
    "connection",
    "content-length",
    "transfer-encoding",
    "accept-encoding",
}

STRIP_RESPONSE_HEADERS = {
    "connection",
    "content-length",
    "content-encoding",
    "transfer-encoding",
}


logger = logging.getLogger("guardette")


_EXCEPTION_RESPONSES: dict[type[GuardetteException], tuple[int, str, str]] = {
    # exception class -> (status_code, response_message, log_message)
    AuthException: (401, "Unauthorized", "Authentication failed"),
    MatchNotFoundException: (404, "Not Found", "No matching route found"),
}


def _make_error_response(correlation_id: str, status_code: int, message: str, **extra_content) -> JSONResponse:
    content = {
        "message": message,
        "source": "proxy",
        "correlation_id": correlation_id,
        **extra_content,
    }
    return JSONResponse(
        status_code=status_code,
        content={"error": content},
        headers={PROXY_ERROR_HEADER: "proxy"},
    )


def guardette_route():
    def wrapper(func):
        @functools.wraps(func)
        async def wrapped(*args, **kwargs):
            request: Request = kwargs.get("request") or args[0]
            correlation_id = getattr(request.state, "correlation_id", None) or str(uuid.uuid4())
            request.state.correlation_id = correlation_id
            start_time = time.time()

            try:
                response = await func(*args, **kwargs)
            except GuardetteException as ge:
                elapsed_time = time.time() - start_time
                status_code, message, log_message = _EXCEPTION_RESPONSES.get(
                    type(ge), (500, "Internal Server Error", "GuardetteException encountered")
                )
                log_func = logger.warning if status_code < 500 else logger.error
                if isinstance(ge, AuthException):
                    _record_auth_failure(request)
                log_func(
                    log_message,
                    exc_info=status_code >= 500,
                    extra={
                        "correlation_id": correlation_id,
                        "error_class": type(ge).__name__,
                        "elapsed_time": f"{elapsed_time:.3f}s",
                    },
                )
                return _make_error_response(correlation_id, status_code, message)
            except Exception as exc:
                elapsed_time = time.time() - start_time
                logger.error(
                    "Unexpected error occurred",
                    exc_info=True,
                    extra={
                        "correlation_id": correlation_id,
                        "error_class": type(exc).__name__,
                        "elapsed_time": f"{elapsed_time:.3f}s",
                    },
                )
                return _make_error_response(
                    correlation_id,
                    500,
                    "Internal Server Error",
                    details="An unexpected error occurred.",
                )
            return response

        return wrapped

    return wrapper


class Guardette:
    def __init__(self, policy_path: str):
        self.actions = action_registry
        self.auth = auth_registry
        self.policy = Policy.from_file(policy_path)
        self.config = ConfigManager()

        for source in self.policy.sources:
            for rule in source.rules:
                for action in rule.actions:
                    action.validate_config(self.config)

        logger.info(
            "Guardette policy loaded",
            extra={
                "source_count": len(self.policy.sources),
                "rule_count": sum(len(source.rules) for source in self.policy.sources),
            },
        )

        conf_secret_manager = self.config.SECRET_MANAGER
        if conf_secret_manager == SecretManagerType.DEFAULT:
            self.secrets: SecretsManager = ConfigSecretsManager(self.config)
        elif conf_secret_manager == SecretManagerType.AWS_SECRET_MANAGER:
            self.secrets: SecretsManager = AwsSecretsManager(self.config)
        else:
            raise ConfigurationException("Invalid secret manager option: " + conf_secret_manager)

    @property
    def policy(self):
        return self._policy

    @policy.setter
    def policy(self, value):
        self._policy = value
        self._matcher = Matcher(self._policy)

    @property
    def matcher(self):
        return self._matcher

    async def _validate_client_secret(self, request: Request):
        req_client_secret = request.headers.get("authorization")
        if not req_client_secret:
            raise AuthException("Missing authorization header.")

        client_secret = await self.secrets.get("CLIENT_SECRET", correlation_id=request.state.correlation_id)

        if not compare_digest(req_client_secret, client_secret):
            raise AuthException("Invalid authorization header.")

    @guardette_route()
    async def _meta_route(self, request: Request):
        await self._validate_client_secret(request)

        return JSONResponse(
            content={
                "version": VERSION,
                "policy": self.policy.model_dump(),
            },
            status_code=200,
        )

    @guardette_route()
    async def _proxy_route(self, request: Request):  # noqa: PLR0912
        await self._validate_client_secret(request)

        target_host = request.headers.get(PROXY_HOST_HEADER)
        if not target_host:
            raise GuardetteException(f"{PROXY_HOST_HEADER} header is missing.")

        match = self.matcher.match(request, target_host=target_host)
        if match is None:
            raise MatchNotFoundException("Match not found.")

        proxy_transformer = ProxyTransformer(
            auth=self.auth,
            config=self.config,
            secrets=self.secrets,
            match=match,
        )
        try:
            proxy_request = await proxy_transformer.transform_request(request)
        except Exception as e:
            raise TransformationException(f"Error transforming request: {e!s}") from e

        client_timeout: int = self.config.PROXY_CLIENT_TIMEOUT_SECS
        async with httpx.AsyncClient(timeout=client_timeout) as client:
            try:
                if request.method == "GET":
                    response = await client.get(
                        proxy_request.url,
                        headers=proxy_request.headers,
                    )
                elif request.method == "POST":
                    response = await client.post(
                        proxy_request.url,
                        headers=proxy_request.headers,
                        data=proxy_request.json_data,
                    )
                elif request.method == "PUT":
                    response = await client.put(
                        proxy_request.url,
                        headers=proxy_request.headers,
                        data=proxy_request.json_data,
                    )
                elif request.method == "PATCH":
                    response = await client.patch(
                        proxy_request.url,
                        headers=proxy_request.headers,
                        data=proxy_request.json_data,
                    )
                elif request.method == "DELETE":
                    response = await client.delete(
                        proxy_request.url,
                        headers=proxy_request.headers,
                    )
                elif request.method == "HEAD":
                    response = await client.head(
                        proxy_request.url,
                        headers=proxy_request.headers,
                    )
                elif request.method == "OPTIONS":
                    response = await client.options(
                        proxy_request.url,
                        headers=proxy_request.headers,
                    )
                else:
                    raise HttpMethodNotSupportedException(f"Unexpected http method: {request.method}")
            except httpx.TimeoutException as e:
                _record_upstream(request, "timeout", None)
                raise ProxyClientTimeoutException(f"Request timed out: {e!s}") from e
            except httpx.HTTPError:
                _record_upstream(request, "error", None)
                raise
            else:
                outcome = "success" if response.status_code < 500 else "error"
                _record_upstream(request, outcome, response.status_code)

        try:
            proxy_response = await proxy_transformer.transform_response(request, response)
        except Exception as e:
            raise TransformationException(f"Error transforming response: {e!s}") from e

        return JSONResponse(
            content=proxy_response.json_data,
            status_code=proxy_response.status_code,
            headers=dict(proxy_response.headers),
        )

    @copy_signature(action_registry.register)
    def action(self, *args, **kwargs):
        return self.actions.register(*args, **kwargs)

    @copy_signature(auth_registry.register)
    def auth_handler(self, *args, **kwargs):
        return self.auth.register(*args, **kwargs)

    def to_fastapi(self, app: FastAPI):
        configure_observability(app)
        app.api_route("/_guardette/meta", methods=["GET"])(self._meta_route)
        app.api_route(
            "/{path:path}",
            methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"],
        )(self._proxy_route)


def _record_auth_failure(request: Request) -> None:
    observability = getattr(request.app.state, "observability", None)
    if observability is not None:
        observability.metrics.record_auth_failure("client")


def _record_upstream(request: Request, outcome: str, status_code: int | None) -> None:
    observability = getattr(request.app.state, "observability", None)
    if observability is not None:
        observability.metrics.record_upstream(outcome, status_code)


class ProxyTransformer:
    def __init__(
        self,
        *,
        auth: AuthHandlerRegistry,
        config: ConfigManager,
        secrets: SecretsManager,
        match: SourceMatcherResult,
    ):
        self.auth = auth
        self.config = config
        self.secrets = secrets
        self.target = match["target"]
        self.rule = match["rule"]
        self.path_params = match["path_params"]
        self._proxy_request: ProxyRequest | None = None

    async def transform_request(self, in_request: Request) -> ProxyRequest:
        correlation_id = in_request.state.correlation_id
        url = str(
            URL(
                scheme="https",
                hostname=self.target.host,  # Your new hostname
                path=in_request.url.path,
                query=in_request.url.query,
                fragment=in_request.url.fragment,
            ),
        )

        headers = MutableHeaders(
            {k: v for k, v in in_request.headers.items() if k.lower() not in STRIP_REQUEST_HEADERS},
        )
        body = await in_request.body()
        if body:
            json_data = await in_request.json()
        else:
            json_data = None

        self._proxy_request = ProxyRequest(
            url=url,
            headers=headers,
            json_data=json_data,
        )
        if self.target.auth:
            logger.debug(f"Using target auth handler: {self.target.auth}", extra={"correlation_id": correlation_id})
            await self.auth(
                self.target.auth,
                request=self._proxy_request,
                secrets=self.secrets,
                config=self.config,
            )

        ctx = ActionContext(
            config=self.config,
            secrets=self.secrets,
            request=self._proxy_request,
            response=ProxyResponse(
                status_code=0,
                headers=MutableHeaders(),
                json_data=None,
            ),
        )
        logger.debug(
            "Transforming request",
            extra={
                "correlation_id": correlation_id,
                "actions": [action.__class__.__name__ for action in self.rule.actions],
            },
        )
        for action in self.rule.actions:
            await action.request(ctx)
        return self._proxy_request

    async def transform_response(self, in_request: Request, in_response: httpx.Response) -> ProxyResponse:
        correlation_id = in_request.state.correlation_id

        if self._proxy_request is None:
            raise TransformationException(
                "Cannot call transform_response() without first calling transform_request()",
            )
        status_code = in_response.status_code
        headers = MutableHeaders(
            {k: v for k, v in in_response.headers.items() if k.lower() not in STRIP_RESPONSE_HEADERS},
        )
        try:
            json_data = in_response.json()
        except Exception as e:
            raise TransformationException("Upstream returned non-JSON response") from e
        ctx = ActionContext(
            config=self.config,
            secrets=self.secrets,
            request=self._proxy_request,
            response=ProxyResponse(
                status_code=status_code,
                headers=headers,
                json_data=json_data,
            ),
        )
        logger.debug(
            "Transforming response",
            extra={
                "correlation_id": correlation_id,
                "actions": [action.__class__.__name__ for action in self.rule.actions],
            },
        )
        for action in self.rule.actions:
            await action.response(ctx)
        return ctx.response
