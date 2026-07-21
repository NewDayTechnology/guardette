# Product Requirements Document: Guardette Observability

**Product:** Guardette
**Capability:** Observability, telemetry and security enforcement monitoring
**Status:** Draft
**Owner:** Product Security / Platform Engineering
**Target runtime:** Cloudflare Worker and Cloudflare Container
**Application runtime:** Python, FastAPI/Starlette
**Last updated:** 21 July 2026

---

# 1. Executive Summary

Guardette is a security enforcement proxy that sits between external consumers and upstream APIs. It applies configured policies to requests and responses, including field removal, redaction, filtering and pseudonymisation.

Traditional service monitoring based only on availability, HTTP status and latency is insufficient for Guardette. A request returning HTTP 200 must not be treated as successful unless Guardette:

1. selected the intended policy;
2. applied the required transformations;
3. completed those transformations without error;
4. returned only the permitted representation;
5. did not expose sensitive values through logs or telemetry.

This capability will provide structured logs, metrics, traces and security events across the Cloudflare Worker, Cloudflare Container and Guardette application layers.

The implementation will use adapter-based interfaces so observability backends can be replaced or extended without modifying core policy or transformation logic. Each observability concern will be independently feature flagged.

---

# 2. Problem Statement

Guardette currently lacks sufficient visibility into:

* request volume, latency and errors;
* policy loading and policy selection;
* transformation execution;
* how many fields were matched, changed or skipped;
* upstream API performance and failures;
* secret retrieval and authentication failures;
* container readiness and lifecycle;
* policy drift between deployed instances;
* upstream schema changes that cause transformation rules to stop matching;
* accidental sensitive data exposure through logs.

Without this capability, Guardette could appear operational while failing to enforce the intended data protection policy.

Examples include:

* a JSONPath rule no longer matches after an upstream schema change;
* the wrong policy is selected for a route;
* a transformation action silently changes zero fields;
* a container is serving an outdated policy version;
* an upstream authentication mechanism repeatedly fails;
* logging accidentally records response bodies or credentials;
* an upstream service is slow, but the latency is incorrectly attributed to Guardette;
* a successful response is returned after incomplete policy enforcement.

---

# 3. Goals

The observability capability shall:

1. Provide end-to-end correlation across the Cloudflare Worker and Guardette container.
2. Record structured request lifecycle events.
3. Record security enforcement and policy decision events.
4. Measure transformation activity without recording transformed values.
5. Distinguish fields matched, changed and skipped.
6. Measure Guardette-owned latency separately from upstream latency.
7. Detect policy failures, transformation failures and unexpected zero-match conditions.
8. Support multiple telemetry backends through adapters.
9. Allow logging, metrics and tracing to be enabled independently.
10. Prevent sensitive data from entering telemetry.
11. Support service health dashboards and actionable alerts.
12. Introduce minimal latency and operational overhead.
13. Continue operating if the configured telemetry backend is unavailable.

---

# 4. Non-Goals

The initial implementation will not:

* store request or response bodies;
* provide packet capture or full traffic replay;
* expose sensitive fields for debugging;
* replace application audit records required by upstream systems;
* provide a general-purpose SIEM;
* implement automatic policy remediation;
* guarantee exactly-once metric delivery;
* use telemetry as an enforcement dependency;
* perform live dependency checks against every upstream API during readiness probes;
* support arbitrary runtime-loaded Python observability plugins.

---

# 5. Users and Stakeholders

## 5.1 Primary users

### Platform engineers

Need to understand:

* service availability;
* latency;
* container health;
* upstream dependency behaviour;
* deployment failures;
* resource saturation.

### Security engineers

Need to understand:

* which policy was applied;
* whether transformations occurred;
* whether policy enforcement failed;
* whether an unapproved host or route was requested;
* whether security-sensitive configuration drift exists.

### Application engineers

Need to understand:

* which processing stage failed;
* whether an error originated in Guardette or an upstream API;
* how long each processing stage took;
* whether policy rules still match upstream response structures.

### Service owners

Need to understand:

* reliability against agreed service levels;
* upstream dependency health;
* deployment and policy versions serving traffic.

---

# 6. Assumptions

1. Guardette runs as a Python FastAPI/Starlette application inside a Cloudflare Container.
2. A Cloudflare Worker handles the external request and invokes the container.
3. Policies are defined in YAML and loaded when Guardette starts.
4. Policy actions include removal, redaction, filtering and pseudonymisation.
5. Transformation actions use JSONPath expressions to identify target fields.
6. Cloudflare captures container stdout and stderr.
7. Telemetry may later be exported to an external backend such as Grafana Cloud, Honeycomb, Sentry or an OTLP-compatible platform.
8. Guardette may process data containing personal, confidential or security-sensitive information.
9. Production deployments are internet exposed.
10. Telemetry failure must not prevent Guardette from enforcing policy or returning responses.

---

# 7. Design Principles

## 7.1 Security enforcement is observable

Policy evaluation and transformation are first-class operations, not implementation details.

## 7.2 Telemetry records metadata, not protected content

The system records counts, outcomes and timing. It must not record field values or payload content.

## 7.3 Instrument at the point of truth

Transformation counts must be generated by the transformation function itself. They must not be inferred by comparing request and response bodies later.

## 7.4 Backend-independent application code

Guardette core logic calls stable observability interfaces. Backend-specific behaviour remains in adapters.

## 7.5 Failure isolation

Telemetry errors must not cause policy enforcement or proxy requests to fail.

## 7.6 Low cardinality by default

Metric dimensions must be bounded and predictable.

## 7.7 Independent feature control

Request logging, security events, metrics and tracing must be independently configurable.

## 7.8 Secure defaults

Body logging, query-string logging and credential logging must remain disabled and unsupported in production configuration.

---

# 8. Proposed Architecture

```text
External consumer
        |
        v
Cloudflare Worker
        |
        | request ID
        | W3C trace context
        | Cloudflare Ray ID
        v
Cloudflare Container
        |
        v
FastAPI observability middleware
        |
        v
Guardette policy engine
        |
        +---- Policy selection
        |
        +---- Authentication and secret retrieval
        |
        +---- Upstream API request
        |
        +---- Transformation actions
        |
        v
Permitted response
```

Observability components:

```text
Guardette application
    |
    +-- RequestLogger
    +-- MetricsRecorder
    +-- SecurityEventSink
    +-- TraceProvider
              |
              v
        Adapter implementations
              |
              +-- No-op adapter
              +-- Structured stdout adapter
              +-- OpenTelemetry adapter
              +-- Future backend-specific adapters
```

---

# 9. Package Structure

The implementation should use a dedicated Python package:

```text
src/guardette/
├── observability/
│   ├── __init__.py
│   ├── config.py
│   ├── events.py
│   ├── factory.py
│   ├── middleware.py
│   ├── request_logging.py
│   ├── metrics.py
│   ├── security_events.py
│   ├── tracing.py
│   ├── sanitisation.py
│   └── adapters/
│       ├── __init__.py
│       ├── noop.py
│       ├── stdout.py
│       ├── otlp.py
│       └── composite.py
```

Core policy and action modules must depend only on observability interfaces, not concrete adapters.

---

# 10. Functional Requirements

## 10.1 Configuration

The service shall support environment-based observability configuration.

Minimum configuration:

```text
OBS_ENABLED=true
OBS_PROVIDER=stdout

OBS_REQUEST_LOGGING_ENABLED=true
OBS_SECURITY_EVENTS_ENABLED=true
OBS_METRICS_ENABLED=true
OBS_TRACING_ENABLED=false

OBS_TRACE_SAMPLE_RATE=0.10
OBS_SUCCESS_LOG_SAMPLE_RATE=1.00
OBS_INCLUDE_POLICY_VERSION=true
OBS_INCLUDE_CF_RAY=true
```

The following settings must default to false and must not be enabled in production:

```text
OBS_LOG_REQUEST_BODY=false
OBS_LOG_RESPONSE_BODY=false
OBS_LOG_HEADERS=false
OBS_LOG_QUERY_STRING=false
```

The implementation should reject unsafe production configuration where practical.

Example:

```text
ENVIRONMENT=production
OBS_LOG_RESPONSE_BODY=true
```

should cause startup validation to fail.

---

## 10.2 Feature flags

The following controls must operate independently:

| Capability                     | Flag                          |
| ------------------------------ | ----------------------------- |
| Entire observability subsystem | `OBS_ENABLED`                 |
| Request lifecycle logging      | `OBS_REQUEST_LOGGING_ENABLED` |
| Security events                | `OBS_SECURITY_EVENTS_ENABLED` |
| Metrics                        | `OBS_METRICS_ENABLED`         |
| Distributed tracing            | `OBS_TRACING_ENABLED`         |

Disabling request logs must not disable metrics or security events.

Security events should remain enabled by default in production.

---

## 10.3 Adapter factory

A factory function shall select adapters from configuration.

```python
def create_observability(
    config: ObservabilityConfig,
) -> Observability:
    ...
```

The factory shall construct:

* request logger;
* metrics recorder;
* security event sink;
* trace provider.

When a capability is disabled, the factory shall provide a no-op implementation.

Core execution paths must not repeatedly check global feature flags.

---

## 10.4 Correlation identifiers

The Cloudflare Worker shall create or accept a request identifier.

The following identifiers shall be propagated:

* `x-guardette-request-id`;
* `traceparent`;
* `tracestate`, where present;
* `cf-ray`.

The application shall return `x-guardette-request-id` in the response.

Request identifiers must be opaque and must not encode:

* account IDs;
* user IDs;
* tenant names;
* policy names;
* upstream resource identifiers.

---

## 10.5 Request lifecycle logging

The FastAPI middleware shall emit structured events for:

* request started, optionally sampled;
* request completed;
* request failed;
* request rejected;
* request timed out.

Minimum completed-request fields:

```json
{
  "event": "guardette.request.completed",
  "request_id": "opaque-id",
  "trace_id": "trace-id",
  "cf_ray": "cloudflare-ray",
  "method": "GET",
  "route": "/rest/api/3/issue/{issueId}",
  "status_code": 200,
  "duration_ms": 487.2,
  "guardette_duration_ms": 21.4,
  "upstream_duration_ms": 465.8,
  "environment": "production",
  "service_version": "git-sha",
  "policy_version": "sha256:..."
}
```

The route must be a normalised route template rather than the raw path.

The query string must not be recorded.

---

## 10.6 Policy lifecycle events

The service shall emit events for:

* policy loading started;
* policy loaded;
* policy validation failed;
* policy reload started, if reload is supported;
* policy reload completed;
* policy reload failed;
* policy version activated.

Example:

```json
{
  "event": "guardette.policy.loaded",
  "policy_version": "sha256:...",
  "source_count": 4,
  "route_count": 27,
  "action_count": 83,
  "validation_status": "valid",
  "service_version": "git-sha"
}
```

The policy version shall be derived from a cryptographic hash of canonicalised policy content.

Policy file contents must not be emitted.

A container must not report readiness if the policy cannot be loaded or validated.

---

## 10.7 Policy decision events

For each proxied request, Guardette shall record:

* whether a matching policy was found;
* the normalised route;
* source or upstream class;
* policy version;
* decision outcome;
* configured action types;
* number of actions selected;
* policy evaluation duration.

Example:

```json
{
  "event": "guardette.policy.decision",
  "request_id": "opaque-id",
  "source_kind": "jira",
  "route": "GET /rest/api/3/issue/{issueId}",
  "decision": "allow",
  "policy_version": "sha256:...",
  "action_kinds": [
    "remove",
    "redact"
  ],
  "action_count": 2,
  "duration_ms": 1.8
}
```

Policy names must not contain customer-identifying information.

---

## 10.8 Transformation result model

Transformation functions shall return structured counts.

```python
@dataclass(frozen=True, slots=True)
class TransformationResult:
    matched: int = 0
    changed: int = 0
    skipped: int = 0
    failed: int = 0
```

Definitions:

### Matched

Number of values selected by a configured rule or JSONPath.

### Changed

Number of selected values that were removed, redacted, filtered or pseudonymised.

### Skipped

Number of selected values intentionally left unchanged.

Examples:

* value was not the expected type;
* email domain was allow-listed;
* value was already redacted;
* no filtering expression matched.

### Failed

Number of values that could not be processed because of an execution error.

---

## 10.9 Transformation metrics

Guardette shall record cumulative metrics for each action type.

Required counters:

```text
guardette_transformation_actions_total
guardette_fields_matched_total
guardette_fields_changed_total
guardette_fields_skipped_total
guardette_transformation_failures_total
guardette_zero_match_total
```

Required dimensions:

```text
action
source_kind
route
policy_version
outcome
environment
```

Permitted action values:

```text
redact
remove
pseudonymize_email
filter_regex
allow
custom
```

The system must not use the following as metric dimensions:

* request ID;
* user ID;
* email address;
* raw hostname;
* raw URL;
* raw JSONPath;
* issue key;
* calendar ID;
* document ID;
* arbitrary exception message.

---

## 10.10 Request-level transformation summary

Guardette shall aggregate action results for the request.

Example:

```json
{
  "event": "guardette.response.transformed",
  "request_id": "opaque-id",
  "policy_version": "sha256:...",
  "redacted_count": 14,
  "removed_count": 3,
  "pseudonymised_count": 7,
  "filtered_count": 1,
  "matched_count": 28,
  "changed_count": 25,
  "skipped_count": 3,
  "failure_count": 0,
  "duration_ms": 4.2
}
```

This event must contain counts only.

No transformed values shall be included.

---

## 10.11 Zero-match detection

A zero-match condition occurs where:

* an action is configured;
* the action executes successfully;
* zero fields match the configured selector.

Guardette shall increment:

```text
guardette_zero_match_total
```

A zero-match result is not automatically an error.

The monitoring system shall support alerts where a route that historically changes fields begins consistently producing zero matches.

This may indicate:

* upstream schema change;
* incorrect JSONPath;
* wrong policy selection;
* empty upstream response;
* unexpected content type;
* faulty transformation implementation.

---

## 10.12 Upstream dependency telemetry

Guardette shall record:

* logical upstream type;
* normalised upstream route;
* method;
* status class;
* duration;
* timeout;
* retry count;
* response size bucket;
* authentication failure;
* rate-limit response;
* network failure.

Example:

```json
{
  "event": "guardette.upstream.completed",
  "request_id": "opaque-id",
  "upstream": "jira",
  "method": "GET",
  "route": "/rest/api/3/issue/{issueId}",
  "status_code": 200,
  "duration_ms": 465.8,
  "response_size_bucket": "10kb-100kb",
  "retry_count": 0
}
```

Raw upstream URLs and customer-specific hostnames must not be logged.

---

## 10.13 Authentication and secret telemetry

Guardette shall emit metadata-only events for:

* secret cache hit;
* secret cache miss;
* secret retrieval failure;
* OAuth token cache hit;
* OAuth token request;
* OAuth token request failure;
* upstream authentication rejection;
* unsupported authentication handler.

No secret value, token, password, credential ARN or authorisation header shall be recorded.

Permitted attributes include:

* authentication handler type;
* logical secret name;
* cache result;
* duration;
* outcome;
* error type.

---

## 10.14 Health endpoints

The service shall provide:

```text
/health/live
/health/ready
```

### Liveness

Confirms the process and event loop are responsive.

Liveness shall not depend on upstream services.

### Readiness

Confirms:

* policy loaded;
* policy valid;
* mandatory configuration present;
* required action modules registered;
* required authentication handler configuration present;
* service can enforce policy.

Readiness shall return HTTP 503 if Guardette cannot safely enforce policy.

Health request logs should be disabled or heavily sampled.

---

## 10.15 Distributed tracing

Tracing shall be optional and independently feature flagged.

The application shall support W3C trace context propagation.

Recommended spans:

```text
guardette.request
guardette.policy.select
guardette.secret.resolve
guardette.auth.acquire
guardette.upstream.request
guardette.response.transform
guardette.response.validate
```

Span attributes must use the same data classification rules as logs and metrics.

Request or response bodies must not be added as span attributes or events.

Tracing shall use configurable sampling.

---

## 10.16 Failure behaviour

Observability failures must not fail a Guardette request.

Adapter calls shall be:

* exception-safe;
* bounded in execution time;
* non-blocking where practical;
* isolated from policy execution.

If an adapter raises an exception:

1. Guardette shall continue processing.
2. The adapter error may be written to stderr using a minimal safe fallback logger.
3. Repeated adapter errors should be rate limited.
4. The system shall increment an internal telemetry failure counter where possible.

Required metric:

```text
guardette_observability_errors_total
```

---

# 11. Adapter Requirements

## 11.1 No-op adapter

The no-op adapter shall:

* implement every interface;
* perform no external I/O;
* allocate minimal objects;
* never raise an exception.

It shall be used when a capability is disabled.

---

## 11.2 Structured stdout adapter

The stdout adapter shall:

* emit one-line JSON records;
* use UTC timestamps;
* include service and environment metadata;
* emit errors to stderr;
* omit unset optional fields;
* avoid Python object string representations;
* sanitise exceptions;
* avoid duplicate stack traces.

Cloudflare shall collect stdout and stderr from the container.

---

## 11.3 OpenTelemetry adapter

The OpenTelemetry adapter may be introduced after the baseline release.

It shall:

* support OTLP over HTTPS;
* batch exports;
* use bounded queues;
* use configurable timeouts;
* drop telemetry rather than block proxy execution;
* propagate incoming trace context;
* instrument FastAPI and outbound HTTP clients;
* support clean shutdown and bounded flush.

---

## 11.4 Composite adapter

The system should support sending the same event to multiple adapters.

Example:

```text
Request logs -> stdout
Metrics      -> OpenTelemetry
Security     -> stdout and OTLP
Tracing      -> OTLP
```

A failure in one child adapter must not prevent delivery to the remaining adapters.

---

# 12. Event Schema Requirements

Every structured event shall contain:

```text
event
timestamp
service
service_version
environment
```

Request-scoped events should additionally contain:

```text
request_id
trace_id
cf_ray
route
method
policy_version
```

Events shall use stable names in the following namespace:

```text
guardette.request.*
guardette.policy.*
guardette.transform.*
guardette.upstream.*
guardette.secret.*
guardette.auth.*
guardette.container.*
guardette.observability.*
```

Event schema changes shall be backwards compatible where practical.

A schema version may be included:

```text
schema_version=1
```

---

# 13. Data Protection Requirements

## 13.1 Prohibited telemetry data

The following must never be recorded:

* request bodies;
* response bodies;
* credentials;
* OAuth tokens;
* API keys;
* cookies;
* authorisation headers;
* session identifiers;
* raw query strings;
* email addresses;
* usernames;
* personal names;
* Jira issue summaries;
* calendar event content;
* document contents;
* field values before transformation;
* field values after transformation;
* pseudonymisation salt;
* secret manager values;
* exception messages containing upstream response content.

## 13.2 Restricted telemetry data

The following may only be recorded after normalisation or pseudonymisation:

* upstream hostname;
* route path;
* tenant identifier;
* customer identifier;
* policy identifier;
* resource identifier.

## 13.3 Allowed telemetry data

The following are permitted:

* opaque request identifier;
* trace identifier;
* Cloudflare Ray ID;
* method;
* normalised route;
* HTTP status;
* duration;
* action type;
* field counts;
* service version;
* policy hash;
* environment;
* error class;
* upstream class;
* payload-size bucket;
* retry count.

---

# 14. Metrics Catalogue

## 14.1 Request metrics

```text
guardette_requests_total
guardette_request_failures_total
guardette_request_duration_ms
guardette_guardette_duration_ms
guardette_upstream_duration_ms
guardette_response_size_bytes
```

Dimensions:

```text
method
route
status_class
source_kind
environment
```

## 14.2 Policy metrics

```text
guardette_policy_load_total
guardette_policy_load_failures_total
guardette_policy_decisions_total
guardette_policy_evaluation_duration_ms
guardette_policy_no_match_total
guardette_policy_version_instances
```

Dimensions:

```text
outcome
source_kind
route
policy_version
environment
```

## 14.3 Transformation metrics

```text
guardette_transformation_actions_total
guardette_fields_matched_total
guardette_fields_changed_total
guardette_fields_skipped_total
guardette_transformation_failures_total
guardette_zero_match_total
guardette_transformation_duration_ms
```

Dimensions:

```text
action
source_kind
route
policy_version
outcome
environment
```

## 14.4 Upstream metrics

```text
guardette_upstream_requests_total
guardette_upstream_failures_total
guardette_upstream_duration_ms
guardette_upstream_timeouts_total
guardette_upstream_rate_limits_total
guardette_upstream_retries_total
guardette_upstream_auth_failures_total
```

Dimensions:

```text
upstream
method
route
status_class
environment
```

## 14.5 Secret and authentication metrics

```text
guardette_secret_cache_hits_total
guardette_secret_cache_misses_total
guardette_secret_fetch_failures_total
guardette_secret_fetch_duration_ms
guardette_auth_token_requests_total
guardette_auth_token_failures_total
guardette_auth_cache_hits_total
```

Dimensions:

```text
handler
secret_type
outcome
environment
```

## 14.6 Runtime metrics

```text
guardette_container_starts_total
guardette_container_start_failures_total
guardette_container_ready
guardette_observability_errors_total
```

Cloudflare-native metrics shall additionally cover:

* Worker invocations;
* Worker CPU time;
* Worker duration;
* container CPU;
* container memory;
* network;
* restarts;
* container uptime.

---

# 15. Service-Level Indicators

## 15.1 Availability

```text
successful valid requests / total valid requests
```

Initial target:

```text
99.9%
```

## 15.2 Enforcement success

```text
responses with successful policy selection and completed transformations
/
responses requiring policy enforcement
```

Initial target:

```text
99.99%
```

## 15.3 Policy readiness

```text
instances serving expected policy version / active instances
```

Target:

```text
100%
```

## 15.4 Guardette-owned latency

```text
total duration - upstream duration
```

Initial target:

```text
p95 below 100 ms
```

This target must be reviewed after production baselining.

## 15.5 Transformation failure rate

```text
failed transformation actions / executed transformation actions
```

Target:

```text
0%
```

---

# 16. Alerting Requirements

## 16.1 Immediate page

Page when:

* a response is returned without a successful policy decision;
* a response requiring transformation is returned after transformation failure;
* policy loading fails across newly started instances;
* multiple instances serve different policy versions unexpectedly;
* readiness remains failed after deployment;
* 5xx rate exceeds 5% for five minutes at meaningful traffic volume;
* upstream authentication failures affect multiple requests;
* transformation failure rate exceeds threshold;
* memory, CPU or disk saturation threatens availability;
* repeated container restarts occur;
* an unapproved upstream host is requested.

## 16.2 Security alert

Alert security when:

* an unapproved host or route is attempted;
* a configured action repeatedly produces zero matches;
* redaction counts materially diverge from the established baseline;
* policy version differs from the approved deployment;
* security-event telemetry stops unexpectedly;
* configuration attempts to enable sensitive logging in production.

## 16.3 Operational ticket

Create a ticket when:

* upstream 429 responses trend upwards;
* secret retrieval latency increases;
* cold-start duration increases materially;
* one route develops elevated upstream latency;
* zero-match events persist without an immediate security impact;
* telemetry adapter failures recur;
* trace or log export queues continuously drop data.

---

# 17. Dashboards

## 17.1 Service health dashboard

Must show:

* requests per second;
* HTTP status distribution;
* p50, p95 and p99 latency;
* Guardette-owned latency;
* upstream latency;
* Worker CPU and duration;
* container CPU and memory;
* container restarts;
* active service version;
* active policy version;
* readiness status.

## 17.2 Security enforcement dashboard

Must show:

* policy allow, deny and no-match decisions;
* transformations by action;
* fields matched;
* fields changed;
* fields skipped;
* transformation failures;
* zero-match events;
* unapproved host attempts;
* policy version divergence;
* enforcement success rate.

## 17.3 Dependency health dashboard

Must show per upstream:

* request volume;
* latency;
* error rate;
* timeouts;
* retries;
* authentication failures;
* 429 responses;
* response-size distribution.

---

# 18. Performance Requirements

1. Baseline observability shall add no more than 5 ms p95 Guardette-owned latency.
2. Metric recording must not perform synchronous external network calls in the request path.
3. Logging shall emit a bounded number of events per request.
4. Guardette shall not emit one external event per transformed field.
5. Transformation counts shall be aggregated locally and emitted once per action or request.
6. Event serialisation must avoid request or response deep copies.
7. Telemetry queues must be bounded.
8. Telemetry backpressure must result in dropped telemetry, not request failure.
9. Repeated internal observability errors must be rate limited.

---

# 19. Security Requirements

1. Observability configuration shall be validated at startup.
2. Unsafe logging options shall be rejected in production.
3. Adapter credentials shall use short-lived or platform-provided identity where available.
4. OTLP endpoints shall require TLS.
5. Telemetry export credentials shall be stored separately from upstream API credentials.
6. Telemetry adapters shall operate with least privilege.
7. Logging sanitisation shall be tested automatically.
8. Policy and service versions shall be immutable deployment metadata.
9. Route normalisation shall occur before logging.
10. Exception sanitisation shall remove credential and payload content.
11. Observability modules shall not receive full bodies unless required for in-process counting.
12. Transformation metrics shall contain counts only.
13. Telemetry retention shall align with organisational data retention policy.
14. Access to security event logs shall be restricted and audited.

---

# 20. Testing Requirements

## 20.1 Unit tests

Tests shall verify:

* no-op adapters never raise;
* adapter factory selects the correct implementation;
* disabled capabilities use no-op adapters;
* route normalisation removes identifiers;
* query strings are not logged;
* header values are not logged;
* transformation result counts are accurate;
* matched, changed and skipped are distinguished;
* zero-match metrics are emitted;
* transformation failures increment failure metrics;
* observability exceptions do not fail the request;
* policy hashes remain deterministic;
* unsafe production configuration is rejected.

## 20.2 Sensitive-data tests

Tests shall inject marker values into:

* headers;
* request bodies;
* response bodies;
* query strings;
* exception messages;
* upstream error payloads;
* email values;
* policy configuration.

Captured telemetry shall be asserted not to contain those markers.

## 20.3 Integration tests

Tests shall verify:

* request ID propagation from Worker to container;
* request ID returned to the client;
* trace context propagation;
* policy events correlate with request events;
* upstream duration is separated from Guardette duration;
* stdout events are valid JSON;
* health endpoints behave correctly;
* policy load failure causes readiness failure;
* telemetry backend failure does not affect Guardette response processing.

## 20.4 Transformation tests

For each action type:

* no target values;
* one target value;
* multiple target values;
* invalid target type;
* skipped allow-listed value;
* already transformed value;
* partial failure;
* nested arrays and objects;
* multiple JSONPath rules targeting overlapping fields.

Overlapping selectors must not unintentionally double-count the same changed field unless explicitly documented.

---

# 21. Rollout Plan

## Phase 1: Baseline service visibility

Deliver:

* configuration model;
* feature flags;
* no-op adapters;
* structured stdout adapter;
* FastAPI request middleware;
* request ID propagation;
* liveness and readiness endpoints;
* service and policy version metadata;
* request, error and latency events;
* basic dashboards and alerts.

## Phase 2: Security enforcement telemetry

Deliver:

* policy lifecycle events;
* policy decision events;
* transformation result model;
* matched, changed, skipped and failed counts;
* request-level transformation summary;
* zero-match detection;
* security enforcement dashboard;
* policy-version divergence alert.

## Phase 3: Dependency telemetry

Deliver:

* upstream API metrics;
* secret cache metrics;
* authentication metrics;
* dependency dashboard;
* rate-limit, timeout and authentication alerts.

## Phase 4: Distributed tracing and external export

Deliver:

* W3C trace context;
* FastAPI tracing;
* HTTP client tracing;
* manual policy and transformation spans;
* OTLP adapter;
* bounded export queues;
* external retention and alert integration.

## Phase 5: Advanced assurance

Deliver:

* synthetic redaction canaries;
* schema-change anomaly detection;
* expected transformation baselines;
* automated deployment comparison;
* release health gates;
* optional automated rollback signals.

---

# 22. Acceptance Criteria

The capability will be accepted when:

1. Observability features can be enabled or disabled independently.
2. Disabled features use no-op adapters without conditional logic spread across core code.
3. Every proxied request has a correlation identifier.
4. Worker and container events can be correlated.
5. Request events include normalised routes and timing.
6. Policy load and policy decision events are emitted.
7. Every transformation action returns matched, changed, skipped and failed counts.
8. Request-level transformation summaries are emitted.
9. Zero-match conditions can be queried and alerted on.
10. No telemetry contains request or response bodies.
11. No telemetry contains credentials, tokens or raw personal data.
12. Telemetry adapter failure does not fail requests.
13. Readiness fails when Guardette cannot enforce policy.
14. Dashboards show service health and enforcement health separately.
15. Automated tests prove sensitive markers do not enter telemetry.
16. The baseline implementation adds no more than 5 ms p95 Guardette-owned latency.
17. Active service and policy versions are visible.
18. Production configuration rejects unsafe body, header or query logging.

---

# 23. Key Risks and Mitigations

## Risk: Sensitive data enters logs

**Mitigation:**

* allow-list telemetry fields;
* prohibit generic object serialisation;
* centralise sanitisation;
* add marker-based leak tests;
* reject unsafe production settings.

## Risk: Metric cardinality becomes unbounded

**Mitigation:**

* use normalised routes;
* use logical upstream names;
* prohibit request IDs and raw resource identifiers as labels;
* review dimensions before adding metrics.

## Risk: Telemetry increases request latency

**Mitigation:**

* aggregate locally;
* use stdout or asynchronous exporters;
* bound queues;
* avoid per-field export;
* benchmark p95 overhead.

## Risk: Telemetry failure affects enforcement

**Mitigation:**

* exception-safe adapter wrapper;
* no-op fallback;
* bounded timeouts;
* drop telemetry rather than block.

## Risk: Zero-match alerts create noise

**Mitigation:**

* baseline by route and action;
* require sustained deviation;
* distinguish naturally empty responses from schema-change patterns.

## Risk: Counts are inaccurate because selectors overlap

**Mitigation:**

* document counting semantics;
* track object paths internally where required;
* test overlapping JSONPath behaviour;
* count changed values once per action unless explicitly configured otherwise.

## Risk: Policy hash changes because of formatting only

**Mitigation:**

* hash canonicalised policy data rather than raw YAML text.

---

# 24. Open Decisions

1. Whether the first external backend will be Grafana Cloud, Honeycomb or another OTLP platform.
2. Whether metrics will initially use structured stdout, Cloudflare Analytics Engine or direct OTLP export.
3. Whether policy identifiers need tenant-safe pseudonymisation.
4. Whether policy reload is supported without container restart.
5. Whether security events require separate retention from operational logs.
6. Whether expected transformation counts should be configured explicitly or learned from historical baselines.
7. Whether custom actions must implement a mandatory transformation result interface.
8. Whether tracing should be enabled by default in non-production environments.
9. Whether deployment health should block promotion when policy-version divergence is detected.
10. Whether synthetic canary responses can be safely executed against each upstream integration.

---

# 25. Recommended Initial Implementation

The first production release should include:

* structured stdout logs;
* no-op adapters;
* separate request, metrics and security interfaces;
* independent feature flags;
* correlation IDs;
* request lifecycle middleware;
* policy version hashing;
* policy decision events;
* transformation counts;
* zero-match metrics;
* upstream duration;
* readiness and liveness endpoints;
* Cloudflare-native Worker and container metrics;
* security-focused dashboards;
* sensitive-data telemetry tests.

Direct OpenTelemetry export should follow after the event model and metric dimensions have stabilised.

The critical initial control is not distributed tracing. It is proving that each successful response had the intended policy applied and that the expected fields were actually transformed.
