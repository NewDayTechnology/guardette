# Redaction Rules

Guardette uses a policy file to control which API responses are modified and how. This document covers the policy file format and the available redaction rules.

## Policy File Format

A policy file defines one or more **sources** (upstream APIs), each with **rules** that match specific routes and apply **actions** to the response data.

```yaml
version: "1"
sources:
  - host: api.example.com
    auth: bearer_token:example
    rules:
      - route: "GET /api/v1/users"
        actions:
          - kind: redact
            json_paths:
              - "$.users[*].ssn"
      - route: "GET /api/v1/projects"
```

### Sources

Each source maps to a single upstream host.

| Field | Required | Description |
|---|---|---|
| `host` | Yes | Upstream API hostname (e.g., `api.github.com`, `gitlab.com`) |
| `auth` | No | Authentication handler. Format: `handler` or `handler:subkind` (e.g., `bearer_token:github`, `basic_auth:jira`, `gcp_service_account`) |
| `rules` | Yes | List of route rules |

Each host can only appear once across all sources.

### Rules

Each rule matches an HTTP method and path pattern, and optionally applies actions to the response.

| Field | Required | Description |
|---|---|---|
| `route` | Yes | Route pattern: `METHOD /path/{param}` (e.g., `GET /api/v4/projects/{projectId}/issues`) |
| `actions` | No | List of actions to apply. If omitted, the route is proxied without modification. |

Path parameters use `{paramName}` syntax and match any path segment.

### Actions

Actions transform API response data. Each action has a `kind` and operates on fields identified by JSONPath expressions. Multiple actions on a single route are applied in order.

## Available Actions

### `redact`

Replaces targeted values with a redaction token (default: `[REDACTED]`).

```yaml
- kind: redact
  json_paths:
    - "$.summary"
    - "$..displayName"
```

| Field | Type | Description |
|---|---|---|
| `json_paths` | `list[str]` | JSONPath expressions targeting values to replace |

**Use when:** You want to indicate a field exists but hide its value.

### `nullify`

Sets targeted values to `null`.

```yaml
- kind: nullify
  json_paths:
    - "$..description"
    - "$.issues[*].fields.worklog"
```

| Field | Type | Description |
|---|---|---|
| `json_paths` | `list[str]` | JSONPath expressions targeting values to nullify |

**Use when:** You want to blank out a field entirely. Useful for long-form free-text content like descriptions and comments where even a `[REDACTED]` token is unnecessary.

### `remove`

Removes targeted fields from the response entirely. Unlike `nullify`, the key itself is deleted.

```yaml
- kind: remove
  json_paths:
    - "$.items[*].attachments"
    - "$.items[*].conferenceData"
```

| Field | Type | Description |
|---|---|---|
| `json_paths` | `list[str]` | JSONPath expressions targeting fields to remove |

**Use when:** Downstream consumers should not see the field at all (e.g., attachments, raw diffs, embedded objects with sensitive data).

### `redact_regex`

Finds all matches of a regex pattern within string values and replaces them with the redaction token. Non-string values are left unchanged.

```yaml
- kind: redact_regex
  json_paths:
    - "$..summary"
    - "$..title"
  regex_pattern: '\b(\w{11,}|[\d-]{5,}|\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b)\b'
```

| Field | Type | Description |
|---|---|---|
| `json_paths` | `list[str]` | JSONPath expressions targeting string values |
| `regex_pattern` | `str` | Regex pattern to match (case-insensitive) |

**Use when:** You want to keep the overall structure of a text field but strip out specific sensitive patterns like email addresses, long identifiers, or numeric sequences.

### `filter_regex`

Extracts all matches of a regex pattern and replaces the field value with only the matched content, joined by a delimiter. This is the inverse of `redact_regex` -- it keeps matches and discards everything else.

```yaml
- kind: filter_regex
  json_paths:
    - "$.items[*].description"
  regex_pattern: '\bhttps:\/\/[^\s]+\.greenhouse\.io\/[^\s]+\b'
  delimiter: " "
```

| Field | Type | Description |
|---|---|---|
| `json_paths` | `list[str]` | JSONPath expressions targeting string values |
| `regex_pattern` | `str` | Regex pattern to extract (case-insensitive) |
| `delimiter` | `str` | String used to join multiple matches (default: `""`) |

**Use when:** You only need specific structured data (e.g., URLs) from a free-text field and want to discard everything else.

### `redact_secrets`

Scans string values with [detect-secrets](https://github.com/Yelp/detect-secrets) and replaces any detected secrets (API keys, tokens, high-entropy strings, etc.) with the redaction token. Surrounding text is preserved; only the secret substring itself is replaced. Non-string values are left unchanged. All built-in detect-secrets plugins run.

```yaml
- kind: redact_secrets
  json_paths:
    - "$[*].diff"
```

| Field | Type | Description |
|---|---|---|
| `json_paths` | `list[str]` | JSONPath expressions targeting string values |

**Use when:** Free-text fields (MR diffs, commit messages, issue bodies, chat logs) may contain accidentally-pasted credentials. Complements `redact_regex` (known-shape patterns) by catching provider-specific tokens and high-entropy strings.

### `pseudonymize_email`

Transforms email addresses into a deterministic pseudonymous format (`u-{hash}@d-{hash}.invalid`). The same email always produces the same pseudonym for the selected secret and algorithm, preserving the ability to correlate records by email without exposing the real address. This is not encryption and is not reversible.

```yaml
- kind: pseudonymize_email
  json_paths:
    - "$..email"
```

| Field | Type | Description |
|---|---|---|
| `json_paths` | `list[str]` | JSONPath expressions targeting email values |

**Required environment variables:**

| Variable | Description |
|---|---|
| `PSEUDONYMIZE_ALGORITHM` | Optional. `sha256` (default, legacy) or `hmac-sha256`. |
| `PSEUDONYMIZE_SALT` | Required when `PSEUDONYMIZE_ALGORITHM=sha256`. Used by the legacy `SHA-256(value + salt)` construction. |
| `HMAC_KEY` | Required when `PSEUDONYMIZE_ALGORITHM=hmac-sha256`. Used as the HMAC-SHA-256 key. |
| `PSEUDONYMIZE_EMAIL_DOMAINS_ALLOWLIST` | Optional. Comma-separated list of domains to skip pseudonymization (e.g., `example.com,company.org`). |

For new deployments, both secret values should contain at least 32 bytes of high-entropy material. HMAC mode enforces this minimum, while legacy `sha256` continues to accept existing non-empty salts for compatibility. Do not use a password or human-readable value. Generate a safe key with OpenSSL:

```bash
# Recommended for environment variables and .env files:
openssl rand -hex 32

# Alternatively, use Base64:
openssl rand -base64 32 | tr -d '\n'
```

Copy the generated value into `HMAC_KEY` for `hmac-sha256` or `PSEUDONYMIZE_SALT` for legacy `sha256`. Guardette treats the generated hex or Base64 text as the key directly; do not manually decode it. Keep the value out of source control and logs. The HMAC mode is the recommended construction; switching algorithms changes all generated pseudonyms.

**Use when:** You need to preserve email-based join/correlation logic in downstream systems without exposing actual email addresses.

## JSONPath Syntax

Actions use [JSONPath](https://goessner.net/articles/JsonPath/) expressions (via `jsonpath-ng`) to target fields in response data.

| Expression | Description |
|---|---|
| `$.field` | Top-level field |
| `$.parent.child` | Nested field |
| `$..field` | All occurrences of `field` at any depth (recursive descent) |
| `$.items[*].field` | `field` on every element of an array |
| `$.items[*].nested[*].field` | Nested array traversal |
| `$.items[?(@.type = "summary")].value` | Filter expression |

## Examples

### Proxying without modification

Routes without actions pass responses through unchanged. This is useful for metadata endpoints (labels, milestones, pipelines) that don't contain sensitive data.

```yaml
rules:
  - route: "GET /api/v4/projects/{projectId}/labels"
  - route: "GET /api/v4/projects/{projectId}/pipelines"
```

### Redacting titles and nullifying descriptions

A common pattern for user-authored content: use `redact_regex` on short structured fields (titles) and `nullify` on long free-text fields (descriptions).

```yaml
rules:
  - route: "GET /api/v4/projects/{projectId}/issues"
    actions:
      - kind: nullify
        json_paths:
          - "$..description"
      - kind: redact_regex
        json_paths:
          - "$..title"
        regex_pattern: '\b(\w{11,}|[\d-]{5,}|\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b)\b'
```

### Stripping sensitive fields from a complex response

Combine multiple action types to handle different field categories in a single route.

```yaml
rules:
  - route: "GET /calendar/v3/calendars/{calendarId}/events"
    actions:
      - kind: redact
        json_paths:
          - "$..summary"
          - "$..displayName"
      - kind: remove
        json_paths:
          - "$.items[*].attachments"
          - "$.items[*].conferenceData"
      - kind: pseudonymize_email
        json_paths:
          - "$..email"
```
