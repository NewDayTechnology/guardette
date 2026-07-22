# Guardette

Guardette is a **redacting proxy layer** that sits between the REST APIs of your data sources and vendors who require access to a subset of that data. By leveraging Guardette, you can achieve **more secure and granular access control** through customizable redaction and allow-listing rules defined in a YAML file.

## Features

- **Flexible Deployment**: Run as a standalone webservice or deploy as an AWS Lambda function.
- **Redaction and Filtering**: Define precise rules to redact sensitive information or filter specific data fields.
- **Granular Access Control**: Allow or restrict access to specific parts of your APIs based on defined policies.
- **Authentication Support**: Integrate with various authentication mechanisms, including AWS Secrets Manager for secure credential management.
- **Extensible**: Easily add custom actions and authentication handlers to extend Guardette's capabilities.

## Getting Started

### Generate a policy.yml

Span will send you a config file to generate your policy.yml with, but it might look something like this:

```
{
  "sources": [
    {
      "kind": "test_hacker_news",
      "config": {}
    },
    {
      "kind": "jira_basic_auth",
      "config": {"jira_domain": "yourdomain.atlassian.net"}
    }
  ]
}
```

```
poetry run python scripts/policygen/policygen.py --config=policygen.config.json
```

Upon successful execution, a `.guardette/policy.yml` file will be created. This YAML file contains the rules that the proxy will use to enforce data access policies.

### Setup

#### Option A: Docker

1. **Build the image**

```
docker build -t guardette .
```

2. **Run the container**

Mount your policy file and pass secrets via environment variables:

```
docker run \
  -v $(pwd)/.guardette/policy.yml:/app/config/policy.yml:ro \
  -e CLIENT_SECRET=your-secret \
  -p 8000:8000 \
  guardette
```

Or using Docker Compose:

```
docker compose up
```

See `docker-compose.yml` for a complete example with all configuration options.

#### Option B: Local

1. **Install dependencies**

```
poetry install
```

2. **Set up your `.env` file** (see `.env.example`)

```
cp .env.example .env
```

3. **Run the server**

```
poetry run uvicorn main:app --reload
```

### Verify it works

```
curl -H "Authorization: secret" -H "X-Guardette-Host: hacker-news.firebaseio.com" "http://localhost:8000/v0/item/8863.json?print=pretty"
```

### Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `CLIENT_SECRET` | Yes | - | Secret for authenticating requests to Guardette |
| `GUARDETTE_POLICY_PATH` | Yes | `/app/config/policy.yml` (Docker) / `.guardette/policy.yml` (local via `.env`) | Path to policy YAML file |
| `SECRET_MANAGER` | No | `default` | Secret manager backend (`default` or `aws_secret_manager`) |
| `PROXY_CLIENT_TIMEOUT_SECS` | No | `60` | Proxy request timeout in seconds |
| `SECRET_MANAGER_CACHE_TTL_SECS` | No | `120` | Secret cache TTL in seconds |
| `PSEUDONYMIZE_ALGORITHM` | No | `sha256` | Pseudonymization algorithm: `sha256` (legacy) or `hmac-sha256` |
| `PSEUDONYMIZE_SALT` | Conditional | `""` | Non-empty secret input for legacy `sha256`; new deployments should use at least 32 random bytes |
| `HMAC_KEY` | Conditional | `""` | Secret HMAC key for `hmac-sha256`; at least 32 bytes is enforced |
| `PSEUDONYMIZE_EMAIL_DOMAINS_ALLOWLIST` | No | `""` | Comma-separated domain allowlist |
| `OBS_ENABLED` | No | `false` | Master switch for application observability |
| `OBS_REQUEST_LOGGING_ENABLED` | No | `false` | Opt-in safe request/response JSON logging |
| `OBS_METRICS_ENABLED` | No | `false` | Opt-in low-cardinality metric events |
| `SERVICE_NAME` | No | `guardette` | Service name in observability events |
| `SERVICE_VERSION` | No | Package version | Service version in observability events |
| `ENVIRONMENT` | No | `unknown` | Deployment environment in observability events |

When enabled, request events include method, normalized route, status, duration, the `request_id` event field, and a small allowlist of safe headers. The same opaque ID is returned in the `X-Guardette-Request-Id` response header. Request/response bodies, query strings, authorization headers, cookies, tokens, API keys, and secrets are not logged. Metric events are emitted as structured JSON to `stdout`; native Cloudflare or OTLP metric export is a deployment concern.

Authentication metrics distinguish `failure_class=client` for credentials rejected by Guardette from `failure_class=upstream` for target-service credentials rejected by Jira or another configured upstream. Upstream 401/403 responses are recorded with `outcome=auth_failure` in `guardette_upstream_requests_total`.

### Pseudonymization algorithms

`pseudonymize_email` remains the same policy action. Select its digest construction with `PSEUDONYMIZE_ALGORITHM`:

| Algorithm | Construction | Secret variable | Characteristics |
|---|---|---|---|
| `sha256` | `SHA-256(value + PSEUDONYMIZE_SALT)` | `PSEUDONYMIZE_SALT` | Legacy default for compatibility; deterministic and non-reversible; not a standard keyed construction |
| `hmac-sha256` | `HMAC-SHA-256(HMAC_KEY, context + value)` | `HMAC_KEY` | Recommended; deterministic and non-reversible; uses a standard keyed construction |

Both modes preserve stable correlation and the existing `u-{hash}@d-{hash}.invalid` output format. Neither mode is encryption or reversible pseudonymization. Switching algorithms changes all generated pseudonyms.

For new deployments, use at least 32 bytes of high-entropy material for either secret. HMAC mode enforces this minimum; legacy `sha256` accepts existing non-empty salts for compatibility. Do not use a password or human-readable value. Generate a safe key with OpenSSL:

```bash
# Recommended for environment variables and .env files:
openssl rand -hex 32

# Alternatively, use Base64:
openssl rand -base64 32 | tr -d '\n'
```

Copy the generated value into `HMAC_KEY` when using `hmac-sha256`, or into `PSEUDONYMIZE_SALT` when using legacy `sha256`. Guardette treats the generated hex or Base64 text as the key directly; do not manually decode it. Keep the value out of source control and logs. When using AWS Secrets Manager, the environment variable contains the secret identifier and the stored secret value must meet the same requirement.

## Deploying to AWS Lambda

To deploy as an AWS Lambda function, build with the Lambda Dockerfile:

```
docker build -f Dockerfile.awslambda -t guardette-lambda .
```

See [terraform/aws/README.md](terraform/aws/README.md) for full deployment instructions.

## Authentication Configuration

Guardette supports multiple authentication handlers (`basic_auth`, `bearer_token`, `gcp_service_account`, `oauth2_client_credentials`) defined in the `guardette/default_auth/` directory. When a policy specifies an auth handler, Guardette looks up the required credentials via environment variables.

### Naming Convention

Each handler declares its own required **secret keys** (fetched via the [secret manager backend](#secret-manager-backends)) and **config keys** (always read directly from the environment, never from a secret manager). Given a policy `auth` value of `<handler>` or `<handler>:<subkind>`, the environment variable for one of its keys is:

```
AUTH_<HANDLER>_[<SUBKIND>_]<KEY>
```

(all uppercased, `<SUBKIND>_` only present if your policy's `auth` value includes a subkind).

#### Handlers

| Handler | Secret keys | Config keys |
|---|---|---|
| `basic_auth` | `username`, `password` | – |
| `bearer_token` | `secret` | – |
| `gcp_service_account` | `secret` | `scopes` |
| `oauth2_client_credentials` | `client_id`, `client_secret` | `token_url` |

#### Examples

Apply the pattern above to each handler's keys to get the environment variables for a given policy `auth` value:

| Policy `auth` value | Required environment variables |
|---|---|
| `basic_auth:jira` | `AUTH_BASIC_AUTH_JIRA_USERNAME`, `AUTH_BASIC_AUTH_JIRA_PASSWORD` |
| `bearer_token:github` | `AUTH_BEARER_TOKEN_GITHUB_SECRET` |
| `gcp_service_account` (no subkind) | `AUTH_GCP_SERVICE_ACCOUNT_SECRET`, `AUTH_GCP_SERVICE_ACCOUNT_SCOPES` |
| `oauth2_client_credentials:jira` | `AUTH_OAUTH2_CLIENT_CREDENTIALS_JIRA_CLIENT_ID`, `AUTH_OAUTH2_CLIENT_CREDENTIALS_JIRA_CLIENT_SECRET`, `AUTH_OAUTH2_CLIENT_CREDENTIALS_JIRA_TOKEN_URL` |

### Secret Manager Backends

The `SECRET_MANAGER` environment variable controls how these credential values are interpreted.

#### Option 1: Environment Variables (default)

Set `SECRET_MANAGER=default` (or omit it — this is the default). Environment variables contain the **actual secret values** directly.

```
AUTH_BASIC_AUTH_JIRA_USERNAME=your_jira_username
AUTH_BASIC_AUTH_JIRA_PASSWORD=your_jira_password
```

Best for: Docker and local development.

#### Option 2: AWS Secrets Manager

Set `SECRET_MANAGER=aws_secret_manager`. Environment variables contain **ARNs** pointing to secrets in AWS Secrets Manager. Guardette fetches the actual values at runtime, with TTL-based caching controlled by `SECRET_MANAGER_CACHE_TTL_SECS`.

```
SECRET_MANAGER=aws_secret_manager
AUTH_BASIC_AUTH_JIRA_USERNAME=arn:aws:secretsmanager:us-west-2:123456789012:secret:JIRA_USERNAME
AUTH_BASIC_AUTH_JIRA_PASSWORD=arn:aws:secretsmanager:us-west-2:123456789012:secret:JIRA_PASSWORD
```

For HMAC mode, set `PSEUDONYMIZE_ALGORITHM=hmac-sha256` and provide an ARN for `HMAC_KEY` instead of `PSEUDONYMIZE_SALT`.

Best for: AWS Lambda deployments.

To create secrets in AWS Secrets Manager:

```bash
aws secretsmanager create-secret --name AUTH_BASIC_AUTH_JIRA_USERNAME --secret-string "your_jira_username"
aws secretsmanager create-secret --name AUTH_BASIC_AUTH_JIRA_PASSWORD --secret-string "your_jira_password"
```

For Lambda deployments, pass the ARNs via Terraform:

```hcl
variable "environment_vars" {
  default = {
    SECRET_MANAGER                       = "aws_secret_manager"
    CLIENT_SECRET                        = "arn:aws:secretsmanager:us-west-2:123456789012:secret:CLIENT_SECRET"
    PSEUDONYMIZE_SALT                    = "arn:aws:secretsmanager:us-west-2:123456789012:secret:SALT_SECRET"
    PSEUDONYMIZE_EMAIL_DOMAINS_ALLOWLIST = "example.com"
    AUTH_BASIC_AUTH_JIRA_USERNAME        = "arn:aws:secretsmanager:us-west-2:123456789012:secret:JIRA_USERNAME"
    AUTH_BASIC_AUTH_JIRA_PASSWORD        = "arn:aws:secretsmanager:us-west-2:123456789012:secret:JIRA_PASSWORD"
  }
}
```

See [terraform/aws/README.md](terraform/aws/README.md) for full deployment instructions.

### Policy Configuration

Guardette uses a policy file (`.guardette/policy.yml`) to determine how to handle incoming API requests. This file is generated using the `policygen.py` script based on the `policygen.config.json` configuration.

- **policygen.config.json**: Defines the sources and their specific configurations.
- **scripts/policygen/policygen.py**: Processes the configuration and generates the policy YAML file.

**Sample Policy Template**

Here's an example of a policy template for a Google Workspace Calendar source:

```yaml
  host: www.googleapis.com
  auth: gcp_service_account
  rules:
    - route: "GET /calendar/v3/calendars/{calendarId}"
      actions:
        - kind: redact
          json_paths:
            - "$.summary"
    - route: "GET /calendar/v3/calendars/{calendarId}/events"
      actions:
        - kind: redact
          json_paths:
            - "$..summary"
            - "$..displayName"
            - "$.items[*].summary"
        - kind: remove
          json_paths:
            - "$.items[*].attachments"
            - "$.items[*].conferenceData"
            - "$.items[*].extendedProperties"
        - kind: pseudonymize_email
          json_paths:
            - "$..email"
        - kind: filter_regex
          json_paths:
            - "$.items[*].description"
          regex_pattern: '\b(https:\/\/[^.]+\.greenhouse\.io\/[^\s]+|https://[^.]+\.ashbyhq\.com\/[^\s]+)\b'
          delimiter: " "
```

## Development Setup
```
brew install pre-commit
pre-commit install
poetry install
```

### Building the Wheel
```
poetry build
```

### Running Tests
```
poetry run pytest
```
