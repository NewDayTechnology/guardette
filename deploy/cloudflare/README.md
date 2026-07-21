# Cloudflare Containers deployment

This adapter keeps the Python proxy unchanged and exposes it through one
private Cloudflare Container behind a Worker and Durable Object. The Worker
routes every request to the named `guardette` instance, while the container
image listens on port `8000` and uses `/healthz` for readiness checks.

## Prerequisites

- Node.js and npm
- Wrangler 4.112 or newer
- Docker-compatible local container tooling
- A Cloudflare account with Containers enabled

From the repository root, install the Worker dependencies:

```bash
cd deploy/cloudflare
npm ci
```

Authenticate Wrangler before creating account resources:

```bash
npx wrangler login
```

Create and review the production policy before deploying. Run this command
from the repository root; the Cloudflare image build expects the generated
artifact at:

```text
.guardette/policy.yml
```

```bash
cd ../..
poetry run python scripts/policygen/policygen.py \
  --config=policygen.config.json
cd deploy/cloudflare
```

That path is intentionally ignored and not committed. Policy changes require
a new image deployment.

## Secrets

Use Cloudflare Secrets Store for production secrets. It provides centralized
account-level storage, scoped Worker bindings, and separate access control
from the Worker deployment. Worker Secrets remain supported as a fallback for
local development or a single-Worker setup.

The Worker passes an explicit allowlist of environment variables to the
container. It does not enumerate bindings or log secret values. For Secrets
Store, create a store and only the secrets required by the deployed policy:

```bash
npx wrangler secrets-store store create guardette --remote
npx wrangler secrets-store store list
npx wrangler secrets-store secret create <STORE_ID> \
  --name CLIENT_SECRET --scopes workers --remote
npx wrangler secrets-store secret create <STORE_ID> \
  --name AUTH_BASIC_AUTH_JIRA_PASSWORD --scopes workers --remote
```

The canonical command shape is:

```bash
npx wrangler secrets-store secret create <STORE_ID> \
  --name <SECRET_NAME> \
  --scopes workers \
  --remote
```

Use `workers` as the scope. Cloudflare Secrets Store currently supports the
`workers` and `ai-gateway` scopes; there is no separate `containers` scope.
The Worker consumes the bound secret and passes it to the private Container,
so a Container-backed deployment still requires the `workers` scope.

Keep deployment configuration out of Git by copying the tracked example:

```bash
cp wrangler.jsonc.example wrangler.jsonc
```

Edit `wrangler.jsonc` and replace `<STORE_ID>` and `<JIRA_USERNAME>`. That
file is ignored by Git and is the active Wrangler configuration used by local
development and production deployment. The username is a non-secret Worker
variable; the client secret and Jira API token are stored in Secrets Store.
Do not put Secret Store values in the Wrangler configuration.

If you maintain separate local copies, name them `wrangler.jsonc.dev` and
`wrangler.jsonc.production` (both are ignored), then copy the desired one to
`wrangler.jsonc` before running Wrangler. Wrangler's canonical config filename
is required for consistent `dev`, `types`, and `deploy` behavior.

The adapter resolves each configured Secrets Store binding asynchronously and
injects its value into the Container only when it starts.

Creating secrets requires Secrets Store Admin or Super Administrator access.
Deploying a Worker that binds them requires a Secrets Store Deployer role or
an API token with Account Secrets Store Edit permission.

If you use Worker Secrets instead, create the required names with:

```bash
npx wrangler secret put CLIENT_SECRET
npx wrangler secret put AUTH_BASIC_AUTH_JIRA_USERNAME
npx wrangler secret put AUTH_BASIC_AUTH_JIRA_PASSWORD
```

When a Secrets Store binding exists, it takes precedence over the same-named
Worker Secret. `SECRET_MANAGER=default` remains the Guardette backend because
both Cloudflare mechanisms provide runtime environment values. AWS Secrets
Manager is not used.

Production Secrets Store values are not available to local development. Use
an ignored `.dev.vars` file with local-only values, or create non-remote test
secrets if local Secrets Store testing is required.

When secrets rotate, restart or redeploy the Container so new instances
receive the new values.

## Deploy

Run the type checks from `deploy/cloudflare` after creating `wrangler.jsonc`:

```bash
cd deploy/cloudflare
npm run typecheck
cd ../..
```

Deploy from the repository root with the config under `deploy/cloudflare`:

```bash
npx wrangler deploy --config deploy/cloudflare/wrangler.jsonc
```

Wrangler builds `../../Dockerfile.cloudflare` with `../../` as the explicit
Docker build context, which is the repository root. Docker must be running.
The Cloudflare image uses `python:3.13-slim`, runs as the non-root `nobody`
user, and is built for Cloudflare's required `linux/amd64` architecture. The
root `.dockerignore` keeps the context limited to the Dockerfile and required
application inputs.

The standalone `wrangler containers build <PATH>` command does not support a
separate Dockerfile path and build context. Do not use it for this image,
because the Cloudflare Dockerfile is named `Dockerfile.cloudflare` while its
build context is the repository root. For a manual image build and push, run:

```bash
cd ../..
docker build --platform linux/amd64 \
  -f Dockerfile.cloudflare \
  -t guardette-dev .
env -u CLOUDFLARE_API_TOKEN npx wrangler containers push guardette-dev \
  --config deploy/cloudflare/wrangler.jsonc
```

If a deploy or push fails with `failed commit on ref ... 403 Forbidden` after
the image builds successfully, verify the OAuth session with
`wrangler whoami`. If it shows `containers: write` and a raw Docker push to
the same registry fails identically, the failure is in Cloudflare's managed
registry/account path rather than this Dockerfile or build context. Do not
commit registry credentials; raise the failing layer digest with Cloudflare
support or the Workers SDK issue tracker.

## Verify the deployment

Check the Worker and Container image status:

```bash
npx wrangler containers list --config deploy/cloudflare/wrangler.jsonc
npx wrangler containers images list --config deploy/cloudflare/wrangler.jsonc
```

Then send a request through the deployed Worker. Replace the Worker hostname
and Jira host with the deployment values:

```bash
curl \
  -H "Authorization: <GUARDETTE_CLIENT_SECRET>" \
  -H "X-Guardette-Host: <JIRA_HOST>" \
  "https://<WORKER_HOST>/rest/api/3/project/search"
```

The Worker forwards the request to the private Container. The Container
health check uses `/healthz`; it does not require client authentication or
call Jira.

## Local development

For local Worker development, create the ignored active configuration:

```bash
cp wrangler.jsonc.example wrangler.jsonc
```

Remove the `secrets_store_secrets` block and the placeholder Jira username
from `wrangler.jsonc`. Create an ignored `.dev.vars` file containing local
values such as:

```dotenv
CLIENT_SECRET=local-client-secret
AUTH_BASIC_AUTH_JIRA_USERNAME=local-jira-username
AUTH_BASIC_AUTH_JIRA_PASSWORD=local-jira-password
```

Then run:

```bash
npm run dev
```

`.dev.vars` is ignored by Git and supplies local Worker/container values.
Production deployment does not read `.dev.vars`; it uses only the ignored
`wrangler.jsonc` file.

Production Secrets Store values are not available to local development. If
you need to exercise Secrets Store locally, create local (non-remote) test
secrets with Wrangler and do not use production values.

## Observability

Workers Logs are enabled in `wrangler.jsonc`. The Worker emits
structured JSON events for request start/completion/failure and container
start/stop/error
hooks. It deliberately records only method, path, status, duration, and
non-sensitive error type. The Python container also emits JSON logs to stdout,
which appear in the Container logs.

Use the Worker Observability dashboard to query the `event`,
`request_id`, `status`, and `elapsed_ms` fields. Do not add request headers,
request bodies, query strings, policy contents, or secret values to these
events.
