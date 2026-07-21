import { Container } from "@cloudflare/containers";

const CONTAINER_NAME = "guardette";

const CONTAINER_SECRET_NAMES = [
  "CLIENT_SECRET",
  "PSEUDONYMIZE_SALT",
  "AUTH_BASIC_AUTH_JIRA_USERNAME",
  "AUTH_BASIC_AUTH_JIRA_PASSWORD",
  "AUTH_BEARER_TOKEN_GITHUB_SECRET",
  "AUTH_BEARER_TOKEN_GITLAB_SECRET",
  "AUTH_GCP_SERVICE_ACCOUNT_SECRET",
] as const;

const CONTAINER_ENV_NAMES = [
  ...CONTAINER_SECRET_NAMES,
  "PSEUDONYMIZE_EMAIL_DOMAINS_ALLOWLIST",
  "AUTH_GCP_SERVICE_ACCOUNT_SCOPES",
] as const;

type ContainerEnvName = (typeof CONTAINER_ENV_NAMES)[number];
type ContainerSecretName = (typeof CONTAINER_SECRET_NAMES)[number];
type SecretStoreBindingName = `SECRET_STORE_${ContainerSecretName}`;

interface SecretStoreBinding {
  get(): Promise<string | null>;
}

const SECRET_STORE_BINDINGS = {
  CLIENT_SECRET: "SECRET_STORE_CLIENT_SECRET",
  PSEUDONYMIZE_SALT: "SECRET_STORE_PSEUDONYMIZE_SALT",
  AUTH_BASIC_AUTH_JIRA_USERNAME: "SECRET_STORE_AUTH_BASIC_AUTH_JIRA_USERNAME",
  AUTH_BASIC_AUTH_JIRA_PASSWORD: "SECRET_STORE_AUTH_BASIC_AUTH_JIRA_PASSWORD",
  AUTH_BEARER_TOKEN_GITHUB_SECRET: "SECRET_STORE_AUTH_BEARER_TOKEN_GITHUB_SECRET",
  AUTH_BEARER_TOKEN_GITLAB_SECRET: "SECRET_STORE_AUTH_BEARER_TOKEN_GITLAB_SECRET",
  AUTH_GCP_SERVICE_ACCOUNT_SECRET: "SECRET_STORE_AUTH_GCP_SERVICE_ACCOUNT_SECRET",
} as const satisfies Record<ContainerSecretName, SecretStoreBindingName>;

export type Env = {
  GUARDETTE_CONTAINER: DurableObjectNamespace<GuardetteContainer>;
  LOG_LEVEL?: string;
  SECRET_MANAGER?: string;
} & Partial<Record<ContainerEnvName, string>> &
  Partial<Record<SecretStoreBindingName, SecretStoreBinding>>;

export class GuardetteContainer extends Container {
  defaultPort = 8000;
  enableInternet = true;
  sleepAfter = "10m";
  pingEndpoint = "localhost/healthz";

  override onStart() {
    console.log({
      event: "guardette.container.started",
      container: CONTAINER_NAME,
    });
  }

  override onStop({ exitCode, reason }: { exitCode: number; reason: string }) {
    console.log({
      event: "guardette.container.stopped",
      container: CONTAINER_NAME,
      exit_code: exitCode,
      reason,
    });
  }

  override onError(error: unknown) {
    console.error({
      event: "guardette.container.error",
      container: CONTAINER_NAME,
      error_type: error instanceof Error ? error.name : "UnknownError",
    });
    throw error;
  }
}

async function resolveSecret(env: Env, name: ContainerSecretName): Promise<string | undefined> {
  const binding = env[SECRET_STORE_BINDINGS[name]];
  if (binding) {
    const value = await binding.get();
    if (value === null) {
      throw new Error(`Cloudflare Secret Store secret is empty: ${name}`);
    }
    return value;
  }

  return env[name];
}

async function containerEnv(env: Env): Promise<Record<string, string>> {
  const values: Record<string, string> = {
    LOG_LEVEL: env.LOG_LEVEL ?? "INFO",
    SECRET_MANAGER: env.SECRET_MANAGER ?? "default",
  };

  for (const name of CONTAINER_SECRET_NAMES) {
    const value = await resolveSecret(env, name);
    if (value !== undefined) {
      values[name] = value;
    }
  }

  for (const name of CONTAINER_ENV_NAMES.slice(CONTAINER_SECRET_NAMES.length)) {
    const value = env[name];
    if (value !== undefined) {
      values[name] = value;
    }
  }

  if (!values.CLIENT_SECRET) {
    throw new Error("Guardette requires CLIENT_SECRET from Cloudflare Secret Store or Worker Secrets");
  }

  return values;
}

function requestPath(request: Request): string {
  return new URL(request.url).pathname;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const requestId = crypto.randomUUID();
    const startedAt = Date.now();

    console.log({
      event: "guardette.request.started",
      request_id: requestId,
      method: request.method,
      path: requestPath(request),
    });

    try {
      const container = env.GUARDETTE_CONTAINER.getByName(CONTAINER_NAME);
      await container.startAndWaitForPorts({
        startOptions: {
          envVars: await containerEnv(env),
        },
      });

      const response = await container.fetch(request);
      console.log({
        event: "guardette.request.completed",
        request_id: requestId,
        status: response.status,
        elapsed_ms: Date.now() - startedAt,
      });
      return response;
    } catch (error) {
      console.error({
        event: "guardette.request.failed",
        request_id: requestId,
        error_type: error instanceof Error ? error.name : "UnknownError",
        elapsed_ms: Date.now() - startedAt,
      });
      throw error;
    }
  },
};
