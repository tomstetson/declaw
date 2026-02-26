/**
 * Environment variable and secrets substitution for config values.
 *
 * Supports two substitution patterns:
 * 1. `${VAR_NAME}` - Environment variable substitution
 *    - Only uppercase env vars are matched: `[A-Z_][A-Z0-9_]*`
 *    - Escape with `$${}` to output literal `${}`
 *    - Missing env vars throw `MissingEnvVarError`
 *
 * 2. `secret://SECRET_NAME` - DeClaw secrets manager (full value only)
 *    - Calls declaw-secrets to retrieve vault-stored secrets
 *    - Missing secrets throw `SecretNotFoundError`
 *    - Only works when value is exactly "secret://NAME" (not embedded)
 *
 * @example
 * ```json5
 * {
 *   models: {
 *     providers: {
 *       "vercel-gateway": {
 *         apiKey: "${VERCEL_GATEWAY_API_KEY}"
 *       },
 *       "anthropic": {
 *         apiKey: "secret://ANTHROPIC_API_KEY"
 *       }
 *     }
 *   }
 * }
 * ```
 */

import { isSecretUri, parseSecretUri, resolveSecret } from "../lib/secrets.js";
// Pattern for valid uppercase env var names: starts with letter or underscore,
// followed by letters, numbers, or underscores (all uppercase)
import { isPlainObject } from "../utils.js";

// Re-export secret errors for convenience
export { SecretNotFoundError, SecretsManagerNotAvailableError } from "../lib/secrets.js";

const ENV_VAR_NAME_PATTERN = /^[A-Z_][A-Z0-9_]*$/;

export class MissingEnvVarError extends Error {
  constructor(
    public readonly varName: string,
    public readonly configPath: string,
  ) {
    super(`Missing env var "${varName}" referenced at config path: ${configPath}`);
    this.name = "MissingEnvVarError";
  }
}

type EnvToken =
  | { kind: "escaped"; name: string; end: number }
  | { kind: "substitution"; name: string; end: number };

function parseEnvTokenAt(value: string, index: number): EnvToken | null {
  if (value[index] !== "$") {
    return null;
  }

  const next = value[index + 1];
  const afterNext = value[index + 2];

  // Escaped: $${VAR} -> ${VAR}
  if (next === "$" && afterNext === "{") {
    const start = index + 3;
    const end = value.indexOf("}", start);
    if (end !== -1) {
      const name = value.slice(start, end);
      if (ENV_VAR_NAME_PATTERN.test(name)) {
        return { kind: "escaped", name, end };
      }
    }
  }

  // Substitution: ${VAR} -> value
  if (next === "{") {
    const start = index + 2;
    const end = value.indexOf("}", start);
    if (end !== -1) {
      const name = value.slice(start, end);
      if (ENV_VAR_NAME_PATTERN.test(name)) {
        return { kind: "substitution", name, end };
      }
    }
  }

  return null;
}

function substituteString(value: string, env: NodeJS.ProcessEnv, configPath: string): string {
  // Check for secret:// URI first (must be exact match, not embedded)
  if (isSecretUri(value)) {
    const secretName = parseSecretUri(value);
    if (secretName) {
      return resolveSecret(secretName, configPath);
    }
    // Value starts with secret:// but has an invalid name — fail loudly so the
    // user gets a clear error instead of a cryptic API auth failure downstream.
    throw new Error(
      `Invalid secret URI "${value}" at config path "${configPath}". ` +
        `Secret names must match [A-Za-z0-9_-]+. Example: secret://MY_API_KEY`,
    );
  }

  if (!value.includes("$")) {
    return value;
  }

  const chunks: string[] = [];

  for (let i = 0; i < value.length; i += 1) {
    const char = value[i];
    if (char !== "$") {
      chunks.push(char);
      continue;
    }

    const token = parseEnvTokenAt(value, i);
    if (token?.kind === "escaped") {
      chunks.push(`\${${token.name}}`);
      i = token.end;
      continue;
    }
    if (token?.kind === "substitution") {
      const envValue = env[token.name];
      if (envValue === undefined || envValue === "") {
        throw new MissingEnvVarError(token.name, configPath);
      }
      chunks.push(envValue);
      i = token.end;
      continue;
    }

    // Leave untouched if not a recognized pattern
    chunks.push(char);
  }

  return chunks.join("");
}

export function containsEnvVarReference(value: string): boolean {
  if (!value.includes("$")) {
    return false;
  }

  for (let i = 0; i < value.length; i += 1) {
    const char = value[i];
    if (char !== "$") {
      continue;
    }

    const token = parseEnvTokenAt(value, i);
    if (token?.kind === "escaped") {
      i = token.end;
      continue;
    }
    if (token?.kind === "substitution") {
      return true;
    }
  }

  return false;
}

function substituteAny(value: unknown, env: NodeJS.ProcessEnv, path: string): unknown {
  if (typeof value === "string") {
    return substituteString(value, env, path);
  }

  if (Array.isArray(value)) {
    return value.map((item, index) => substituteAny(item, env, `${path}[${index}]`));
  }

  if (isPlainObject(value)) {
    const result: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(value)) {
      const childPath = path ? `${path}.${key}` : key;
      result[key] = substituteAny(val, env, childPath);
    }
    return result;
  }

  // Primitives (number, boolean, null) pass through unchanged
  return value;
}

/**
 * Resolves config value substitutions:
 * - `${VAR_NAME}` environment variable references
 * - `secret://SECRET_NAME` DeClaw secrets manager URIs
 *
 * @param obj - The parsed config object (after JSON5 parse and $include resolution)
 * @param env - Environment variables to use for ${} substitution (defaults to process.env)
 * @returns The config object with substitutions resolved
 * @throws {MissingEnvVarError} If a referenced env var is not set or empty
 * @throws {SecretNotFoundError} If a referenced secret doesn't exist
 * @throws {SecretsManagerNotAvailableError} If declaw-secrets is not available
 */
export function resolveConfigEnvVars(obj: unknown, env: NodeJS.ProcessEnv = process.env): unknown {
  return substituteAny(obj, env, "");
}
