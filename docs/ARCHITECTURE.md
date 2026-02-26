# DeClaw Architecture

DeClaw adds security layers to OpenClaw's config loading pipeline, startup
validation, and runtime monitoring. This document covers only the DeClaw-specific
architecture. For upstream OpenClaw internals, see the OpenClaw docs.

## Config Loading Pipeline

DeClaw hooks into OpenClaw's config loading at step 5 below. The `secret://`
check runs before `${}` env var substitution so vault-stored secrets take
priority over environment variables.

```mermaid
flowchart TD
    A["CLI: openclaw gateway run"] --> B["loadConfig()"]
    B --> C["Read ~/.openclaw/openclaw.json (JSON5)"]
    C --> D["Resolve $include directives"]
    D --> E["applyConfigEnvVars (config.env -> process.env)"]
    E --> F["resolveConfigEnvVars"]

    F --> G{For each string value}
    G -->|"starts with secret://"| H["isSecretUri() + parseSecretUri()"]
    G -->|"contains ${}"| I["parseEnvTokenAt()"]
    G -->|"plain string"| J["pass through"]

    H --> K["resolveSecret()
    src/lib/secrets.ts"]
    K --> L["execSync: declaw-secrets get NAME
    5s timeout"]
    L --> M["Python: auto-detect provider"]
    M --> N["Provider.get(key)"]
    N --> O["Return secret value"]

    I --> P["Lookup process.env[VAR]"]

    O --> Q["Substituted config object"]
    P --> Q
    J --> Q

    Q --> R["validateConfigObjectWithPlugins()"]
    R --> S["Apply defaults + normalize paths"]
    S --> T["Gateway initialized with resolved config"]

    style H fill:#e6f3ff,stroke:#0066cc
    style K fill:#e6f3ff,stroke:#0066cc
    style L fill:#e6f3ff,stroke:#0066cc
    style M fill:#e6f3ff,stroke:#0066cc
    style N fill:#e6f3ff,stroke:#0066cc
    style O fill:#e6f3ff,stroke:#0066cc
```

**Key files:**

- `src/config/io.ts` -- Config orchestrator (loadConfig, include resolution, validation)
- `src/config/env-substitution.ts` -- `substituteString()` with secret:// check (lines 91-99)
- `src/lib/secrets.ts` -- TypeScript bridge to Python via execSync
- `scripts/declaw-secrets/declaw-secrets` -- Multi-provider secrets manager

## Secrets Provider Architecture

The secrets manager uses an abstract provider pattern with auto-detection.
On first call, it checks providers in priority order and uses the first
available one.

```mermaid
classDiagram
    class SecretProvider {
        <<abstract>>
        +get(key) str
        +set(key, value)
        +list_keys() list
        +is_available() bool
    }

    class KeychainProvider {
        SERVICE_NAME = "DeClaw"
        +get(key): security find-generic-password
        +set(key, value): security add-generic-password
        +is_available(): platform == Darwin
    }

    class VaultProvider {
        addr: str
        token: str
        mount: str = "secret"
        path: str = "declaw"
        +get(key): vault kv get
        +set(key, value): vault kv put
        +is_available(): vault version succeeds
    }

    class BitwardenProvider {
        +get(key): bw get password
        +set(key, value): bw create item
        +is_available(): bw --version succeeds
    }

    class OnePasswordProvider {
        vault: str = "DeClaw"
        +get(key): op read
        +set(key, value): op item create
        +is_available(): op --version succeeds
    }

    class EnvFileProvider {
        file: ~/.declaw/secrets.env
        +get(key): parse KEY=VALUE lines
        +set(key, value): append to file
        +is_available(): always true
    }

    class SecretsManager {
        providers: list
        config: ~/.declaw/secrets-config.json
        audit_log: ~/.declaw/audit.log
        +get(key)
        +set(key, value)
        +list_keys()
        -auto_detect_provider()
        -_log_access()
    }

    SecretProvider <|-- KeychainProvider
    SecretProvider <|-- VaultProvider
    SecretProvider <|-- BitwardenProvider
    SecretProvider <|-- OnePasswordProvider
    SecretProvider <|-- EnvFileProvider
    SecretsManager --> SecretProvider : uses first available
```

**Auto-detection priority:** Keychain > Vault > Bitwarden > 1Password > EnvFile

## Security Tools Overview

Three standalone Python tools provide defense-in-depth at different stages:

```mermaid
flowchart LR
    subgraph "Pre-Start"
        A["declaw-doctor
        Config Validator"]
    end

    subgraph "Startup"
        B["declaw-secrets
        Secret Resolution"]
    end

    subgraph "Runtime"
        C["declaw-monitor
        Anomaly Detection"]
    end

    A -->|"validates config"| D["~/.openclaw/openclaw.json"]
    B -->|"resolves secret:// URIs"| D
    D --> E["OpenClaw Gateway"]
    E -->|"spawns"| F["Agent Sessions"]
    F -->|"writes transcripts"| G["~/.openclaw/agents/*/sessions/*.jsonl"]
    C -->|"tail -f watches"| G

    C -->|"CRITICAL: kill"| H["docker kill container"]
    C -->|"HIGH+: alert"| I["~/.declaw/monitor-audit.log"]
    A -->|"audit results"| J["stdout (pass/fail)"]
    B -->|"all accesses"| K["~/.declaw/audit.log"]

    style A fill:#fff3e6,stroke:#cc6600
    style B fill:#e6f3ff,stroke:#0066cc
    style C fill:#ffe6e6,stroke:#cc0000
```

## declaw-doctor Check Matrix

| ID  | Check                               | Severity | Auto-Fix                 |
| --- | ----------------------------------- | -------- | ------------------------ |
| C1  | Gateway auth token (32+ chars)      | CRITICAL | Generate random token    |
| C2  | API keys in env vars (no secret://) | CRITICAL | No (requires migration)  |
| C3  | Sandbox mode enabled                | CRITICAL | Set mode to "all"        |
| H1  | Dangerous tools in allow list       | HIGH     | Remove dangerous entries |
| H2  | Exec approvals enabled              | HIGH     | Enable with targets      |
| H3  | readOnlyRoot on containers          | HIGH     | Set to true              |
| M1  | Context pruning enabled             | MEDIUM   | Set mode to "cache-ttl"  |
| M2  | Gateway bind (loopback or TLS)      | MEDIUM   | No (requires TLS setup)  |
| M3  | Capability drop on containers       | MEDIUM   | Set capDrop to ["ALL"]   |
| L1  | Reload mode (hot + debounce)        | LOW      | Set mode to "hot"        |

## declaw-monitor Detection Patterns

| Pattern          | Severity | Action | What It Detects                                       |
| ---------------- | -------- | ------ | ----------------------------------------------------- |
| ENV_ACCESS       | CRITICAL | kill   | `printenv`, `env`, `os.environ`, `/proc/self/environ` |
| BASE64_ENCODE    | CRITICAL | kill   | `base64`, `xxd`, `openssl enc`, `btoa`                |
| REVERSE_SHELL    | CRITICAL | kill   | `bash -i`, `python pty.spawn`                         |
| DOCKER_ESCAPE    | CRITICAL | kill   | `docker.sock`, `runc`, `cgroups`                      |
| EXFIL_TOOLS      | HIGH     | alert  | `curl -d`, `wget --post`, `nc -e`, `socat`            |
| CRED_SCAN        | HIGH     | alert  | `grep password`, `find .ssh`, `cat /etc/shadow`       |
| SUSPICIOUS_FILES | MEDIUM   | alert  | `rm -rf`, `chmod 777`, `dd if=`                       |
| PORT_SCAN        | MEDIUM   | alert  | `nmap`, `masscan`, `zmap`                             |
| API_SPAM         | LOW      | alert  | Excessive `web_fetch`, `web_search` calls             |
| LARGE_WRITE      | LOW      | alert  | `dd bs=`, `fallocate`, `truncate`                     |

CRITICAL patterns trigger the kill switch (if enabled): container killed,
block file created at `~/.declaw/AGENT_ID.blocked`, restart prevented.

## File System Layout

```
~/.openclaw/                        # OpenClaw config + data
  openclaw.json                     # Config (read by doctor, secrets resolver)
  agents/
    AGENT_ID/
      sessions/*.jsonl              # Transcripts (watched by monitor)

~/.declaw/                          # DeClaw local state
  secrets-config.json               # Provider config (vault addr, 1password vault)
  secrets.env                       # Fallback plaintext secrets (chmod 600)
  audit.log                         # Secret access audit trail (JSONL)
  monitor-audit.log                 # Detection audit trail (JSONL)
  AGENT_ID.blocked                  # Kill switch block files

project/                            # DeClaw repo
  src/lib/secrets.ts                # TypeScript bridge (execSync to Python)
  src/config/env-substitution.ts    # secret:// integration point
  scripts/declaw-secrets/           # Python secrets manager
  scripts/declaw-doctor/            # Python config validator
  scripts/declaw-monitor/           # Python anomaly detector
```

## Command Policy Enforcement (Phase 2)

DeClaw's command policy runs at the top of the exec handler — before host
routing, before the existing allowlist evaluation, before approval registration.
A denied command cannot be bypassed by user approval.

```mermaid
flowchart TD
    A["Agent calls exec tool"] --> B["createExecTool().execute()"]
    B --> C{"DeClaw command policy
    evaluateDeclawCommandPolicy()"}
    C -->|"denied"| D["Error: exec denied by
    DeClaw command policy"]
    C -->|"allowed / off"| E{"Host routing"}
    E -->|"sandbox"| F["Docker container exec"]
    E -->|"gateway"| G["processGatewayAllowlist()
    (OpenClaw allowlist + approvals)"]
    E -->|"node"| H["Remote node exec"]

    style C fill:#fff3cd,stroke:#856404
    style D fill:#ffe6e6,stroke:#cc0000
```

Config: `tools.exec.commandPolicy` (global) or per-agent override.

## Egress Policy Enforcement (Phase 2)

Egress policy enforcement hooks into `resolveSandboxDockerConfig()`, modifying
the Docker config before the container is created. The `deny-all` mode forces
`network=none` regardless of other settings.

```mermaid
flowchart TD
    A["openclaw.json"] --> B["resolveSandboxDockerConfig()"]
    B --> C{"egressPolicy set?"}
    C -->|"no"| D["Pass through
    (default: network=none)"]
    C -->|"yes"| E{"egressPolicy.mode"}
    E -->|"deny-all"| F["Force network=none
    Strip DNS/hosts"]
    E -->|"restricted"| G["Keep network mode
    Apply allowed DNS/hosts"]
    E -->|"unrestricted"| H["Pass through
    Log warning"]
    F --> I["buildSandboxCreateArgs()
    docker create --network none"]
    G --> I
    H --> I
    D --> I

    style F fill:#d4edda,stroke:#155724
    style H fill:#ffe6e6,stroke:#cc0000
```

Config: `agents.defaults.sandbox.docker.egressPolicy` or per-agent override.

## Webhook Alert Dispatch (Phase 2)

When `declaw-monitor` detects an anomaly, `AlertDispatcher` routes alerts to
one or more destinations based on URL scheme:

```mermaid
flowchart TD
    A["_handle_detection()"] --> B{"pattern.action?"}
    B -->|"kill + kill_switch"| C["_kill_container()"]
    C --> D["_send_alert(action='kill')"]
    B -->|"alert"| E["_send_alert(action='alert')"]

    D --> F["AlertDispatcher.send()"]
    E --> F

    F --> G["For each destination URL"]
    G --> H{"URL scheme?"}
    H -->|"telegram://"| I["Telegram Bot API
    POST /sendMessage"]
    H -->|"slack:// or hooks.slack.com"| J["Slack Incoming Webhook
    POST JSON"]
    H -->|"smtp://"| K["SMTP + STARTTLS
    MIMEText email"]
    H -->|"https://"| L["Generic Webhook
    POST JSON"]
    H -->|"unknown"| M["Skip + warn"]

    I & J & K & L -->|"failure"| N["Retry once after 2s"]
    N -->|"still fails"| O["Increment fail_count"]
    I & J & K & L -->|"success"| P["Increment send_count"]

    style C fill:#ffe6e6,stroke:#cc0000
    style M fill:#fff3cd,stroke:#856404
```

Config: `declaw-monitor monitor --webhook "telegram://BOT@CHAT, https://hook.example.com"`

## Plugin Security Scanning (Phase 2)

DeClaw wraps OpenClaw's existing `skill-scanner` and adds policy enforcement,
capability restriction, integrity verification, and sandbox compatibility:

```mermaid
flowchart TD
    A["Plugin Install / Load"] --> B["skill-scanner
    scanDirectoryWithSummary()"]
    B --> C["SkillScanSummary
    (findings, counts)"]
    C --> D["evaluatePluginSecurity()"]

    D --> E{"Policy mode?"}
    E -->|"off"| F["Allow (no enforcement)"]
    E -->|"warn"| G["Allow + log warnings"]
    E -->|"enforce"| H{"Violations?"}

    H -->|"critical > max"| I["DENY: critical findings"]
    H -->|"blocked capability"| J["DENY: capability violation"]
    H -->|"clean"| K["Allow"]

    C --> L["checkSandboxCompatibility()"]
    L --> M{"Plugin needs vs sandbox?"}
    M -->|"network + none"| N["Incompatible"]
    M -->|"exec + capDrop ALL"| N
    M -->|"no conflicts"| O["Compatible"]

    style I fill:#ffe6e6,stroke:#cc0000
    style J fill:#ffe6e6,stroke:#cc0000
    style N fill:#fff3cd,stroke:#856404
```

Capabilities are mapped from skill-scanner rule IDs: `dangerous-exec` → exec,
`suspicious-network`/`potential-exfiltration` → network, `env-harvesting` → env,
`dynamic-code-execution` → eval, `crypto-mining` → crypto-mining.

Config: `plugins.pluginSecurity` in `openclaw.json`.

## Error Handling

Secret resolution errors fail fast (no silent fallback):

```mermaid
flowchart TD
    A["resolveSecret(name, path)"] --> B["execSync: declaw-secrets get NAME"]
    B -->|"stdout non-empty"| C["Return trimmed value"]
    B -->|"stdout empty"| D["SecretNotFoundError
    'Run: declaw-secrets set NAME'"]
    B -->|"stderr: 'not found'"| D
    B -->|"stderr: 'does not exist'"| D
    B -->|"ENOENT / timeout"| E["SecretsManagerNotAvailableError
    'Install: npm install -g declaw'"]

    D --> F["Gateway refuses to start"]
    E --> F

    style D fill:#ffe6e6,stroke:#cc0000
    style E fill:#ffe6e6,stroke:#cc0000
    style F fill:#ffe6e6,stroke:#cc0000
```
