# DeClaw Secrets - Provider Guide

**`declaw-secrets` supports 5 providers with auto-detection.**

## Quick Start

```bash
# Auto-detect best provider (recommended)
declaw-secrets set SHODAN_API_KEY

# Or specify provider explicitly
declaw-secrets --provider keychain set SHODAN_API_KEY
declaw-secrets --provider vault set SHODAN_API_KEY
```

---

## Provider Comparison

| Provider      | Platform | Dependencies    | Security              | Ease of Use           | Best For        |
| ------------- | -------- | --------------- | --------------------- | --------------------- | --------------- |
| **keychain**  | macOS    | None (built-in) | ⭐⭐⭐⭐⭐ Encrypted  | ⭐⭐⭐⭐⭐ Just works | macOS users     |
| **vault**     | All      | Vault server    | ⭐⭐⭐⭐⭐ Enterprise | ⭐⭐ Complex setup    | Enterprise      |
| **bitwarden** | All      | Bitwarden CLI   | ⭐⭐⭐⭐ Self-hosted  | ⭐⭐⭐ Moderate       | Self-hosters    |
| **1password** | All      | 1Password CLI   | ⭐⭐⭐⭐⭐ Commercial | ⭐⭐⭐⭐ Easy         | 1Password users |
| **env**       | All      | None            | ⭐ Plaintext file     | ⭐⭐⭐⭐⭐ Trivial    | Testing only    |

---

## macOS Keychain (Recommended on Mac)

**Built-in, no dependencies, fully encrypted.**

### Setup

No setup needed! Works out of the box on macOS.

### Usage

```bash
# Auto-detects keychain on Mac
declaw-secrets set SHODAN_API_KEY
# Output: 🔍 Auto-detected provider: keychain
#         ✅ Secret 'SHODAN_API_KEY' stored in macOS Keychain

# Retrieve
declaw-secrets get SHODAN_API_KEY
```

### How it Works

- Secrets stored in macOS Keychain.app
- Service name: `DeClaw`
- Account name: your secret key
- Uses `security` CLI (built into macOS)
- Encrypted at rest with keychain password
- Syncs across devices if iCloud Keychain enabled

### View in Keychain.app

1. Open Keychain Access app
2. Search for "DeClaw"
3. Double-click to view secret
4. Click "Show password" (requires auth)

---

## HashiCorp Vault (Enterprise)

**Industry-standard secrets management.**

### Setup

```bash
# Install Vault
brew install vault

# Start Vault dev server (for testing)
vault server -dev

# Set environment variables
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='<dev-token>'

# Or configure in declaw-secrets
declaw-secrets config --vault-addr http://127.0.0.1:8200
```

### Usage

```bash
# Vault must be running and VAULT_TOKEN set
declaw-secrets --provider vault set SHODAN_API_KEY

# Retrieve
declaw-secrets --provider vault get SHODAN_API_KEY
```

### Configuration

```json
{
  "vault": {
    "addr": "http://127.0.0.1:8200",
    "mount": "secret",
    "path": "declaw"
  }
}
```

Secrets stored at: `secret/declaw/<KEY>`

### Production Setup

For production, use:

- TLS (`https://vault.example.com`)
- AppRole authentication (not root token)
- Policies for least-privilege access

See: https://learn.hashicorp.com/vault

---

## Bitwarden CLI (Self-Hosted)

**Open source, self-hostable.**

### Setup

```bash
# Install Bitwarden CLI
brew install bitwarden-cli

# Or download from: https://bitwarden.com/download/

# Login
bw login
bw unlock
# Copy session key to env

export BW_SESSION="<session-key>"
```

### Usage

```bash
declaw-secrets --provider bitwarden set SHODAN_API_KEY

# Retrieve
declaw-secrets --provider bitwarden get SHODAN_API_KEY
```

### Self-Hosting with Vaultwarden

```bash
# Run Vaultwarden (lightweight Bitwarden server)
docker run -d \
  -p 8080:80 \
  -v bw-data:/data \
  vaultwarden/server:latest

# Configure Bitwarden CLI to use self-hosted
bw config server http://localhost:8080
```

---

## 1Password CLI (Commercial)

**Commercial password manager with CLI.**

### Setup

```bash
# Install 1Password CLI
brew install --cask 1password-cli

# Or download from: https://1password.com/downloads/command-line/

# Sign in
eval $(op signin)

# Create vault (optional)
op vault create DeClaw
```

### Usage

```bash
declaw-secrets --provider 1password set SHODAN_API_KEY

# Retrieve
declaw-secrets --provider 1password get SHODAN_API_KEY
```

### Configuration

```json
{
  "1password": {
    "vault": "DeClaw"
  }
}
```

---

## Environment File (Fallback Only)

**Plaintext file - NOT SECURE for production.**

### Setup

No setup needed.

### Usage

```bash
declaw-secrets --provider env set SHODAN_API_KEY
# Output: ⚠️  WARNING: .env file is NOT SECURE - use keychain/vault for production

# Stored in: ~/.declaw/secrets.env
```

### Security

- File permissions: 600 (user read/write only)
- **NOT encrypted** - plaintext on disk
- Still extractable if agent compromised
- Only use for testing/development

---

## Provider Auto-Detection

When you don't specify `--provider`, `declaw-secrets` auto-detects the best available provider:

**Priority order:**

1. **keychain** (if on macOS)
2. **vault** (if Vault CLI installed)
3. **bitwarden** (if Bitwarden CLI installed)
4. **1password** (if 1Password CLI installed)
5. **env** (fallback)

```bash
# Check what will be used
declaw-secrets providers

# Output:
# ✅ keychain     - macOS Keychain (built-in, recommended on Mac)
# ❌ vault        - HashiCorp Vault (not available)
# ❌ bitwarden    - Bitwarden CLI (not installed)
# ✅ 1password    - 1Password CLI (available)
# ✅ env          - Environment file (always available)
```

---

## Configuration File

Config stored at: `~/.declaw/secrets-config.json`

```json
{
  "provider": null, // null = auto-detect
  "vault": {
    "addr": "http://127.0.0.1:8200",
    "mount": "secret",
    "path": "declaw"
  },
  "1password": {
    "vault": "DeClaw"
  }
}
```

Update with:

```bash
declaw-secrets config --provider keychain
declaw-secrets config --vault-addr https://vault.example.com
```

---

## Migrating Between Providers

```bash
# Export from env file
for key in $(declaw-secrets --provider env list | tail -n +2 | sed 's/  - //'); do
  value=$(declaw-secrets --provider env get $key)
  declaw-secrets --provider keychain set $key "$value"
done

# Verify
declaw-secrets --provider keychain list
```

---

## Security Comparison

### Threat: Agent reads secret from storage

| Provider  | Protected? | How?                                  |
| --------- | ---------- | ------------------------------------- |
| keychain  | ✅ Yes     | Keychain requires user auth to access |
| vault     | ✅ Yes     | Vault token required, can be revoked  |
| bitwarden | ✅ Yes     | Session key required                  |
| 1password | ✅ Yes     | Must be signed in                     |
| env       | ❌ No      | File readable by agent user           |

### Threat: Disk compromise (stolen laptop)

| Provider  | Protected? | How?                                               |
| --------- | ---------- | -------------------------------------------------- |
| keychain  | ✅ Yes     | Encrypted with FileVault + keychain password       |
| vault     | ✅ Yes     | Vault storage encrypted at rest                    |
| bitwarden | ✅ Yes     | Vault encrypted with master password               |
| 1password | ✅ Yes     | Vault encrypted with account password + Secret Key |
| env       | ❌ No      | Plaintext on disk                                  |

### Threat: Prompt injection

**All providers mitigate this** by not storing secrets in agent-accessible env vars. Secrets must be fetched on-demand with provider auth.

---

## Audit Logging

All providers log to: `~/.declaw/audit.log`

Example:

```json
{
  "timestamp": "2026-02-10T03:47:17Z",
  "event_type": "secret_access",
  "action": "get",
  "key": "SHODAN_API_KEY",
  "success": true,
  "provider": "keychain",
  "pid": 12345,
  "user": "tomstetson"
}
```

Query logs:

```bash
# All access
declaw-secrets audit

# Filter by key
declaw-secrets audit --key SHODAN_API_KEY

# Output:
# 2026-02-10T03:47:17Z ✅ get SHODAN_API_KEY (keychain)
```

---

## Recommendations

### For Personal Use (macOS)

→ Use **keychain** (auto-detected, no setup)

### For Personal Use (Linux/Windows)

→ Use **bitwarden** (free, self-hostable) or **1password** (commercial)

### For Enterprise

→ Use **vault** (centralized, audited, policy-driven)

### For Testing

→ Use **env** (fast, disposable) but **never in production**

---

## Troubleshooting

### "❌ Not signed in to 1Password CLI"

```bash
eval $(op signin)
```

### "❌ VAULT_TOKEN not set"

```bash
export VAULT_TOKEN="<your-token>"
```

### "❌ Bitwarden CLI not logged in"

```bash
bw login
bw unlock
export BW_SESSION="<session-key>"
```

### "Secret not found" but it exists

Check you're using the same provider:

```bash
# List secrets by provider
declaw-secrets --provider keychain list
declaw-secrets --provider env list
```

---

## Future Providers (Roadmap)

- **AWS Secrets Manager** (cloud-native for AWS)
- **Azure Key Vault** (cloud-native for Azure)
- **Google Secret Manager** (cloud-native for GCP)
- **pass** (standard Unix password manager)
- **systemd credentials** (Linux built-in)

---

**DeClaw Secrets** - Multi-provider, auto-detecting, audit-logged secrets management.
