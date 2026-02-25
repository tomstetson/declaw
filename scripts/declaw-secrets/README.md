# DeClaw Secrets Manager

Secure secrets management for OpenClaw AI agents. Eliminates plaintext API keys in environment variables.

## The Problem

**OpenClaw stores API keys in plaintext:**

```json
{
  "agents": {
    "list": [{
      "sandbox": {
        "docker": {
          "env": {
            "SHODAN_API_KEY": "sk_abc123..."  ← Extractable via env/printenv
          }
        }
      }
    }]
  }
}
```

**A single prompt injection extracts all secrets:**

```python
# Attacker's injected code
import os
print(dict(os.environ))  # Leaks all API keys
```

## The Solution

**Store secrets in 1Password/Vault, retrieve on-demand:**

```bash
# Store secret once
declaw-secrets set SHODAN_API_KEY

# Retrieve when needed (in OpenClaw exec commands)
export SHODAN_API_KEY=$(declaw-secrets get SHODAN_API_KEY)
shodan search apache
```

**All access is logged:**

```
2026-02-09T03:22:15Z ✅ get SHODAN_API_KEY
```

---

## Installation

### Quick Install (Standalone Script)

```bash
# Copy to your PATH
curl -o /usr/local/bin/declaw-secrets \
  https://raw.githubusercontent.com/tomstetson/declaw-patterns/main/scripts/declaw-secrets/declaw-secrets
chmod +x /usr/local/bin/declaw-secrets
```

### Install 1Password CLI (Recommended Provider)

```bash
# macOS
brew install --cask 1password-cli

# Or download from: https://1password.com/downloads/command-line/

# Sign in
eval $(op signin)
```

---

## Usage

### Basic Commands

```bash
# Store a secret
declaw-secrets set SHODAN_API_KEY
# Prompts: Enter value for SHODAN_API_KEY: sk_abc123...
# Output: ✅ Secret 'SHODAN_API_KEY' stored in 1Password vault 'DeClaw'

# Retrieve a secret
declaw-secrets get SHODAN_API_KEY
# Output: sk_abc123...

# List all secrets
declaw-secrets list
# Output:
# Secrets in 1password:
#   - SHODAN_API_KEY
#   - CENSYS_API_KEY
#   - FASTMAIL_PASSWORD

# View audit log
declaw-secrets audit
# Output:
# 2026-02-09T03:22:15Z ✅ get SHODAN_API_KEY
# 2026-02-09T03:23:42Z ✅ set CENSYS_API_KEY
```

### Use in OpenClaw SOUL.md

Add this pattern to your agent's SOUL.md or tool scripts:

````markdown
## API Key Usage Pattern

**NEVER use env vars directly**. Instead:

1. Fetch secret on-demand:
   ```bash
   export SHODAN_API_KEY=$(declaw-secrets get SHODAN_API_KEY)
   ```
````

2. Use immediately:

   ```bash
   shodan search apache
   ```

3. Unset after use:
   ```bash
   unset SHODAN_API_KEY
   ```

This ensures secrets are:

- ✅ Not persisted in container env
- ✅ Logged every time they're accessed
- ✅ Scoped to single command execution

````

### Configuration

```bash
# Configure provider and vault
declaw-secrets config --provider 1password --vault "My DeClaw Vault"

# Or use environment variables
export DECLAW_SECRETS_PROVIDER=1password
export DECLAW_SECRETS_VAULT="DeClaw"
````

---

## Providers

### 1Password CLI (Recommended)

**Pros:**

- ✅ Encrypted at rest
- ✅ Cross-device sync
- ✅ Audit logging
- ✅ MFA support
- ✅ Widely trusted

**Setup:**

```bash
# Install
brew install --cask 1password-cli

# Create vault (one-time)
op vault create DeClaw

# Store secret
declaw-secrets set SHODAN_API_KEY
```

**How it works:**

- Secrets stored as items in 1Password vault
- Retrieved via `op read op://DeClaw/SHODAN_API_KEY/password`
- Requires 1Password CLI to be signed in

---

### Environment File (Fallback, Not Recommended)

**For testing only. Not secure for production.**

```bash
# Use env file provider
declaw-secrets --provider env set SHODAN_API_KEY

# Stored in: ~/.declaw/secrets.env
# Permissions: 0600 (user read/write only)
```

**Why not recommended:**

- ❌ Plaintext file on disk
- ❌ No encryption at rest
- ❌ No MFA
- ❌ Limited audit trail

---

### HashiCorp Vault (Future)

Coming soon. Use 1Password for now.

---

## Audit Logging

All secret access is logged to `~/.declaw/audit.log` (JSONL format):

```json
{
  "timestamp": "2026-02-09T03:22:15Z",
  "event_type": "secret_access",
  "action": "get",
  "key": "SHODAN_API_KEY",
  "success": true,
  "provider": "1password",
  "pid": 12345,
  "user": "tomstetson"
}
```

**Query audit log:**

```bash
# All accesses
declaw-secrets audit

# Filter by key
declaw-secrets audit --key SHODAN_API_KEY

# Filter by timeframe (coming soon)
declaw-secrets audit --since 24h
```

---

## Integration with OpenClaw

### Option 1: Wrapper Scripts

Create wrapper scripts that fetch secrets before running tools:

```bash
# ~/scripts/shodan-search.sh
#!/bin/bash
export SHODAN_API_KEY=$(declaw-secrets get SHODAN_API_KEY)
shodan "$@"
unset SHODAN_API_KEY
```

Reference in SOUL.md:

```markdown
## Tools

- **shodan-search.sh** - Shodan CLI with automatic secret injection
```

---

### Option 2: Pre-Exec Hook (Future)

When DeClaw fork is ready, secrets will be fetched automatically:

```json
{
  "agents": {
    "list": [{
      "env": {
        "SHODAN_API_KEY": "secret://SHODAN_API_KEY"  ← Auto-fetched
      }
    }]
  }
}
```

---

## Security Features

1. **Secrets never in plaintext config**
   - Stored in 1Password vault (encrypted)
   - Retrieved on-demand only

2. **Audit logging**
   - Every access logged with timestamp
   - User, PID, success/failure tracked
   - Queryable audit trail

3. **Ephemeral exposure**
   - Secrets fetched per-command
   - Not persisted in container env
   - Unset after use

4. **Provider abstraction**
   - Switch providers without code changes
   - Upgrade from env file → 1Password seamlessly

---

## Threat Model

### ❌ What This PREVENTS:

1. **Prompt injection extracting env vars**
   - Attacker: `exec("printenv | grep KEY")`
   - Defense: No keys in env to extract

2. **Config file exposure**
   - Attacker reads `openclaw.json`
   - Defense: Only references to secrets, not values

3. **Long-lived credential theft**
   - Attacker exfiltrates env snapshot
   - Defense: Secrets fetched on-demand, short-lived

### ⚠️ What This DOES NOT PREVENT:

1. **Secrets used after retrieval**
   - If agent runs `shodan search`, Shodan key is in memory
   - Attacker could still read memory (but much harder)

2. **Malicious commands after secret fetch**
   - Agent fetches key, then runs attacker's command
   - Mitigation: Command allowlist (coming in DeClaw fork)

3. **1Password CLI compromise**
   - If `op` binary is malicious, secrets exposed
   - Mitigation: Verify 1Password CLI signature

---

## Roadmap

### v1.0 (Current)

- ✅ 1Password CLI integration
- ✅ Environment file fallback
- ✅ Audit logging
- ✅ Basic CLI commands (get, set, list, audit)

### v1.1 (Next)

- [ ] HashiCorp Vault provider
- [ ] AWS Secrets Manager provider
- [ ] Audit log time filtering (`--since 24h`)
- [ ] Secret rotation reminders

### v2.0 (DeClaw Fork Integration)

- [ ] Auto-fetch on agent startup
- [ ] Config schema validation
- [ ] Canary token detection
- [ ] Real-time alerting on suspicious access

---

## FAQ

**Q: Why not just use env files with restrictive permissions?**
A: Permissions don't prevent the agent itself from reading the file. Prompt injection gives attacker code execution within the agent's context.

**Q: Can I use this with OpenClaw today?**
A: Yes! It's a standalone tool. Create wrapper scripts that call `declaw-secrets get` before running commands.

**Q: Does this work with the OpenClaw browser tool?**
A: Not directly. Browser tool doesn't execute bash commands. This is for exec-based workflows. Full integration coming in DeClaw fork.

**Q: What if 1Password CLI breaks or is unavailable?**
A: Fallback to env file provider temporarily, but rotate keys after (since they were in plaintext).

**Q: Is the audit log encrypted?**
A: No, but it doesn't contain secret values, only metadata (which key was accessed, when, by whom).

---

## Contributing

This tool will eventually be integrated into the DeClaw fork. For now, it's standalone.

**Report issues:** https://github.com/tomstetson/declaw-patterns/issues
**Pull requests:** https://github.com/tomstetson/declaw-patterns/pulls

---

## License

MIT License - See repository root for full text.

---

**DeClaw** - Assume your AI agent will be compromised, and design accordingly.
