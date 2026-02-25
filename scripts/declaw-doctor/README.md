# DeClaw Doctor - OpenClaw Security Auditor

Identifies misconfigurations and security issues in OpenClaw configs.

## Quick Start

```bash
# Audit your config
declaw-doctor ~/.openclaw/openclaw.json

# Auto-fix issues
declaw-doctor ~/.openclaw/openclaw.json --fix

# Dry run (show what would be fixed)
declaw-doctor ~/.openclaw/openclaw.json --fix --dry-run
```

---

## What It Checks

### CRITICAL Issues

| ID  | Check                             | Auto-Fix                   |
| --- | --------------------------------- | -------------------------- |
| C1  | Gateway auth token missing/weak   | ✅ Yes                     |
| C2  | API keys in environment variables | ❌ No (use declaw-secrets) |
| C3  | Sandbox disabled                  | ✅ Yes                     |

### HIGH Severity

| ID  | Check                   | Auto-Fix   |
| --- | ----------------------- | ---------- |
| H1  | Dangerous tools allowed | ✅ Yes     |
| H2  | Exec approvals disabled | ✅ Partial |
| H3  | readOnlyRoot disabled   | ✅ Yes     |

### MEDIUM Severity

| ID  | Check                            | Auto-Fix             |
| --- | -------------------------------- | -------------------- |
| M1  | Context pruning disabled         | ✅ Yes               |
| M2  | Gateway non-loopback without TLS | ❌ No (manual setup) |
| M3  | No capability drop               | ✅ Yes               |

### LOW Priority

| ID  | Check                          | Auto-Fix |
| --- | ------------------------------ | -------- |
| L1  | Gateway reload race conditions | ✅ Yes   |

---

## Example Output

```
============================================================
🔍 DeClaw Security Audit Report
============================================================

❌ CRITICAL & HIGH ISSUES:

🚨 [C2] API keys stored in environment variables
   Agent 'jebnick' has 'SHODAN_API_KEY' in env (use declaw-secrets)

🚨 [C3] Sandbox disabled for one or more agents [AUTO-FIXABLE]
   Agent 'main' has sandbox=off

⚠️  [H3] readOnlyRoot disabled (allows persistent malware) [AUTO-FIXABLE]
   Agent 'main' has writable root filesystem

⚠️  MEDIUM WARNINGS:

⚠️  [M1] Context pruning not enabled (risk of overflow) [AUTO-FIXABLE]
   Context pruning disabled (risk of 200K token overflow)

============================================================
Score: 1/5 checks passed
  - 2 critical/high issues
  - 1 medium warnings
  - 0 low priority items

💡 3 issue(s) can be auto-fixed with: declaw-doctor --fix
============================================================
```

---

## Auto-Fix Details

### What Gets Fixed

**C1: Gateway Token**

- Generates 64-char hex token
- Sets `gateway.auth.mode: "token"`
- Sets `gateway.auth.token`

**C3: Sandbox**

- Sets `sandbox.mode: "all"` for all agents

**H1: Dangerous Tools**

- Removes `gateway`, `sessions_send`, `sessions_list`, `nodes` from allow lists

**H2: Exec Approvals**

- Sets `approvals.exec.enabled: true`
- Adds placeholder approval target (you must set Telegram user ID)

**H3: readOnlyRoot**

- Sets `readOnlyRoot: true` for all agents

**M1: Context Pruning**

- Sets `contextPruning.mode: "cache-ttl"`
- Sets `contextPruning.ttl: "1h"`

**M3: Capability Drop**

- Sets `capDrop: ["ALL"]` for all agents

**L1: Reload Mode**

- Sets `gateway.reload.mode: "hot"`
- Sets `gateway.reload.debounceMs: 500`

### What DOESN'T Get Fixed

**C2: API Keys in Env**

- **Why:** Requires migration to `declaw-secrets`
- **Manual fix:** Use `declaw-secrets set` for each key, update config to reference `secret://`

**M2: Gateway TLS**

- **Why:** Requires manual TLS setup (Tailscale or self-signed cert)
- **Manual fix:** See OpenClaw docs for Tailscale Serve setup

---

## Usage

### Audit Only

```bash
declaw-doctor ~/.openclaw/openclaw.json
```

Exit codes:

- `0` - All checks passed
- `1` - Critical/high issues found
- `2` - Only medium warnings found

### Auto-Fix

```bash
# Preview changes
declaw-doctor ~/.openclaw/openclaw.json --fix --dry-run

# Apply fixes
declaw-doctor ~/.openclaw/openclaw.json --fix
```

Creates backup: `~/.openclaw/openclaw.json.bak`

### Verbose Mode

```bash
declaw-doctor ~/.openclaw/openclaw.json -v
```

Shows low-priority issues too.

---

## Migrating API Keys to declaw-secrets

After running `declaw-doctor`, migrate API keys:

```bash
# 1. Set each key in declaw-secrets
declaw-secrets set SHODAN_API_KEY

# 2. Update openclaw.json to reference secret://
{
  "env": {
    "SHODAN_API_KEY": "secret://SHODAN_API_KEY"
  }
}

# 3. Restart gateway
openclaw gateway restart
```

**NOTE:** `secret://` reference is not implemented yet - this is for DeClaw fork integration.

For now, use wrapper scripts:

```bash
#!/bin/bash
# shodan-secure.sh
export SHODAN_API_KEY=$(declaw-secrets get SHODAN_API_KEY)
shodan "$@"
unset SHODAN_API_KEY
```

---

## Integration with OpenClaw

`declaw-doctor` works with **existing OpenClaw** installations. No fork required.

### Recommended Workflow

1. **Initial audit**

   ```bash
   declaw-doctor ~/.openclaw/openclaw.json
   ```

2. **Auto-fix safe issues**

   ```bash
   declaw-doctor ~/.openclaw/openclaw.json --fix
   ```

3. **Manually migrate secrets**

   ```bash
   # Use declaw-secrets for each API key
   ```

4. **Re-audit to verify**

   ```bash
   declaw-doctor ~/.openclaw/openclaw.json
   ```

5. **Add to CI/CD** (optional)
   ```bash
   # Fail deployment if security issues found
   declaw-doctor config.json || exit 1
   ```

---

## CI/CD Integration

```yaml
# .github/workflows/security-audit.yml
name: Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Install declaw-doctor
        run: pip install declaw-doctor
      - name: Audit config
        run: declaw-doctor openclaw.json
```

---

## Comparison with `openclaw doctor`

| Feature           | openclaw doctor | declaw-doctor |
| ----------------- | --------------- | ------------- |
| Config validation | ✅ Yes          | ✅ Yes        |
| Security checks   | ❌ No           | ✅ Yes        |
| Auto-fix          | ✅ Some         | ✅ More       |
| Secrets detection | ❌ No           | ✅ Yes        |
| Scoring           | ❌ No           | ✅ Yes        |
| Exit codes        | ❌ Always 0     | ✅ 0/1/2      |

`declaw-doctor` is focused on **security**, not just correctness.

---

## FAQ

**Q: Will this break my OpenClaw setup?**
A: No. Always creates `.bak` backup before changes. Test in dev first.

**Q: Can I run this on production configs?**
A: Yes, but use `--dry-run` first to preview changes.

**Q: Does this work with DeClaw fork?**
A: Yes, but DeClaw fork will have these checks built-in (fail at startup, not audit time).

**Q: What if I disagree with a check?**
A: File an issue. Security is opinionated, but we're open to feedback.

**Q: Can I add custom checks?**
A: Not yet, but planned for v2.0 (plugin system for checks).

---

## Roadmap

### v1.0 (Current)

- ✅ 10 security checks
- ✅ Auto-fix for 8 checks
- ✅ Backup before changes
- ✅ Exit codes for CI/CD

### v1.1 (Next)

- [ ] JSON output (`--format json`)
- [ ] Config diff view
- [ ] Historical tracking (audit over time)
- [ ] More checks (20 total)

### v2.0 (Future)

- [ ] Plugin system for custom checks
- [ ] Integration with declaw-monitor (runtime validation)
- [ ] Web UI for audit results
- [ ] Compliance reporting (SOC2, ISO 27001)

---

## Contributing

Report issues or suggest new checks:

- GitHub: https://github.com/tomstetson/declaw-patterns/issues

---

## License

MIT License - See repository root

---

**DeClaw Doctor** - Security auditor for OpenClaw configs
