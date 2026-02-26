"""
Shared fixtures for DeClaw Python tool tests.

The three Python tools (declaw-secrets, declaw-doctor, declaw-monitor) are
standalone scripts with shebang lines and no .py extension. We use importlib
to load them as modules so we can test their classes and functions directly.
"""

import importlib.machinery
import importlib.util
import json
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Module import helpers
# ---------------------------------------------------------------------------

SCRIPTS_DIR = Path(__file__).resolve().parent.parent.parent / "scripts"


def _import_script(script_dir: str, module_name: str):
    """Import a shebang script (no .py extension) as a Python module.

    The scripts live at e.g. scripts/declaw-secrets/declaw-secrets.
    importlib.util.spec_from_file_location lets us treat them as regular
    modules despite the missing extension. We must provide a submodule_search_locations
    and explicit loader to handle extensionless files.
    """
    script_path = SCRIPTS_DIR / script_dir / script_dir
    if not script_path.exists():
        pytest.skip(f"Script not found: {script_path}")

    loader = importlib.machinery.SourceFileLoader(module_name, str(script_path))
    spec = importlib.util.spec_from_file_location(
        module_name, script_path, loader=loader
    )
    if spec is None:
        pytest.skip(f"Could not create module spec for: {script_path}")
    mod = importlib.util.module_from_spec(spec)
    # Register under a non-__main__ name to avoid the script's
    # if __name__ == "__main__" block running on import.
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="session")
def declaw_secrets_mod():
    """Import declaw-secrets script as a module (session-scoped for speed)."""
    return _import_script("declaw-secrets", "declaw_secrets")


@pytest.fixture(scope="session")
def declaw_doctor_mod():
    """Import declaw-doctor script as a module."""
    return _import_script("declaw-doctor", "declaw_doctor")


@pytest.fixture(scope="session")
def declaw_monitor_mod():
    """Import declaw-monitor script as a module."""
    return _import_script("declaw-monitor", "declaw_monitor")


# ---------------------------------------------------------------------------
# Config fixtures
# ---------------------------------------------------------------------------

# Minimal valid openclaw.json -- all security settings correct
SECURE_CONFIG = {
    "gateway": {
        "auth": {
            "mode": "token",
            "token": "a" * 64,  # 64-char hex token
        },
        "bind": "loopback",
        "mode": "local",
        "reload": {
            "mode": "hot",
            "debounceMs": 500,
        },
    },
    "agents": {
        "contextPruning": {
            "mode": "cache-ttl",
            "ttl": "1h",
        },
        "list": [
            {
                "id": "secure-agent",
                "sandbox": {
                    "mode": "all",
                    "docker": {
                        "readOnlyRoot": True,
                        "capDrop": ["ALL"],
                        "env": {},
                    },
                },
                "tools": {
                    "allow": ["web_fetch", "file_read"],
                },
            }
        ],
    },
    "tools": {
        "exec": {
            "commandPolicy": {
                "mode": "denylist",
                "deny": ["curl", "wget", "nc", "ncat", "socat", "ssh"],
            },
        },
    },
    "approvals": {
        "exec": {
            "enabled": True,
            "mode": "targets",
            "targets": [{"channel": "telegram", "to": "12345"}],
        }
    },
    "plugins": {
        "pluginSecurity": {
            "mode": "enforce",
            "maxCriticalFindings": 0,
            "blockedCapabilities": ["exec", "crypto-mining"],
            "trustedOrigins": ["bundled"],
        },
    },
    "channels": {
        "telegram": {"enabled": True},
    },
}

# Insecure config -- triggers every security check
INSECURE_CONFIG = {
    "gateway": {
        "auth": {
            "mode": "token",
            "token": "short",  # Too short
        },
        "bind": "0.0.0.0",
        "mode": "local",
        "reload": {
            "mode": "hybrid",
        },
    },
    "agents": {
        "contextPruning": {
            "mode": "off",
        },
        "list": [
            {
                "id": "insecure-agent",
                "sandbox": {
                    "mode": "off",
                    "docker": {
                        "readOnlyRoot": False,
                        "capDrop": [],
                        "env": {
                            "ANTHROPIC_API_KEY": "sk-ant-real-key",
                            "SOME_TOKEN": "secret-value",
                        },
                    },
                },
                "tools": {
                    "allow": [
                        "web_fetch",
                        "gateway",
                        "sessions_send",
                        "sessions_list",
                    ],
                },
            }
        ],
    },
    "approvals": {
        "exec": {
            "enabled": False,
        }
    },
}


@pytest.fixture
def secure_config():
    """Return a deep copy of the secure config dict."""
    return json.loads(json.dumps(SECURE_CONFIG))


@pytest.fixture
def insecure_config():
    """Return a deep copy of the insecure config dict."""
    return json.loads(json.dumps(INSECURE_CONFIG))


@pytest.fixture
def tmp_config_dir(tmp_path):
    """Provide a temp directory pre-populated with openclaw.json (insecure)."""
    config_file = tmp_path / "openclaw.json"
    config_file.write_text(json.dumps(INSECURE_CONFIG, indent=2))
    return tmp_path


@pytest.fixture
def secure_config_file(tmp_path, secure_config):
    """Write the secure config to a temp file and return the Path."""
    config_file = tmp_path / "openclaw.json"
    config_file.write_text(json.dumps(secure_config, indent=2))
    return config_file


@pytest.fixture
def insecure_config_file(tmp_path, insecure_config):
    """Write the insecure config to a temp file and return the Path."""
    config_file = tmp_path / "openclaw.json"
    config_file.write_text(json.dumps(insecure_config, indent=2))
    return config_file
