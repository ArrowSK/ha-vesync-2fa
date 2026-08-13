#!/usr/bin/env python3
"""Repository-specific checks for the isolated VeSync 2FA probe."""

from __future__ import annotations

import ast
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
CUSTOM_COMPONENTS = ROOT / "custom_components"
INTEGRATION = CUSTOM_COMPONENTS / "vesync_2fa_probe"


def fail(message: str) -> None:
    """Print a validation error and stop."""
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path) -> dict:
    """Load a JSON object or fail with a useful path."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as err:
        fail(f"{path.relative_to(ROOT)} is not valid JSON: {err}")
    if not isinstance(value, dict):
        fail(f"{path.relative_to(ROOT)} must contain a JSON object")
    return value


def main() -> None:
    """Validate repository and safety invariants."""
    if not CUSTOM_COMPONENTS.is_dir():
        fail("custom_components directory is missing")

    integration_dirs = {
        path.name
        for path in CUSTOM_COMPONENTS.iterdir()
        if path.is_dir() and path.name != "__pycache__"
    }
    if integration_dirs != {"vesync_2fa_probe"}:
        fail(
            "custom_components must contain only vesync_2fa_probe; found: "
            + ", ".join(sorted(integration_dirs))
        )
    if (CUSTOM_COMPONENTS / "vesync").exists():
        fail("custom_components/vesync must never exist in the diagnostic release")

    manifest = load_json(INTEGRATION / "manifest.json")
    hacs = load_json(ROOT / "hacs.json")
    strings = load_json(INTEGRATION / "strings.json")
    translations = load_json(INTEGRATION / "translations" / "en.json")

    required_manifest = {
        "domain",
        "name",
        "codeowners",
        "config_flow",
        "documentation",
        "issue_tracker",
        "requirements",
        "version",
    }
    missing = sorted(required_manifest - manifest.keys())
    if missing:
        fail(f"manifest.json is missing required keys: {', '.join(missing)}")

    if manifest["domain"] != "vesync_2fa_probe":
        fail("diagnostic domain must be vesync_2fa_probe")
    if manifest["domain"] == "vesync":
        fail("diagnostic builds must never override Home Assistant Core vesync")
    if manifest["name"] != "VeSync 2FA Probe":
        fail("manifest name must be VeSync 2FA Probe")
    if manifest["requirements"] != ["pyvesync==3.4.2"]:
        fail("pyvesync must stay pinned to the validated release")
    if manifest["version"] != "0.3.0":
        fail("manifest version and validation rules are out of sync")
    if hacs.get("name") != "VeSync 2FA Probe":
        fail("hacs.json name must match the diagnostic package")
    if hacs.get("homeassistant") != "2026.8.0":
        fail("HACS minimum Home Assistant version must remain explicit")
    if strings != translations:
        fail("translations/en.json must match strings.json")

    config = strings.get("config", {})
    if "result" not in config.get("step", {}):
        fail("the sanitized result config-flow step is missing")
    if "probe_complete" not in config.get("abort", {}):
        fail("the probe-complete abort reason is missing")

    python_files = list(INTEGRATION.glob("*.py"))
    combined_python = "\n".join(path.read_text(encoding="utf-8") for path in python_files)

    if "homeassistant.components.vesync" in combined_python:
        fail("probe must not import or delegate to Home Assistant Core vesync")
    if "async_forward_entry_setups" in combined_python:
        fail("probe must not load entity platforms")

    flow_text = (INTEGRATION / "config_flow.py").read_text(encoding="utf-8")
    flow_tree = ast.parse(flow_text)
    if "async_create_entry" in flow_text:
        fail("probe config flow must never create a persistent config entry")
    if "async_update_reload_and_abort" in flow_text:
        fail("probe must never update another integration's config entry")

    version = None
    for node in ast.walk(flow_tree):
        if isinstance(node, ast.ClassDef) and node.name == "VeSync2FAProbeConfigFlow":
            for item in node.body:
                if isinstance(item, ast.Assign) and len(item.targets) == 1:
                    target = item.targets[0]
                    if (
                        isinstance(target, ast.Name)
                        and target.id == "VERSION"
                        and isinstance(item.value, ast.Constant)
                    ):
                        version = item.value.value
    if version != 1:
        fail("probe config-flow VERSION must remain 1")

    for marker in (
        "async_probe_auth",
        "async_step_result",
        "safe_summary",
        "self.async_abort",
    ):
        if marker not in flow_text:
            fail(f"probe flow invariant missing: {marker}")

    auth_text = (INTEGRATION / "auth.py").read_text(encoding="utf-8")
    for marker in (
        "authByPWDOrOTM",
        "RequestGetTokenModel",
        "mfaMethodList",
        "bizToken",
        "parse_probe_response",
        "safe_summary",
    ):
        if marker not in auth_text:
            fail(f"probe authentication invariant missing: {marker}")

    for forbidden in (
        "loginByAuthorizeCode4Vesync",
        "_exchange_authorization_code",
        "set_credentials(",
        "manager.login(",
    ):
        if forbidden in auth_text:
            fail(f"diagnostic probe must not complete a VeSync login: {forbidden}")

    if "logger." in auth_text or "_LOGGER." in auth_text:
        fail("auth.py must not log raw authentication/challenge data")

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    readme_lower = readme.casefold()
    if "`vesync_2fa_probe`" not in readme:
        fail("README must document the isolated probe domain")
    if "leave the existing built-in **vesync** integration alone" not in readme_lower:
        fail("README must explicitly protect the built-in VeSync integration")

    forbidden_docs = (
        "temporarily disable two-factor",
        "temporarily disable 2fa",
        "disable 2fa once",
    )
    for path in (ROOT / "README.md", INTEGRATION / "strings.json"):
        text = path.read_text(encoding="utf-8").casefold()
        for phrase in forbidden_docs:
            if phrase in text:
                fail(f"obsolete disable-2FA workaround found in {path.relative_to(ROOT)}")

    print("Repository structure: OK")
    print("Built-in VeSync isolation: OK")
    print("JSON/translation files: OK")
    print("No persistent probe config entry: OK")
    print("No token exchange or second-factor submission: OK")
    print("MFA metadata redaction invariants: OK")


if __name__ == "__main__":
    main()
