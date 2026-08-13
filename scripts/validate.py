#!/usr/bin/env python3
"""Repository-specific checks that do not require a Home Assistant checkout."""

from __future__ import annotations

import ast
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
INTEGRATION = ROOT / "custom_components" / "vesync"
EXPECTED_PLATFORMS = {
    "binary_sensor",
    "fan",
    "humidifier",
    "light",
    "number",
    "select",
    "sensor",
    "switch",
    "update",
}


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as err:
        fail(f"{path.relative_to(ROOT)} is not valid JSON: {err}")


def main() -> None:
    manifest = load_json(INTEGRATION / "manifest.json")
    hacs = load_json(ROOT / "hacs.json")
    strings = load_json(INTEGRATION / "strings.json")
    translations = load_json(INTEGRATION / "translations" / "en.json")
    load_json(INTEGRATION / "icons.json")

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

    if manifest["domain"] != "vesync":
        fail("domain must remain 'vesync' to preserve the existing integration")
    if manifest["name"] != "VeSync 2FA":
        fail("manifest name must describe the native 2FA project")
    if manifest["requirements"] != ["pyvesync==3.4.2"]:
        fail("pyvesync must stay pinned to the version validated for this release")
    if manifest["version"] != "0.2.0":
        fail("manifest version and release validation are out of sync")
    if hacs.get("homeassistant") != "2026.8.0":
        fail("HACS minimum Home Assistant version must remain explicit")
    if strings != translations:
        fail("translations/en.json must match strings.json in this repository")

    config = strings.get("config", {})
    if "mfa_challenge" not in config.get("step", {}):
        fail("the MFA challenge discovery config-flow step is missing")
    if "mfa_protocol_unverified" not in config.get("abort", {}):
        fail("the unverified-protocol abort reason is missing")
    if "mfa_required" not in strings.get("exceptions", {}):
        fail("the MFA-required config-entry exception translation is missing")

    for platform in EXPECTED_PLATFORMS:
        path = INTEGRATION / f"{platform}.py"
        if not path.is_file():
            fail(f"missing platform adapter: {path.relative_to(ROOT)}")
        text = path.read_text(encoding="utf-8")
        expected_import = f"homeassistant.components.vesync.{platform} import async_setup_entry"
        if expected_import not in text:
            fail(f"{platform}.py no longer delegates directly to Home Assistant Core")

    flow_text = (INTEGRATION / "config_flow.py").read_text(encoding="utf-8")
    flow_tree = ast.parse(flow_text)
    assignments: dict[str, object] = {}
    for node in ast.walk(flow_tree):
        if isinstance(node, ast.ClassDef) and node.name == "VeSyncFlowHandler":
            for item in node.body:
                if isinstance(item, ast.Assign) and len(item.targets) == 1:
                    target = item.targets[0]
                    if isinstance(target, ast.Name) and isinstance(item.value, ast.Constant):
                        assignments[target.id] = item.value.value
    if assignments.get("VERSION") != 1 or assignments.get("MINOR_VERSION") != 3:
        fail("config-flow version must stay aligned with Home Assistant Core 2026.8.0")
    for marker in (
        "VeSyncMFARequired",
        "async_authenticate",
        "async_step_mfa_challenge",
        "safe_summary",
    ):
        if marker not in flow_text:
            fail(f"MFA flow invariant missing from config_flow.py: {marker}")

    init_text = (INTEGRATION / "__init__.py").read_text(encoding="utf-8")
    for marker in (
        "restore_session(manager, config_entry.data)",
        "merged_with_session(config_entry.data, manager)",
        "async_authenticate(",
        "username=username",
        "password=password",
        "async_forward_entry_setups(config_entry, PLATFORMS)",
        "_core_async_migrate_entry",
    ):
        if marker not in init_text:
            fail(f"authentication/compatibility invariant missing from __init__.py: {marker}")

    auth_text = (INTEGRATION / "auth.py").read_text(encoding="utf-8")
    for marker in (
        "authByPWDOrOTM",
        "mfaMethodList",
        "bizToken",
        "VeSyncMFARequired",
        "safe_summary",
        "_exchange_authorization_code",
    ):
        if marker not in auth_text:
            fail(f"MFA discovery invariant missing from auth.py: {marker}")
    if "logger." in auth_text or "_LOGGER." in auth_text:
        fail("auth.py must not log raw authentication/challenge data")

    session_text = (INTEGRATION / "session.py").read_text(encoding="utf-8")
    if "manager.enabled = True" not in session_text:
        fail("restored pyvesync sessions must enable the manager before update()")

    coordinator_text = (INTEGRATION / "coordinator.py").read_text(encoding="utf-8")
    if "ConfigEntryAuthFailed" not in coordinator_text or "UpdateFailed" not in coordinator_text:
        fail("expired sessions must be promoted into Home Assistant reauthentication")

    # The previous prototype required disabling account security. That is no
    # longer an accepted product path. Keep the public UI and README free of that
    # workaround so it cannot accidentally reappear as advice.
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
    print("JSON files: OK")
    print("Core platform delegation: OK")
    print("VeSync domain/config-entry invariants: OK")
    print("MFA challenge/redaction invariants: OK")
    print("Session persistence/reauth invariants: OK")


if __name__ == "__main__":
    main()
