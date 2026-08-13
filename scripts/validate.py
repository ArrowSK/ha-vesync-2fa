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
    if manifest["requirements"] != ["pyvesync==3.4.2"]:
        fail("pyvesync must stay pinned to the version validated for this release")
    if manifest["version"] != "0.1.0":
        fail("manifest version and release validation are out of sync")
    if hacs.get("homeassistant") != "2026.8.0":
        fail("HACS minimum Home Assistant version must remain explicit")
    if strings != translations:
        fail("translations/en.json must match strings.json in this repository")

    if "two_factor_required" not in strings.get("config", {}).get("error", {}):
        fail("the 2FA-specific config-flow error is missing")

    for platform in EXPECTED_PLATFORMS:
        path = INTEGRATION / f"{platform}.py"
        if not path.is_file():
            fail(f"missing platform adapter: {path.relative_to(ROOT)}")
        text = path.read_text(encoding="utf-8")
        expected_import = f"homeassistant.components.vesync.{platform} import async_setup_entry"
        if expected_import not in text:
            fail(f"{platform}.py no longer delegates directly to Home Assistant Core")

    flow_tree = ast.parse((INTEGRATION / "config_flow.py").read_text(encoding="utf-8"))
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

    init_text = (INTEGRATION / "__init__.py").read_text(encoding="utf-8")
    for marker in (
        "restore_session(manager, config_entry.data)",
        "merged_with_session(config_entry.data, manager)",
        "async_forward_entry_setups(config_entry, PLATFORMS)",
        "_core_async_migrate_entry",
    ):
        if marker not in init_text:
            fail(f"session/compatibility invariant missing from __init__.py: {marker}")

    session_text = (INTEGRATION / "session.py").read_text(encoding="utf-8")
    if "manager.enabled = True" not in session_text:
        fail("restored pyvesync sessions must enable the manager before update()")

    print("Repository structure: OK")
    print("JSON files: OK")
    print("Core platform delegation: OK")
    print("VeSync domain/config-entry invariants: OK")
    print("Session persistence invariants: OK")


if __name__ == "__main__":
    main()
