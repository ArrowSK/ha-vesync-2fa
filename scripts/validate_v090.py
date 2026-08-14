#!/usr/bin/env python3
"""Repository checks for VeSync 2FA Probe 0.9.0."""

from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
COMPONENTS = ROOT / "custom_components"
PROBE = COMPONENTS / "vesync_2fa_probe"


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        fail(f"{path.relative_to(ROOT)} must contain a JSON object")
    return value


def main() -> None:
    if not PROBE.is_dir():
        fail("vesync_2fa_probe component is missing")
    if (COMPONENTS / "vesync").exists():
        fail("diagnostic package must not contain custom_components/vesync")

    manifest = load_json(PROBE / "manifest.json")
    strings = load_json(PROBE / "strings.json")
    translation = load_json(PROBE / "translations" / "en.json")

    if manifest.get("domain") != "vesync_2fa_probe":
        fail("probe domain changed")
    if manifest.get("version") != "0.9.0":
        fail("manifest version must be 0.9.0")
    if strings != translation:
        fail("English translation must match strings.json")

    wrapper = (PROBE / "config_flow.py").read_text(encoding="utf-8")
    if "config_flow_v090" not in wrapper:
        fail("active config flow must point to 0.9 implementation")

    flow = (PROBE / "config_flow_v090.py").read_text(encoding="utf-8")
    if "async_step_otp" in flow:
        fail("probe must remain a single-form config flow")
    if "async_create_entry" in flow:
        fail("probe must not create a persistent config entry")
    if "vol.Match" in flow:
        fail("frontend config-flow schema must not use vol.Match")
    if "async_validate_session" not in flow:
        fail("0.9 flow must run read-only session validation")

    session = (PROBE / "session_validation_v090.py").read_text(encoding="utf-8")
    required = (
        "manager.set_credentials(",
        "await manager.get_devices()",
        'hass.config_entries.async_entries(_CORE_DOMAIN)',
        "_identity_set(manager) == _identity_set(core_manager)",
        'username=""',
        'password=""',
    )
    for marker in required:
        if marker not in session:
            fail(f"session validation marker missing: {marker}")

    forbidden = (
        "async_update_entry",
        "async_create_entry",
        "async_forward_entry_setups",
        "entity_registry.async_update_entity",
    )
    for marker in forbidden:
        if marker in session:
            fail(f"session validation must remain read-only: {marker}")

    if list(ROOT.rglob("*.har")):
        fail("HAR capture files must never be committed")

    print("Probe domain isolation: OK")
    print("0.9.0 package metadata: OK")
    print("HAR-confirmed exact MFA flow retained: OK")
    print("Read-only pyvesync session hydration: OK")
    print("Core device identity comparison: OK")
    print("No persistent config entry: OK")
    print("No registry/config-entry mutation: OK")
    print("Translations: OK")


if __name__ == "__main__":
    main()
