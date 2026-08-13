#!/usr/bin/env python3
"""Repository checks for VeSync 2FA Probe 0.4.x."""

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
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"Invalid JSON in {path.relative_to(ROOT)}: {exc}")
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
    hacs = load_json(ROOT / "hacs.json")

    if manifest.get("domain") != "vesync_2fa_probe":
        fail("probe domain changed")
    if manifest.get("version") != "0.4.0":
        fail("manifest version must be 0.4.0")
    if manifest.get("requirements") != ["pyvesync==3.4.2"]:
        fail("validated pyvesync pin changed")
    if hacs.get("name") != "VeSync 2FA Probe":
        fail("HACS package name changed")
    if strings != translation:
        fail("English translation must match strings.json")

    flow = (PROBE / "config_flow.py").read_text(encoding="utf-8")
    if "async_create_entry" in flow:
        fail("probe must not create a persistent config entry")
    if "async_probe_same_endpoint_continuation" not in flow:
        fail("0.4 continuation hypothesis is not wired into the flow")

    continuation = (PROBE / "continuation.py").read_text(encoding="utf-8")
    if "build_no_code_continuation_payload" not in continuation:
        fail("no-code continuation payload builder is missing")
    if 'payload.pop("password", None)' not in continuation:
        fail("continuation payload must remove the password hash")

    combined = "\n".join(
        path.read_text(encoding="utf-8") for path in PROBE.glob("*.py")
    )
    if "homeassistant.components.vesync" in combined:
        fail("probe must not import Home Assistant Core VeSync")
    if "async_forward_entry_setups" in combined:
        fail("probe must not load entity platforms")

    print("Probe domain isolation: OK")
    print("0.4 package metadata: OK")
    print("No persistent config entry: OK")
    print("Single no-code continuation test: OK")
    print("Translations: OK")


if __name__ == "__main__":
    main()
