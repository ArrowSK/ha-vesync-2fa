#!/usr/bin/env python3
"""Repository checks for VeSync 2FA Probe 0.7.1."""

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
    if manifest.get("version") != "0.7.1":
        fail("manifest version must be 0.7.1")
    if strings != translation:
        fail("English translation must match strings.json")

    wrapper = (PROBE / "config_flow.py").read_text(encoding="utf-8")
    if "_serializable_schema" not in wrapper:
        fail("serializable config-flow schema patch is missing")
    if "vol.Match" in wrapper:
        fail("frontend config-flow schema must not use vol.Match")
    if "vol.Length(min=6, max=8)" not in wrapper:
        fail("OTP field must retain bounded length validation")

    implementation = (PROBE / "config_flow_v070.py").read_text(encoding="utf-8")
    if "async_step_otp" in implementation:
        fail("probe must remain a single-form config flow")
    if "async_create_entry" in implementation:
        fail("probe must not create a persistent config entry")

    print("Probe domain isolation: OK")
    print("0.7.1 package metadata: OK")
    print("Single-form config flow: OK")
    print("Frontend-serializable config-flow schema: OK")
    print("No persistent config entry: OK")
    print("Translations: OK")


if __name__ == "__main__":
    main()
