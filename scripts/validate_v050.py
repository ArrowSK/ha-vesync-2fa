#!/usr/bin/env python3
"""Repository checks for VeSync 2FA Probe 0.5.x."""

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
    if manifest.get("version") != "0.5.0":
        fail("manifest version must be 0.5.0")
    if manifest.get("requirements") != ["pyvesync==3.4.2"]:
        fail("validated pyvesync pin changed")
    if hacs.get("name") != "VeSync 2FA Probe":
        fail("HACS package name changed")
    if strings != translation:
        fail("English translation must match strings.json")

    flow_wrapper = (PROBE / "config_flow.py").read_text(encoding="utf-8")
    flow = (PROBE / "config_flow_v050.py").read_text(encoding="utf-8")
    if "config_flow_v050" not in flow_wrapper:
        fail("config_flow.py must point at the 0.5 implementation")
    if "async_create_entry" in flow:
        fail("probe must not create a persistent config entry")
    if "async_probe_continuation_ladder" not in flow:
        fail("0.5 continuation ladder is not wired into the flow")

    ladder = (PROBE / "continuation_v050.py").read_text(encoding="utf-8")
    for marker in (
        "c2_same_auth_password_mfaMethod",
        "c3_same_auth_password_bizToken_only",
        "c4_same_auth_password_mfaMethodType",
        "c5_authByMFA_password_mfaMethod",
        "c6_verifyMFA_password_mfaMethod",
        "async_probe_continuation_ladder",
        "_PAUSE_BETWEEN_ATTEMPTS",
        "account_locked",
        "rate_limited",
    ):
        if marker not in ladder:
            fail(f"0.5 ladder invariant missing: {marker}")

    # The discovery build may reconstruct the first-stage password hash for a
    # candidate request, but it must never submit a second-factor value.
    for marker in (
        'payload["otp"]',
        'payload["otpCode"]',
        'payload["mfaCode"]',
        'payload["verificationCode"]',
        'payload["verifyCode"]',
        'payload["backupCode"]',
        'payload["emailCode"]',
    ):
        if marker in ladder:
            fail(f"ladder must not submit a second-factor value: {marker}")

    combined = "\n".join(path.read_text(encoding="utf-8") for path in PROBE.glob("*.py"))
    if "homeassistant.components.vesync" in combined:
        fail("probe must not import Home Assistant Core VeSync")
    if "async_forward_entry_setups" in combined:
        fail("probe must not load entity platforms")
    if "loginByAuthorizeCode4Vesync" in combined:
        fail("diagnostic build must not exchange an authorization code")

    readme = (ROOT / "README.md").read_text(encoding="utf-8").casefold()
    if "built-in **vesync** integration" not in readme:
        fail("README must protect the built-in VeSync integration")
    if "0.5.0" not in readme:
        fail("README must document the current 0.5.0 build")

    print("Probe domain isolation: OK")
    print("0.5 package metadata: OK")
    print("No persistent config entry: OK")
    print("Bounded C2-C6 continuation ladder: OK")
    print("No second-factor submission: OK")
    print("Translations: OK")


if __name__ == "__main__":
    main()
