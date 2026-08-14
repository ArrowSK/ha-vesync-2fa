#!/usr/bin/env python3
"""Repository checks for VeSync 2FA Probe 0.8.0."""

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
    if manifest.get("version") != "0.8.0":
        fail("manifest version must be 0.8.0")
    if strings != translation:
        fail("English translation must match strings.json")

    wrapper = (PROBE / "config_flow.py").read_text(encoding="utf-8")
    if "config_flow_v080" not in wrapper:
        fail("active config flow must point to 0.8 exact-flow implementation")

    flow = (PROBE / "config_flow_v080.py").read_text(encoding="utf-8")
    if "async_step_otp" in flow:
        fail("probe must remain a single-form config flow")
    if "async_create_entry" in flow:
        fail("probe must not create a persistent config entry")
    if "vol.Match" in flow:
        fail("frontend config-flow schema must not use vol.Match")
    if "vol.Length(min=6, max=8)" not in flow:
        fail("OTP field must retain bounded length validation")
    if "continuation_v070" in flow or "async_probe_otp_ladder" in flow:
        fail("active flow must not use the old 15-way guessing ladder")

    exact = (PROBE / "exact_mfa_v080.py").read_text(encoding="utf-8")
    required = (
        "/globalPlatform/api/accountAuth/v1/authByPWDOrOTM",
        "/globalPlatform/api/accountAuth/v1/authBy2fa",
        "/user/api/accountManage/v1/loginByAuthorizeCode4Vesync",
        '"mfaMethod": "otp"',
        '"bizToken": first.biz_token',
        '"otpCode": otp_code',
        'json={"context": context, "data": data}',
    )
    for marker in required:
        if marker not in exact:
            fail(f"HAR-confirmed protocol marker missing: {marker}")

    forbidden = (
        "private-account-id",
        "redacted-challenge-token",
        "artems.kovalev",
        "12982335",
        "30410011",
        "30110011",
    )
    repository_text = "\n".join(
        path.read_text(encoding="utf-8", errors="ignore")
        for path in ROOT.rglob("*")
        if path.is_file() and ".git" not in path.parts
    )
    for marker in forbidden:
        if marker in repository_text:
            fail("repository contains field-test account data or token material")

    print("Probe domain isolation: OK")
    print("0.8.0 package metadata: OK")
    print("HAR-confirmed authBy2fa protocol markers: OK")
    print("Old guessing ladder inactive: OK")
    print("Frontend-serializable config-flow schema: OK")
    print("No persistent config entry: OK")
    print("No captured account/token material: OK")
    print("Translations: OK")


if __name__ == "__main__":
    main()
