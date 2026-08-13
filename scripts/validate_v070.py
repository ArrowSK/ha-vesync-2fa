#!/usr/bin/env python3
"""Repository checks for VeSync 2FA Probe 0.7.x."""

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
    hacs = load_json(ROOT / "hacs.json")

    if manifest.get("domain") != "vesync_2fa_probe":
        fail("probe domain changed")
    if manifest.get("version") != "0.7.0":
        fail("manifest version must be 0.7.0")
    if manifest.get("requirements") != ["pyvesync==3.4.2"]:
        fail("validated pyvesync pin changed")
    if hacs.get("name") != "VeSync 2FA Probe":
        fail("HACS package name changed")
    if strings != translation:
        fail("English translation must match strings.json")

    flow_wrapper = (PROBE / "config_flow.py").read_text(encoding="utf-8")
    flow = (PROBE / "config_flow_v070.py").read_text(encoding="utf-8")
    ladder = (PROBE / "continuation_v070.py").read_text(encoding="utf-8")

    if "config_flow_v070" not in flow_wrapper:
        fail("config_flow.py must point at the 0.7 implementation")
    if "async_step_otp" in flow:
        fail("0.7 must remain a single-form flow")
    if "async_create_entry" in flow:
        fail("probe must not create a persistent config entry")
    if ladder.count('Candidate("p') != 15:
        fail("0.7 must contain exactly 15 bounded MFA candidates")

    for marker in (
        "p01_auth_mfaCode",
        "p08_auth_totp",
        "p11_authByMFA_otpCode",
        "p14_login_authorizeCode",
        "p15_login_otpCode",
        "token_exchange",
        "candidate_count",
        "rate_limited",
        "account_locked",
    ):
        if marker not in ladder:
            fail(f"0.7 ladder invariant missing: {marker}")

    allowed_endpoints = {
        '"/globalPlatform/api/accountAuth/v1/authByPWDOrOTM"',
        '"/user/api/accountManage/v1/loginByAuthorizeCode4Vesync"',
    }
    endpoint_lines = {
        line.strip().split(" = ", 1)[1]
        for line in ladder.splitlines()
        if line.strip().startswith(("_AUTH_ENDPOINT = ", "_LOGIN_ENDPOINT = "))
    }
    if endpoint_lines != allowed_endpoints:
        fail("0.7 may use only the two already-known VeSync auth endpoints")

    combined = "\n".join(path.read_text(encoding="utf-8") for path in PROBE.glob("*.py"))
    if "homeassistant.components.vesync" in combined:
        fail("probe must not import Home Assistant Core VeSync")
    if "async_forward_entry_setups" in combined:
        fail("probe must not load entity platforms")
    if "logger." in ladder or "_LOGGER." in ladder:
        fail("continuation code must not log authentication data")

    print("Probe domain isolation: OK")
    print("0.7 package metadata: OK")
    print("Single-form config flow: OK")
    print("Exactly 15 bounded MFA payload hypotheses: OK")
    print("Known VeSync auth endpoints only: OK")
    print("No persistent config entry: OK")
    print("Translations: OK")


if __name__ == "__main__":
    main()
