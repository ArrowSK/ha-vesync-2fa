#!/usr/bin/env python3
"""Repository checks for VeSync 2FA Probe 0.6.x."""

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
    if manifest.get("version") != "0.6.0":
        fail("manifest version must be 0.6.0")
    if manifest.get("requirements") != ["pyvesync==3.4.2"]:
        fail("validated pyvesync pin changed")
    if hacs.get("name") != "VeSync 2FA Probe":
        fail("HACS package name changed")
    if strings != translation:
        fail("English translation must match strings.json")

    flow_wrapper = (PROBE / "config_flow.py").read_text(encoding="utf-8")
    flow = (PROBE / "config_flow_v060.py").read_text(encoding="utf-8")
    if "config_flow_v060" not in flow_wrapper:
        fail("config_flow.py must point at the 0.6 implementation")
    if "async_create_entry" in flow:
        fail("probe must not create a persistent config entry")
    for marker in (
        "async_probe_preflight",
        "async_probe_otp_ladder",
        "async_step_otp",
        "_password_hash",
        'otp_code = ""',
    ):
        if marker not in flow:
            fail(f"0.6 flow invariant missing: {marker}")

    ladder = (PROBE / "continuation_v060.py").read_text(encoding="utf-8")
    for marker in (
        "c7_login_bizToken_only",
        "c8_login_bizToken_lastRegion",
        "d1_same_auth_mfaCode",
        "d2_same_auth_otp",
        "d3_same_auth_otpCode",
        "d4_same_auth_verificationCode",
        "d5_same_auth_verifyCode",
        "d6_same_auth_code",
        "e1_login_otpCode",
        "e2_login_mfaCode",
        "e3_login_verificationCode",
        "rate_limited",
        "account_locked",
        "invalid_code",
        "code_expired",
    ):
        if marker not in ladder:
            fail(f"0.6 ladder invariant missing: {marker}")

    # Protocol guesses are limited to the two endpoints already used by current
    # VeSync clients. 0.6 must not turn into broad endpoint enumeration.
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
        fail("0.6 may use only the two already-known VeSync auth endpoints")

    combined = "\n".join(
        path.read_text(encoding="utf-8") for path in PROBE.glob("*.py")
    )
    if "homeassistant.components.vesync" in combined:
        fail("probe must not import Home Assistant Core VeSync")
    if "async_forward_entry_setups" in combined:
        fail("probe must not load entity platforms")
    if "logger." in ladder or "_LOGGER." in ladder:
        fail("continuation code must not log authentication data")

    # The OTP is allowed only as an ephemeral config-flow input and network
    # payload. It must not be written to config entries/files or exposed in the
    # safe summary.
    for forbidden in (
        "async_create_entry",
        "write_text(",
        "save_credentials",
        "output_credentials",
        "otp_code!r",
        "{otp_code}",
    ):
        if forbidden in ladder:
            fail(f"OTP ladder persistence/disclosure invariant failed: {forbidden}")

    readme = (ROOT / "README.md").read_text(encoding="utf-8").casefold()
    if "built-in **vesync** integration" not in readme:
        fail("README must protect the built-in VeSync integration")

    print("Probe domain isolation: OK")
    print("0.6 package metadata: OK")
    print("No persistent config entry: OK")
    print("Bounded one-code continuation ladder: OK")
    print("Known VeSync auth endpoints only: OK")
    print("OTP persistence/redaction invariants: OK")
    print("Translations: OK")


if __name__ == "__main__":
    main()
