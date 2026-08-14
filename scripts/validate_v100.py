#!/usr/bin/env python3
"""Repository checks for VeSync 2FA 1.0.1."""

from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
COMPONENTS = ROOT / "custom_components"
PRODUCTION = COMPONENTS / "vesync"


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        fail(f"{path.relative_to(ROOT)} must contain a JSON object")
    return value


def main() -> None:
    if not PRODUCTION.is_dir():
        fail("production custom_components/vesync package is missing")

    manifest_domains = sorted(
        path.parent.name for path in COMPONENTS.glob("*/manifest.json")
    )
    if manifest_domains != ["vesync"]:
        fail(
            "production HACS package must expose exactly one integration domain "
            f"(vesync); found {manifest_domains}"
        )

    manifest = load_json(PRODUCTION / "manifest.json")
    strings = load_json(PRODUCTION / "strings.json")
    translation = load_json(PRODUCTION / "translations" / "en.json")

    if manifest.get("domain") != "vesync":
        fail("production integration must retain the Core vesync domain")
    if manifest.get("version") != "1.0.1":
        fail("production manifest version must be 1.0.1")
    if manifest.get("requirements") != ["pyvesync==3.4.2"]:
        fail("production build must retain the Core 2026.8 pyvesync pin")
    if strings != translation:
        fail("production strings and English translation must match")

    required_platforms = (
        "binary_sensor.py",
        "fan.py",
        "humidifier.py",
        "light.py",
        "number.py",
        "select.py",
        "sensor.py",
        "switch.py",
        "update.py",
        "diagnostics.py",
    )
    for filename in required_platforms:
        path = PRODUCTION / filename
        if not path.is_file():
            fail(f"Core compatibility proxy missing: {filename}")
        text = path.read_text(encoding="utf-8")
        if "homeassistant.components.vesync" not in text:
            fail(f"{filename} must delegate unchanged behavior to Home Assistant Core")

    init_text = (PRODUCTION / "__init__.py").read_text(encoding="utf-8")
    flow_text = (PRODUCTION / "config_flow.py").read_text(encoding="utf-8")
    mfa_text = (PRODUCTION / "mfa.py").read_text(encoding="utf-8")
    coordinator_text = (PRODUCTION / "coordinator.py").read_text(encoding="utf-8")

    required_init = (
        "manager.set_credentials",
        "persist_manager_credentials",
        "async_forward_entry_setups",
        "core_async_migrate_entry",
        "core_async_remove_config_entry_device",
    )
    for marker in required_init:
        if marker not in init_text:
            fail(f"production setup invariant missing: {marker}")

    for marker in (
        "async_step_mfa",
        "async_step_reauth_mfa",
        "async_update_reload_and_abort",
        "_same_reauth_account",
        "session_data_from_manager",
    ):
        if marker not in flow_text:
            fail(f"production config-flow invariant missing: {marker}")

    for marker in (
        "/globalPlatform/api/accountAuth/v1/authByPWDOrOTM",
        "/globalPlatform/api/accountAuth/v1/authBy2fa",
        "/user/api/accountManage/v1/loginByAuthorizeCode4Vesync",
        '"mfaMethod": "otp"',
        '"bizToken": biz_token',
        '"otpCode": otp_code',
    ):
        if marker not in mfa_text:
            fail(f"confirmed MFA protocol marker missing: {marker}")

    if (
        "ConfigEntryAuthFailed" not in coordinator_text
        or "manager.enabled" not in coordinator_text
    ):
        fail("coordinator must surface expired MFA sessions to Home Assistant reauth")

    component_text = "\n".join(
        path.read_text(encoding="utf-8", errors="ignore")
        for path in COMPONENTS.rglob("*")
        if path.is_file()
    )
    if list(ROOT.rglob("*.har")):
        fail("HAR capture files must never be committed")
    jwt_header_marker = "eyJ" + "hbGciOi"
    if jwt_header_marker in component_text:
        fail("custom components appear to contain JWT/token material")

    print("Single HACS integration domain (vesync): OK")
    print("Production vesync domain preserved: OK")
    print("Core platform behavior delegated unchanged: OK")
    print("Session persistence and registry-preserving setup: OK")
    print("Interactive MFA setup/reauth flow: OK")
    print("Legacy reauth identity migration: OK")
    print("HAR-confirmed authBy2fa protocol: OK")
    print("Expired-session reauth signaling: OK")
    print("No HAR/token material committed: OK")
    print("Translations: OK")


if __name__ == "__main__":
    main()
