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
    """Stop validation with a useful error."""
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_json(path: Path) -> dict:
    """Load a JSON object or stop."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"Invalid JSON in {path.relative_to(ROOT)}: {exc}")
    if not isinstance(value, dict):
        fail(f"{path.relative_to(ROOT)} must contain a JSON object")
    return value


def main() -> None:
    """Validate package, isolation and no-code ladder invariants."""
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

    flow = (PROBE / "config_flow.py").read_text(encoding="utf-8")
    if "async_create_entry" in flow:
        fail("probe must not create a persistent config entry")
    if "async_probe_continuation_ladder" not in flow:
        fail("0.5 continuation ladder is not wired into the flow")

    auth = (PROBE / "auth.py").read_text(encoding="utf-8")
    if "common_payload = dict(request_payload)" not in auth:
        fail("0.5 must retain the verified hashed credential request only in memory")
    if "logger." in auth or "_LOGGER." in auth:
        fail("authentication probe must not log sensitive request/response data")

    continuation = (PROBE / "continuation.py").read_text(encoding="utf-8")
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
        if marker not in continuation:
            fail(f"0.5 ladder invariant missing: {marker}")

    forbidden_submission_markers = (
        'payload["otp"]',
        'payload["otpCode"]',
        'payload["mfaCode"]',
        'payload["verificationCode"]',
        'payload["verifyCode"]',
        'payload["backupCode"]',
        'payload["emailCode"]',
    )
    for marker in forbidden_submission_markers:
        if marker in continuation:
            fail(f"continuation ladder must not submit a second-factor value: {marker}")

    combined = "\n".join(
        path.read_text(encoding="utf-8") for path in PROBE.glob("*.py")
    )
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
    print("Bounded multi-hypothesis continuation ladder: OK")
    print("No second-factor submission: OK")
    print("Translations: OK")


if __name__ == "__main__":
    main()
