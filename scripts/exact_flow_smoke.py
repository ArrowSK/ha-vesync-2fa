#!/usr/bin/env python3
"""Offline smoke checks for the HAR-confirmed VeSync MFA flow."""

from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from custom_components.vesync_2fa_probe import exact_mfa_v080 as exact


def main() -> None:
    context = exact._web_context(
        method="authBy2fa",
        time_zone="Europe/Budapest",
        terminal_id="MallWeb-offline-test",
        app_id="deadbeef",
    )
    assert context["method"] == "authBy2fa"
    assert context["terminalId"] == "MallWeb-offline-test"
    assert context["accountID"] == "common"
    assert context["token"] == "common"

    attempt = exact._attempt(
        "authBy2fa",
        200,
        {
            "code": 0,
            "msg": "request success",
            "result": {
                "accountID": "private-account",
                "authorizeCode": "private-authorize-code",
                "bizToken": "private-biz-token",
                "token": "private-session-token",
            },
        },
    )
    safe = attempt.safe_summary
    assert attempt.authorize_code == "private-authorize-code"
    assert attempt.token == "private-session-token"
    assert "authorize_code=yes" in safe
    assert "token=yes" in safe
    for secret in (
        "private-account",
        "private-authorize-code",
        "private-biz-token",
        "private-session-token",
    ):
        assert secret not in safe

    source = (ROOT / "custom_components" / "vesync_2fa_probe" / "exact_mfa_v080.py").read_text(
        encoding="utf-8"
    )
    assert '/globalPlatform/api/accountAuth/v1/authBy2fa' in source
    assert '"mfaMethod": "otp"' in source
    assert '"bizToken": first.biz_token' in source
    assert '"otpCode": otp_code' in source
    assert 'json={"context": context, "data": data}' in source

    print("HAR-confirmed authBy2fa endpoint: OK")
    print("Exact OTP payload field mapping: OK")
    print("Account-web context wrapper: OK")
    print("Safe exact-flow metadata redaction: OK")


if __name__ == "__main__":
    main()
