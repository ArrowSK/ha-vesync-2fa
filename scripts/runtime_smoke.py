#!/usr/bin/env python3
"""Smoke-test the historical probe against the pinned Home Assistant runtime."""

from __future__ import annotations

import importlib
from pathlib import Path
import sys

from pyvesync.models.vesync_models import RequestGetTokenModel

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> None:
    """Import Core/probe modules and verify probe/redaction invariants."""
    core_vesync = importlib.import_module("homeassistant.components.vesync")
    probe = importlib.import_module("custom_components.vesync_2fa_probe")
    importlib.import_module("custom_components.vesync_2fa_probe.config_flow")
    auth = importlib.import_module("custom_components.vesync_2fa_probe.auth")

    from custom_components.vesync_2fa_probe.const import DOMAIN

    assert core_vesync.DOMAIN == "vesync"
    assert DOMAIN == "vesync_2fa_probe"
    assert DOMAIN != core_vesync.DOMAIN
    # The final repository deliberately contains a separate production
    # custom_components/vesync layer. This smoke test remains scoped only to the
    # historical diagnostic domain and must not assume that package is absent.
    assert (ROOT / "custom_components" / "vesync_2fa_probe").exists()

    request = RequestGetTokenModel(
        email="nobody@example.invalid",
        method="authByPWDOrOTM",
        password="plain-test-password",
        userCountryCode="HU",
        timeZone="Europe/Budapest",
    ).to_dict()
    assert request["password"] != "plain-test-password"
    assert len(request["password"]) == 32
    assert request["userCountryCode"] == "HU"
    assert request["timeZone"] == "Europe/Budapest"

    normal = auth.parse_probe_response(
        {
            "code": 0,
            "msg": "request success",
            "result": {
                "accountID": "private-account-id",
                "verifyEmail": "private@example.invalid",
                "bizToken": None,
                "mfaMethodList": None,
                "authorizeCode": "private-authorization-code",
            },
        }
    )
    assert normal.outcome == "password_accepted"
    assert normal.has_authorize_code is True
    normal_safe = normal.safe_summary

    mfa = auth.parse_probe_response(
        {
            "code": -11000000,
            "msg": "user login requires 2fa authentication",
            "result": {
                "accountID": "private-account-id",
                "verifyEmail": "private@example.invalid",
                "bizToken": "private-mfa-challenge-token",
                "mfaMethodList": ["TOTP", "EMAIL", "bad method <html>"],
                "authorizeCode": "",
            },
        }
    )
    assert mfa.outcome == "mfa_required"
    assert mfa.methods == ("TOTP", "EMAIL", "bad_method_html_")
    assert mfa.has_biz_token is True
    assert mfa.has_verify_email is True
    assert mfa.has_authorize_code is False
    mfa_safe = mfa.safe_summary

    confirmed_field_shape = auth.parse_probe_response(
        {
            "code": -11257129,
            "msg": "user login requires 2fa authentication",
            "result": {
                "accountID": "redacted",
                "accountLockTimeInSec": None,
                "authorizeCode": "",
                "avatarIcon": "",
                "bizToken": "redacted-challenge-token",
                "emailUpdateToSame": "",
                "mailConfirmation": False,
                "mfaMethodList": ["email", "otp", "backupCode"],
                "nickName": "",
                "registerAppVersion": "",
                "registerSourceDetail": None,
                "registerTime": "",
                "userType": "",
                "verifyEmail": "",
            },
        }
    )
    assert confirmed_field_shape.outcome == "mfa_required"
    assert confirmed_field_shape.server_code == -11257129
    assert confirmed_field_shape.methods == ("email", "otp", "backupCode")
    assert confirmed_field_shape.has_biz_token is True
    assert confirmed_field_shape.has_verify_email is False
    assert confirmed_field_shape.has_authorize_code is False
    confirmed_safe = confirmed_field_shape.safe_summary
    assert "server_code=-11257129" in confirmed_safe
    assert "methods=email,otp,backupCode" in confirmed_safe
    assert "biz_token=yes" in confirmed_safe
    assert "verify_email=no" in confirmed_safe
    assert "authorize_code=no" in confirmed_safe
    assert "redacted-challenge-token" not in confirmed_safe

    challenge_without_message = auth.parse_probe_response(
        {
            "code": 0,
            "msg": "request success",
            "result": {
                "bizToken": "another-private-token",
                "mfaMethodList": ["TOTP"],
                "authorizeCode": "must-not-be-used",
            },
        }
    )
    assert challenge_without_message.outcome == "mfa_required"

    rejected = auth.parse_probe_response(
        {
            "code": -10014,
            "msg": "incorrect password for private@example.invalid",
            "result": {},
        }
    )
    assert rejected.outcome == "rejected"
    rejected_safe = rejected.safe_summary

    for safe in (normal_safe, mfa_safe, confirmed_safe, rejected_safe):
        for secret in (
            "private-account-id",
            "private@example.invalid",
            "private-mfa-challenge-token",
            "private-authorization-code",
            "another-private-token",
            "must-not-be-used",
            "plain-test-password",
            "redacted-challenge-token",
        ):
            assert secret not in safe

    assert "methods=TOTP,EMAIL,bad_method_html_" in mfa_safe
    assert "biz_token=yes" in mfa_safe
    assert "verify_email=yes" in mfa_safe
    assert "authorize_code=no" in mfa_safe

    print("Home Assistant Core VeSync import: OK")
    print("Historical probe import/domain: OK")
    print("Pinned pyvesync request model: OK")
    print("MFA response classification: OK")
    print("Confirmed live MFA challenge shape: OK")
    print("Safe metadata redaction: OK")


if __name__ == "__main__":
    main()
