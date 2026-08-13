#!/usr/bin/env python3
"""Smoke-test the custom component against the pinned Home Assistant runtime."""

from __future__ import annotations

import importlib
import inspect
from pathlib import Path
import sys

from pyvesync import VeSync
from pyvesync.models.vesync_models import RequestGetTokenModel

# Running a script by path puts the scripts directory, rather than the repository
# root, first on sys.path. Add the root explicitly so this check imports the
# custom component exactly from the checked-out repository.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

MODULES = (
    "custom_components.vesync",
    "custom_components.vesync.auth",
    "custom_components.vesync.config_flow",
    "custom_components.vesync.coordinator",
    "custom_components.vesync.session",
    "custom_components.vesync.binary_sensor",
    "custom_components.vesync.fan",
    "custom_components.vesync.humidifier",
    "custom_components.vesync.light",
    "custom_components.vesync.number",
    "custom_components.vesync.select",
    "custom_components.vesync.sensor",
    "custom_components.vesync.switch",
    "custom_components.vesync.update",
    "custom_components.vesync.diagnostics",
)


def main() -> None:
    """Import every module and verify authentication/session invariants."""
    for module in MODULES:
        importlib.import_module(module)

    from custom_components.vesync.auth import (
        VeSyncAuthorizationCode,
        VeSyncMFAChallenge,
        parse_auth_response,
    )
    from custom_components.vesync.session import restore_session, session_data

    # This integration deliberately reuses pyvesync's pinned private second-stage
    # token exchange instead of copying its cross-region logic. Fail CI if that
    # contract changes.
    contract_manager = VeSync("nobody@example.invalid", "not-a-real-password")
    exchange = getattr(contract_manager.auth, "_exchange_authorization_code", None)
    assert callable(exchange)
    exchange_parameters = tuple(inspect.signature(exchange).parameters)
    assert exchange_parameters == ("auth_code", "region_change_token")

    # Verify that the pinned request model still hashes the supplied password
    # before serialization; our MFA discovery layer intentionally delegates that
    # detail to pyvesync rather than reproducing it.
    request = RequestGetTokenModel(
        email="nobody@example.invalid",
        method="authByPWDOrOTM",
        password="plain-test-password",
    ).to_dict()
    assert request["password"] != "plain-test-password"
    assert len(request["password"]) == 32

    source = VeSync("nobody@example.invalid", "not-a-real-password")
    source.set_credentials(
        token="test-token",
        account_id="test-account",
        country_code="HU",
        region="EU",
    )

    saved = session_data(source)
    assert saved == {
        "auth_token": "test-token",
        "auth_account_id": "test-account",
        "auth_country_code": "HU",
        "auth_region": "EU",
    }

    restored = VeSync("nobody@example.invalid", "not-a-real-password")
    assert restore_session(restored, saved)
    assert restored.token == "test-token"
    assert restored.account_id == "test-account"
    assert restored.country_code == "HU"
    assert restored.current_region == "EU"
    assert restored.enabled is True

    normal = parse_auth_response(
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
    assert isinstance(normal, VeSyncAuthorizationCode)
    assert normal.authorization_code == "private-authorization-code"

    mfa = parse_auth_response(
        {
            "code": -1,
            "msg": "user login requires 2fa authentication",
            "result": {
                "accountID": "private-account-id",
                "verifyEmail": "private@example.invalid",
                "bizToken": "private-mfa-challenge-token",
                "mfaMethodList": ["TOTP", "EMAIL"],
                "authorizeCode": "",
            },
        }
    )
    assert isinstance(mfa, VeSyncMFAChallenge)
    assert mfa.methods == ("TOTP", "EMAIL")
    safe = mfa.safe_summary
    assert "TOTP,EMAIL" in safe
    assert "biz_token=yes" in safe
    assert "verify_email=yes" in safe
    for secret in (
        "private-account-id",
        "private@example.invalid",
        "private-mfa-challenge-token",
    ):
        assert secret not in safe
        assert secret not in repr(mfa)

    # Some APIs return a successful status together with challenge metadata.
    # Challenge fields must take precedence over an authorization code so MFA can
    # never be silently bypassed by the parser.
    challenge_with_success_code = parse_auth_response(
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
    assert isinstance(challenge_with_success_code, VeSyncMFAChallenge)

    print("Home Assistant module imports: OK")
    print("Pinned pyvesync auth contract: OK")
    print("pyvesync session save/restore round trip: OK")
    print("VeSync MFA challenge parsing/redaction: OK")


if __name__ == "__main__":
    main()
