#!/usr/bin/env python3
"""Runtime checks for the production same-domain VeSync 2FA layer."""

from __future__ import annotations

import importlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main() -> None:
    integration = importlib.import_module("custom_components.vesync")
    flow_module = importlib.import_module("custom_components.vesync.config_flow")
    mfa = importlib.import_module("custom_components.vesync.mfa")
    importlib.import_module("custom_components.vesync.coordinator")

    # Fail when a new Core platform (such as 2026.11 button) has no proxy.
    # This checks actual imported objects as well as file presence.
    for platform in integration.PLATFORMS:
        platform_name = platform.value
        proxy = importlib.import_module(f"custom_components.vesync.{platform_name}")
        core = importlib.import_module(f"homeassistant.components.vesync.{platform_name}")
        assert proxy.async_setup_entry is core.async_setup_entry
    importlib.import_module("custom_components.vesync.diagnostics")

    manifest = json.loads(
        (ROOT / "custom_components" / "vesync" / "manifest.json").read_text()
    )
    assert manifest["domain"] == "vesync"
    assert manifest["version"] == "1.0.2"
    assert integration.PLATFORMS
    assert mfa.region_for_country("HU") == "EU"
    assert mfa.region_for_country("US") == "US"
    assert mfa.is_mfa_required_error(Exception("user login requires 2fa authentication"))

    flow = flow_module.VeSyncFlowHandler()
    flow.hass = SimpleNamespace(config=SimpleNamespace(country="HU"))
    # Validate the actual schemas, without relying on the former frontend
    # schema-serializer dependency removed from current Home Assistant Core.
    user_data = flow_module.DATA_SCHEMA(
        {"username": "test@example.invalid", "password": "dummy-secret"}
    )
    mfa_data = flow._mfa_schema()(
        {"otp_code": "123456", "country_code": "HU"}
    )
    assert set(user_data) == {"username", "password"}
    assert set(mfa_data) == {"otp_code", "country_code"}

    current = SimpleNamespace(unique_id="12345", data={"username": "same@example.com"})
    assert flow._same_reauth_account(
        current, username="same@example.com", account_id="12345"
    )
    stored_session = SimpleNamespace(
        unique_id="legacy-value",
        data={"username": "old@example.com", "account_id": "67890"},
    )
    assert flow._same_reauth_account(
        stored_session, username="old@example.com", account_id="67890"
    )
    legacy_username = SimpleNamespace(
        unique_id="legacy-value", data={"username": "User@Example.com"}
    )
    assert flow._same_reauth_account(
        legacy_username, username=" user@example.com ", account_id="99999"
    )
    different = SimpleNamespace(
        unique_id="legacy-value", data={"username": "other@example.com"}
    )
    assert not flow._same_reauth_account(
        different, username="user@example.com", account_id="99999"
    )

    print("Production VeSync override import: OK")
    print("Core platform proxy imports: OK")
    print("MFA region/error helpers: OK")
    print("User and MFA form input schemas: OK")
    print("Legacy reauth identity compatibility: OK")


if __name__ == "__main__":
    main()
