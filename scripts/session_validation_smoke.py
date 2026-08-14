#!/usr/bin/env python3
"""Exercise 0.9 session validation without network access or real credentials."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from custom_components.vesync_2fa_probe.exact_mfa_v080 import Attempt, ExactFlowResult
import custom_components.vesync_2fa_probe.session_validation_v090 as validation


@dataclass
class FakeDevice:
    cid: str
    sub_device_no: int | None = None


class FakeVeSync:
    """Minimal pyvesync stand-in used only by this offline smoke test."""

    def __init__(self, **kwargs):
        assert kwargs["username"] == ""
        assert kwargs["password"] == ""
        self.devices = [FakeDevice("device-a"), FakeDevice("device-b", 2)]
        self.enabled = False
        self.credentials = None

    def set_credentials(self, token, account_id, country_code, region):
        assert token == "test-session-token"
        assert account_id == "test-account"
        assert country_code == "HU"
        assert region == "EU"
        self.credentials = (token, account_id, country_code, region)

    async def get_devices(self):
        assert self.credentials is not None
        return True


class FakeConfigEntries:
    def __init__(self):
        manager = SimpleNamespace(
            devices=[FakeDevice("device-a"), FakeDevice("device-b", 2)]
        )
        self._entries = [SimpleNamespace(runtime_data=SimpleNamespace(manager=manager))]

    def async_entries(self, domain):
        assert domain == "vesync"
        return self._entries


async def run() -> None:
    original = validation.VeSync
    validation.VeSync = FakeVeSync
    try:
        exact = ExactFlowResult(
            attempts=(
                Attempt(
                    label="token_exchange",
                    http_status=200,
                    server_code=0,
                    message_class="success",
                    result_keys=("accountID", "token"),
                    token="test-session-token",
                    account_id="test-account",
                ),
            ),
            account_host="global",
        )
        hass = SimpleNamespace(config_entries=FakeConfigEntries())
        result = await validation.async_validate_session(
            hass,
            session=None,
            exact_result=exact,
            country_code="HU",
            api_region="EU",
            time_zone="Europe/Budapest",
        )
        assert result.device_list_ok is True
        assert result.device_count == 2
        assert result.core_entry_count == 1
        assert result.core_loaded is True
        assert result.core_device_count == 2
        assert result.identity_match is True
        assert (
            result.safe_summary
            == "session_validation=device_list=ok;devices=2;core_entries=1;"
            "core_loaded=yes;core_devices=2;identity_match=yes"
        )
        assert "test-session-token" not in result.safe_summary
        assert "test-account" not in result.safe_summary
    finally:
        validation.VeSync = original

    print("Read-only MFA session hydration: OK")
    print("Core device identity comparison: OK")
    print("Safe session metadata: OK")


if __name__ == "__main__":
    asyncio.run(run())
