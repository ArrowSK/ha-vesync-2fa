#!/usr/bin/env python3
"""Smoke-test the custom component against the pinned Home Assistant runtime."""

from __future__ import annotations

import importlib
from pathlib import Path
import sys

from pyvesync import VeSync

# Running a script by path puts the scripts directory, rather than the repository
# root, first on sys.path. Add the root explicitly so this check imports the
# custom component exactly from the checked-out repository.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

MODULES = (
    "custom_components.vesync",
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
    """Import every module and verify the pyvesync session round trip."""
    for module in MODULES:
        importlib.import_module(module)

    from custom_components.vesync.session import restore_session, session_data

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

    print("Home Assistant module imports: OK")
    print("pyvesync session save/restore round trip: OK")


if __name__ == "__main__":
    main()
