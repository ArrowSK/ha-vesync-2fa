#!/usr/bin/env python3
"""Runtime checks for the production same-domain VeSync 2FA layer."""

from __future__ import annotations

import importlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

from homeassistant.helpers import config_validation as cv
import voluptuous_serialize

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main() -> None:
    integration = importlib.import_module("custom_components.vesync")
    flow_module = importlib.import_module("custom_components.vesync.config_flow")
    mfa = importlib.import_module("custom_components.vesync.mfa")
    importlib.import_module("custom_components.vesync.coordinator")

    for platform in (
        "binary_sensor", "fan", "humidifier", "light", "number",
        "select", "sensor", "switch", "update", "diagnostics",
    ):
        importlib.import_module(f"custom_components.vesync.{platform}")

    manifest = json.loads(
        (ROOT / "custom_components" / "vesync" / "manifest.json").read_text()
    )
    assert manifest["domain"] == "vesync"
    assert manifest["version"] == "1.0.0"
    assert integration.PLATFORMS
    assert mfa.region_for_country("HU") == "EU"
    assert mfa.region_for_country("US") == "US"
    assert mfa.is_mfa_required_error(Exception("user login requires 2fa authentication"))

    flow = flow_module.VeSyncFlowHandler()
    flow.hass = SimpleNamespace(config=SimpleNamespace(country="HU"))
    serialized_user = voluptuous_serialize.convert(
        flow_module.DATA_SCHEMA, custom_serializer=cv.custom_serializer
    )
    serialized_mfa = voluptuous_serialize.convert(
        flow._mfa_schema(), custom_serializer=cv.custom_serializer
    )
    assert len(serialized_user) == 2
    assert len(serialized_mfa) == 2

    print("Production VeSync override import: OK")
    print("Core platform proxy imports: OK")
    print("MFA region/error helpers: OK")
    print("User and MFA form serialization: OK")


if __name__ == "__main__":
    main()
