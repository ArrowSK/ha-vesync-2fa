#!/usr/bin/env python3
"""Verify that Home Assistant can serialize the probe's initial config-flow form."""

from __future__ import annotations

from pathlib import Path
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from homeassistant.helpers import config_validation as cv
import voluptuous_serialize
from custom_components.vesync_2fa_probe.config_flow import VeSync2FAProbeConfigFlow


def main() -> None:
    flow = VeSync2FAProbeConfigFlow()
    flow.hass = SimpleNamespace(config=SimpleNamespace(country="HU"))
    serialized = voluptuous_serialize.convert(
        flow._schema(),
        custom_serializer=cv.custom_serializer,
    )
    assert len(serialized) == 5
    print("Initial config-flow form serialization: OK")


if __name__ == "__main__":
    main()
