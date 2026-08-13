#!/usr/bin/env python3
"""Verify that Home Assistant can serialize the probe's initial config-flow form."""

from __future__ import annotations

from types import SimpleNamespace

from homeassistant.helpers import config_validation as cv
import voluptuous_serialize

from custom_components.vesync_2fa_probe.config_flow import VeSync2FAProbeConfigFlow


def main() -> None:
    flow = VeSync2FAProbeConfigFlow()
    flow.hass = SimpleNamespace(config=SimpleNamespace(country="HU"))

    schema = flow._schema()
    serialized = voluptuous_serialize.convert(
        schema,
        custom_serializer=cv.custom_serializer,
    )

    field_names = {item["name"] for item in serialized}
    assert field_names == {
        "username",
        "password",
        "otp_code",
        "country_code",
        "api_region",
    }

    print("Initial config-flow form serialization: OK")


if __name__ == "__main__":
    main()
