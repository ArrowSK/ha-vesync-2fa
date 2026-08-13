"""Compatibility entry point for the current VeSync 2FA Probe config flow."""

from typing import Any

from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.helpers import config_validation as cv
import voluptuous as vol

from .config_flow_v070 import CONF_OTP_CODE, VeSync2FAProbeConfigFlow
from .const import (
    API_REGION_EU,
    API_REGION_GLOBAL,
    CONF_API_REGION,
    CONF_COUNTRY_CODE,
    EU_COUNTRY_CODES,
)


def _serializable_schema(
    self: VeSync2FAProbeConfigFlow,
    user_input: dict[str, Any] | None = None,
) -> vol.Schema:
    """Build a config-flow schema Home Assistant can serialize for the frontend."""
    values = user_input or {}
    country = str(values.get(CONF_COUNTRY_CODE, self._default_country())).upper()
    inferred_region = API_REGION_EU if country in EU_COUNTRY_CODES else API_REGION_GLOBAL
    return vol.Schema(
        {
            vol.Required(CONF_USERNAME, default=values.get(CONF_USERNAME, "")): cv.string,
            vol.Required(CONF_PASSWORD): cv.string,
            vol.Required(CONF_OTP_CODE): vol.All(
                cv.string,
                vol.Length(min=6, max=8),
            ),
            vol.Required(CONF_COUNTRY_CODE, default=country): vol.All(
                cv.string,
                vol.Upper,
                vol.Length(min=2, max=2),
            ),
            vol.Required(
                CONF_API_REGION,
                default=values.get(CONF_API_REGION, inferred_region),
            ): vol.In([API_REGION_EU, API_REGION_GLOBAL]),
        }
    )


# Home Assistant serializes config-flow schemas before sending them to the
# frontend. The regex validator used by 0.7.0 is not supported by
# voluptuous-serialize and caused the generic HTTP 500 before the form could be
# displayed. Patch only the schema builder; authentication behavior is
# otherwise unchanged from the tested 0.7 implementation.
VeSync2FAProbeConfigFlow._schema = _serializable_schema

__all__ = ["VeSync2FAProbeConfigFlow"]
