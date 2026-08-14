"""Non-invasive VeSync MFA protocol probe.

This integration intentionally does not replace Home Assistant's built-in
``vesync`` integration. It runs the separately confirmed account-level MFA
flow, reduces responses to public-safe metadata, and creates no persistent
config entry, entity or device.
"""

from homeassistant.core import HomeAssistant
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.typing import ConfigType

from .const import DOMAIN

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up the VeSync 2FA probe."""
    return True
