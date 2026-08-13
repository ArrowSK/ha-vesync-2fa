"""Non-invasive VeSync MFA protocol probe.

This integration intentionally does not replace Home Assistant's built-in
``vesync`` integration. It exists only to inspect the first VeSync
password-authentication response and expose a redacted summary of an MFA
challenge.
"""

from homeassistant.core import HomeAssistant
from homeassistant.helpers.typing import ConfigType


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up the VeSync 2FA probe."""
    return True
