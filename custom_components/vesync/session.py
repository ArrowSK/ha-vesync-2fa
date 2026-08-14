"""Session persistence helpers for VeSync 2FA."""

from __future__ import annotations

from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import (
    CONF_ACCOUNT_ID,
    CONF_COUNTRY_CODE,
    CONF_CURRENT_REGION,
    CONF_SESSION_TOKEN,
)


def session_data_from_manager(manager: Any) -> dict[str, str]:
    """Return the persistent session fields exposed by pyvesync."""
    credentials = manager.output_credentials_dict()
    if not credentials:
        return {}
    return {
        CONF_SESSION_TOKEN: credentials["token"],
        CONF_ACCOUNT_ID: credentials["account_id"],
        CONF_COUNTRY_CODE: credentials["country_code"],
        CONF_CURRENT_REGION: credentials["current_region"],
    }


def persist_manager_credentials(
    hass: HomeAssistant, config_entry: ConfigEntry, manager: Any
) -> None:
    """Persist a changed pyvesync session without reloading the config entry."""
    session_data = session_data_from_manager(manager)
    if not session_data:
        return
    new_data = {**config_entry.data, **session_data}
    if new_data != config_entry.data:
        hass.config_entries.async_update_entry(config_entry, data=new_data)
