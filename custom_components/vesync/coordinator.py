"""VeSync coordinator with session persistence."""

from typing import override

from homeassistant.components.vesync.coordinator import (
    VeSyncDataCoordinator as CoreVeSyncDataCoordinator,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .session import merged_with_session


class VeSyncDataCoordinator(CoreVeSyncDataCoordinator):
    """Keep the reusable VeSync session in sync with the config entry."""

    @override
    async def _async_update_data(self) -> None:
        await super()._async_update_data()
        data = merged_with_session(self.config_entry.data, self.manager)
        if data != self.config_entry.data:
            self.hass.config_entries.async_update_entry(self.config_entry, data=data)


type VesyncConfigEntry = ConfigEntry[VeSyncDataCoordinator]
