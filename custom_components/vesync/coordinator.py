"""VeSync coordinator with session persistence."""

from typing import override

from homeassistant.components.vesync.coordinator import (
    VeSyncDataCoordinator as CoreVeSyncDataCoordinator,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed

from .const import DOMAIN
from .session import merged_with_session


class VeSyncDataCoordinator(CoreVeSyncDataCoordinator):
    """Keep the reusable VeSync session in sync with the config entry."""

    @override
    async def _async_update_data(self) -> None:
        await super()._async_update_data()

        # pyvesync marks the manager disabled when a token is rejected and its
        # automatic password reauthentication cannot recover. The Core
        # coordinator turns device-level VeSync errors into update failures (and
        # pyvesync may log/suppress them inside concurrent device updates), so
        # explicitly surface the resulting authentication state to Home
        # Assistant. This makes a revoked saved session become a normal reauth
        # flow instead of leaving the integration silently stale.
        if not self.manager.enabled:
            raise ConfigEntryAuthFailed(
                translation_domain=DOMAIN, translation_key="invalid_auth"
            )

        data = merged_with_session(self.config_entry.data, self.manager)
        if data != self.config_entry.data:
            self.hass.config_entries.async_update_entry(self.config_entry, data=data)


type VesyncConfigEntry = ConfigEntry[VeSyncDataCoordinator]
