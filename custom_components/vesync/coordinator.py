"""VeSync coordinator with Home Assistant reauth on an expired MFA session."""

from __future__ import annotations

from typing import override

from homeassistant.components.vesync.coordinator import (
    VeSyncDataCoordinator as CoreVeSyncDataCoordinator,
)
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import UpdateFailed
from pyvesync.utils.errors import VeSyncLoginError, VeSyncTokenError

from .session import persist_manager_credentials


class VeSyncDataCoordinator(CoreVeSyncDataCoordinator):
    """Keep Core update behavior while persisting refreshed sessions."""

    @override
    async def _async_update_data(self) -> None:
        try:
            await super()._async_update_data()
        except UpdateFailed as err:
            if isinstance(err.__cause__, (VeSyncLoginError, VeSyncTokenError)):
                raise ConfigEntryAuthFailed("VeSync authentication expired") from err
            raise

        # pyvesync can swallow a device-task authentication exception after its
        # internal reauthentication attempt. In that case it leaves the manager
        # disabled; surface this as a normal Home Assistant reauth request.
        if not self.manager.enabled:
            raise ConfigEntryAuthFailed("VeSync authentication expired")

        persist_manager_credentials(self.hass, self.config_entry, self.manager)
