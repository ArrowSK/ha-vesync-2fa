"""VeSync coordinator with session persistence and authentication recovery."""

from typing import override

from homeassistant.components.vesync.coordinator import (
    VeSyncDataCoordinator as CoreVeSyncDataCoordinator,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import UpdateFailed

from .const import DOMAIN
from .session import merged_with_session


class VeSyncDataCoordinator(CoreVeSyncDataCoordinator):
    """Keep the reusable VeSync session in sync with the config entry."""

    @override
    async def _async_update_data(self) -> None:
        try:
            await super()._async_update_data()
        except UpdateFailed as err:
            # pyvesync automatically attempts password reauthentication when a
            # token is rejected. With account-level MFA that password-only retry
            # cannot complete. If pyvesync has already marked the manager
            # unauthenticated, turn the polling failure into Home Assistant's
            # interactive reauthentication flow instead of leaving stale data.
            if not self.manager.enabled:
                raise ConfigEntryAuthFailed(
                    translation_domain=DOMAIN, translation_key="mfa_required"
                ) from err
            raise

        # Device update tasks inside pyvesync can log/suppress their own VeSync
        # errors. Check the final manager state even when Core did not raise.
        if not self.manager.enabled:
            raise ConfigEntryAuthFailed(
                translation_domain=DOMAIN, translation_key="mfa_required"
            )

        data = merged_with_session(self.config_entry.data, self.manager)
        if data != self.config_entry.data:
            self.hass.config_entries.async_update_entry(self.config_entry, data=data)


type VesyncConfigEntry = ConfigEntry[VeSyncDataCoordinator]
