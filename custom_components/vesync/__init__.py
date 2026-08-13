"""VeSync integration override with MFA-aware authentication.

This custom integration deliberately stays close to Home Assistant's built-in
VeSync integration. Device/entity implementations remain upstream; authentication
and reusable-session handling are the only overridden layers.
"""

import logging

from homeassistant.components.vesync import (
    CONFIG_SCHEMA,
    PLATFORMS,
    async_migrate_entry as _core_async_migrate_entry,
    async_remove_config_entry_device as _core_async_remove_config_entry_device,
)
from homeassistant.components.vesync.services import async_setup_services
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.device_registry import DeviceEntry
from homeassistant.helpers.typing import ConfigType
from pyvesync import VeSync
from pyvesync.utils.errors import (
    VeSyncAPIResponseError,
    VeSyncLoginError,
    VeSyncServerError,
    VeSyncTokenError,
)

from .auth import VeSyncMFARequired, async_authenticate
from .const import DOMAIN
from .coordinator import VesyncConfigEntry, VeSyncDataCoordinator
from .session import merged_with_session, restore_session

_LOGGER = logging.getLogger(__name__)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up VeSync services."""
    async_setup_services(hass)
    return True


async def async_setup_entry(
    hass: HomeAssistant, config_entry: VesyncConfigEntry
) -> bool:
    """Set up a VeSync config entry, preferring a saved authenticated session."""
    username = config_entry.data[CONF_USERNAME]
    password = config_entry.data[CONF_PASSWORD]
    time_zone = str(hass.config.time_zone)

    manager = VeSync(
        username=username,
        password=password,
        time_zone=time_zone,
        session=async_get_clientsession(hass),
    )

    used_saved_session = restore_session(manager, config_entry.data)

    try:
        if not used_saved_session:
            await async_authenticate(manager)
        await manager.update()
        await manager.check_firmware()
    except VeSyncMFARequired as err:
        # A background setup cannot collect an MFA code. Route the entry into
        # Home Assistant's reauthentication flow, where the interactive config
        # flow can expose the sanitized challenge metadata.
        raise ConfigEntryAuthFailed(
            translation_domain=DOMAIN, translation_key="mfa_required"
        ) from err
    except (VeSyncLoginError, VeSyncTokenError) as err:
        raise ConfigEntryAuthFailed(
            translation_domain=DOMAIN, translation_key="invalid_auth"
        ) from err
    except VeSyncServerError as err:
        raise ConfigEntryNotReady(
            translation_domain=DOMAIN, translation_key="server_error"
        ) from err
    except VeSyncAPIResponseError as err:
        raise ConfigEntryNotReady(
            translation_domain=DOMAIN, translation_key="api_response_error"
        ) from err

    updated_data = merged_with_session(config_entry.data, manager)
    if updated_data != config_entry.data:
        hass.config_entries.async_update_entry(config_entry, data=updated_data)

    config_entry.runtime_data = VeSyncDataCoordinator(hass, config_entry, manager)

    # Preserve the built-in integration's account-ID migration exactly.
    if config_entry.minor_version == 2:
        hass.config_entries.async_update_entry(
            config_entry,
            unique_id=manager.account_id,
            minor_version=3,
        )

    await hass.config_entries.async_forward_entry_setups(config_entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: VesyncConfigEntry) -> bool:
    """Unload a VeSync config entry."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)


async def async_migrate_entry(
    hass: HomeAssistant, config_entry: VesyncConfigEntry
) -> bool:
    """Delegate registry migrations to the built-in VeSync integration."""
    return await _core_async_migrate_entry(hass, config_entry)


async def async_remove_config_entry_device(
    hass: HomeAssistant, config_entry: VesyncConfigEntry, device_entry: DeviceEntry
) -> bool:
    """Delegate device removal checks to the built-in VeSync integration."""
    return await _core_async_remove_config_entry_device(hass, config_entry, device_entry)
