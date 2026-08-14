"""VeSync integration with session persistence and authenticator-code reauth."""

from __future__ import annotations

from homeassistant.components.vesync import (
    PLATFORMS,
    async_migrate_entry as core_async_migrate_entry,
    async_remove_config_entry_device as core_async_remove_config_entry_device,
)
from homeassistant.components.vesync.services import async_setup_services
from pyvesync import VeSync
from pyvesync.utils.errors import (
    VeSyncAPIResponseError,
    VeSyncError,
    VeSyncLoginError,
    VeSyncServerError,
    VeSyncTokenError,
)

from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.device_registry import DeviceEntry
from homeassistant.helpers.typing import ConfigType

from .const import (
    CONF_ACCOUNT_ID,
    CONF_COUNTRY_CODE,
    CONF_CURRENT_REGION,
    CONF_SESSION_TOKEN,
    DOMAIN,
)
from .coordinator import VeSyncDataCoordinator
from .session import persist_manager_credentials

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up VeSync services."""
    async_setup_services(hass)
    return True


async def async_setup_entry(hass: HomeAssistant, config_entry) -> bool:
    """Set up VeSync from a stored session, falling back to normal login."""
    username = config_entry.data[CONF_USERNAME]
    password = config_entry.data[CONF_PASSWORD]
    time_zone = str(hass.config.time_zone)

    manager_kwargs = {
        "username": username,
        "password": password,
        "time_zone": time_zone,
        "session": async_get_clientsession(hass),
    }
    country_code = config_entry.data.get(CONF_COUNTRY_CODE)
    if isinstance(country_code, str) and country_code:
        manager_kwargs["country_code"] = country_code
    manager = VeSync(**manager_kwargs)

    token = config_entry.data.get(CONF_SESSION_TOKEN)
    account_id = config_entry.data.get(CONF_ACCOUNT_ID)
    current_region = config_entry.data.get(CONF_CURRENT_REGION)
    if all(isinstance(value, str) and value for value in (token, account_id, country_code, current_region)):
        manager.set_credentials(token, account_id, country_code, current_region)
        manager.enabled = True
    else:
        try:
            await manager.login()
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
        persist_manager_credentials(hass, config_entry, manager)

    try:
        await manager.update()
        await manager.check_firmware()
    except (VeSyncLoginError, VeSyncTokenError) as err:
        raise ConfigEntryAuthFailed(
            translation_domain=DOMAIN, translation_key="invalid_auth"
        ) from err
    except VeSyncServerError as err:
        raise ConfigEntryNotReady(
            translation_domain=DOMAIN, translation_key="server_error"
        ) from err
    except VeSyncError as err:
        raise ConfigEntryNotReady(
            translation_domain=DOMAIN, translation_key="api_response_error"
        ) from err

    persist_manager_credentials(hass, config_entry, manager)
    config_entry.runtime_data = VeSyncDataCoordinator(hass, config_entry, manager)

    if config_entry.minor_version == 2:
        hass.config_entries.async_update_entry(
            config_entry,
            unique_id=manager.account_id,
            minor_version=3,
        )

    await hass.config_entries.async_forward_entry_setups(config_entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry) -> bool:
    """Unload a VeSync config entry."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)


async def async_migrate_entry(hass: HomeAssistant, config_entry) -> bool:
    """Use Home Assistant Core's registry-preserving VeSync migration."""
    return await core_async_migrate_entry(hass, config_entry)


async def async_remove_config_entry_device(
    hass: HomeAssistant, config_entry, device_entry: DeviceEntry
) -> bool:
    """Use Home Assistant Core's VeSync device-removal guard."""
    return await core_async_remove_config_entry_device(hass, config_entry, device_entry)
