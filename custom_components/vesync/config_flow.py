"""Config flow for the VeSync session bridge."""

from collections.abc import Mapping
import logging
from typing import Any, override

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import callback
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from pyvesync import VeSync
from pyvesync.utils.errors import VeSyncError
import voluptuous as vol

from .const import DOMAIN
from .session import merged_with_session

_LOGGER = logging.getLogger(__name__)

DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_USERNAME): cv.string,
        vol.Required(CONF_PASSWORD): cv.string,
    }
)


def _requires_two_factor(error: VeSyncError) -> bool:
    """Return True for VeSync's known account-level 2FA rejection."""
    message = str(error).casefold()
    return "requires 2fa" in message or "2fa authentication" in message


class VeSyncFlowHandler(ConfigFlow, domain=DOMAIN):
    """Handle VeSync setup and reauthentication."""

    # Keep these aligned with Home Assistant Core 2026.8.0. The additional
    # session fields are optional and do not require a config-entry migration.
    VERSION = 1
    MINOR_VERSION = 3

    @callback
    def _show_form(self, errors: dict[str, str] | None = None) -> ConfigFlowResult:
        """Show the initial login form."""
        return self.async_show_form(
            step_id="user",
            data_schema=DATA_SCHEMA,
            errors=errors or {},
        )

    @override
    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle a user-initiated setup."""
        if not user_input:
            return self._show_form()

        username = user_input[CONF_USERNAME]
        password = user_input[CONF_PASSWORD]
        manager = VeSync(
            username,
            password,
            time_zone=str(self.hass.config.time_zone),
            session=async_get_clientsession(self.hass),
        )

        try:
            await manager.login()
        except VeSyncError as err:
            _LOGGER.warning("VeSync login failed: %s", err)
            error = "two_factor_required" if _requires_two_factor(err) else "invalid_auth"
            return self._show_form(errors={"base": error})

        await self.async_set_unique_id(manager.account_id)
        self._abort_if_unique_id_configured()

        data = merged_with_session(
            {CONF_USERNAME: username, CONF_PASSWORD: password}, manager
        )
        return self.async_create_entry(title=username, data=data)

    async def async_step_reauth(
        self, entry_data: Mapping[str, Any]
    ) -> ConfigFlowResult:
        """Start VeSync reauthentication."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Confirm VeSync reauthentication."""
        if user_input:
            username = user_input[CONF_USERNAME]
            password = user_input[CONF_PASSWORD]
            manager = VeSync(
                username,
                password,
                time_zone=str(self.hass.config.time_zone),
                session=async_get_clientsession(self.hass),
            )

            try:
                await manager.login()
            except VeSyncError as err:
                _LOGGER.warning("VeSync reauthentication failed: %s", err)
                error = (
                    "two_factor_required" if _requires_two_factor(err) else "invalid_auth"
                )
                return self.async_show_form(
                    step_id="reauth_confirm",
                    data_schema=DATA_SCHEMA,
                    description_placeholders={"name": "VeSync"},
                    errors={"base": error},
                )

            await self.async_set_unique_id(manager.account_id)
            self._abort_if_unique_id_mismatch(reason="wrong_account")

            current_data = dict(self._get_reauth_entry().data)
            current_data.update({CONF_USERNAME: username, CONF_PASSWORD: password})
            current_data = merged_with_session(current_data, manager)

            return self.async_update_reload_and_abort(
                self._get_reauth_entry(),
                unique_id=manager.account_id,
                data_updates=current_data,
            )

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=DATA_SCHEMA,
            description_placeholders={"name": "VeSync"},
            errors={},
        )
