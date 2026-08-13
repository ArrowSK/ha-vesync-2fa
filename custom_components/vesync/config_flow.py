"""Config flow for VeSync with native MFA challenge discovery."""

from collections.abc import Mapping
from typing import Any, override

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import callback
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from pyvesync import VeSync
from pyvesync.utils.errors import VeSyncError
import voluptuous as vol

from .auth import VeSyncMFARequired, async_authenticate
from .const import DOMAIN
from .session import merged_with_session

DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_USERNAME): cv.string,
        vol.Required(CONF_PASSWORD): cv.string,
    }
)


class VeSyncFlowHandler(ConfigFlow, domain=DOMAIN):
    """Handle VeSync setup and reauthentication."""

    # Keep these aligned with Home Assistant Core 2026.8.0. Additional session
    # fields are optional and do not require a config-entry migration.
    VERSION = 1
    MINOR_VERSION = 3

    def __init__(self) -> None:
        """Initialize flow-local MFA discovery state."""
        self._mfa_summary: str | None = None

    @callback
    def _show_form(self, errors: dict[str, str] | None = None) -> ConfigFlowResult:
        """Show the initial login form."""
        return self.async_show_form(
            step_id="user",
            data_schema=DATA_SCHEMA,
            errors=errors or {},
        )

    async def _try_login(self, username: str, password: str) -> VeSync:
        """Authenticate and return a VeSync manager."""
        manager = VeSync(
            username,
            password,
            time_zone=str(self.hass.config.time_zone),
            session=async_get_clientsession(self.hass),
        )
        await async_authenticate(manager, username=username, password=password)
        return manager

    async def _capture_mfa(self, error: VeSyncMFARequired) -> ConfigFlowResult:
        """Store only public-safe challenge metadata and show the discovery step."""
        self._mfa_summary = error.challenge.safe_summary
        return await self.async_step_mfa_challenge()

    @override
    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle a user-initiated setup."""
        if not user_input:
            return self._show_form()

        username = user_input[CONF_USERNAME]
        password = user_input[CONF_PASSWORD]

        try:
            manager = await self._try_login(username, password)
        except VeSyncMFARequired as err:
            return await self._capture_mfa(err)
        except VeSyncError:
            return self._show_form(errors={"base": "invalid_auth"})

        await self.async_set_unique_id(manager.account_id)
        self._abort_if_unique_id_configured()

        data = merged_with_session(
            {CONF_USERNAME: username, CONF_PASSWORD: password}, manager
        )
        return self.async_create_entry(title=username, data=data)

    async def async_step_mfa_challenge(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Show sanitized metadata for a real VeSync MFA challenge.

        Version 0.2.0 intentionally stops here. The response proves the account
        reached VeSync's MFA branch, but the OTP submission request itself has not
        yet been verified. Asking for a code before that would imply support that
        does not exist and risks locking accounts through guessed API calls.
        """
        if user_input is not None:
            return self.async_abort(
                reason="mfa_protocol_unverified",
                description_placeholders={
                    "details": self._mfa_summary or "no-safe-metadata-returned"
                },
            )

        return self.async_show_form(
            step_id="mfa_challenge",
            data_schema=vol.Schema({}),
            description_placeholders={
                "details": self._mfa_summary or "no-safe-metadata-returned"
            },
            errors={},
        )

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

            try:
                manager = await self._try_login(username, password)
            except VeSyncMFARequired as err:
                return await self._capture_mfa(err)
            except VeSyncError:
                return self.async_show_form(
                    step_id="reauth_confirm",
                    data_schema=DATA_SCHEMA,
                    description_placeholders={"name": "VeSync"},
                    errors={"base": "invalid_auth"},
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
