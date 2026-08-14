"""Config flow for VeSync with authenticator-code support."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, override

from pyvesync import VeSync
from pyvesync.utils.errors import VeSyncError, VeSyncLoginError
import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import callback
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import (
    CONF_ACCOUNT_ID,
    CONF_COUNTRY_CODE,
    CONF_CURRENT_REGION,
    CONF_OTP_CODE,
    CONF_SESSION_TOKEN,
    DOMAIN,
)
from .mfa import (
    MFAAccountLocked,
    MFAError,
    MFAInvalidCode,
    MFARateLimited,
    async_login_with_otp,
    is_mfa_required_error,
)
from .session import session_data_from_manager

DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_USERNAME): cv.string,
        vol.Required(CONF_PASSWORD): cv.string,
    }
)


class VeSyncFlowHandler(ConfigFlow, domain=DOMAIN):
    """Handle VeSync setup and reauthentication."""

    VERSION = 1
    MINOR_VERSION = 3

    def __init__(self) -> None:
        self._pending_username: str | None = None
        self._pending_password: str | None = None
        self._pending_reauth = False

    def _default_country(self) -> str:
        country = self.hass.config.country
        if isinstance(country, str) and len(country) == 2:
            return country.upper()
        return "US"

    @callback
    def _show_user_form(self, errors: dict[str, str] | None = None) -> ConfigFlowResult:
        return self.async_show_form(
            step_id="user",
            data_schema=DATA_SCHEMA,
            errors=errors or {},
        )

    @callback
    def _show_reauth_form(self, errors: dict[str, str] | None = None) -> ConfigFlowResult:
        entry = self._get_reauth_entry()
        schema = vol.Schema(
            {
                vol.Required(
                    CONF_USERNAME, default=entry.data.get(CONF_USERNAME, "")
                ): cv.string,
                vol.Required(CONF_PASSWORD): cv.string,
            }
        )
        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=schema,
            description_placeholders={"name": "VeSync"},
            errors=errors or {},
        )

    def _mfa_schema(self, values: dict[str, Any] | None = None) -> vol.Schema:
        values = values or {}
        return vol.Schema(
            {
                vol.Required(CONF_OTP_CODE): vol.All(
                    cv.string,
                    vol.Length(min=6, max=8),
                ),
                vol.Required(
                    CONF_COUNTRY_CODE,
                    default=values.get(CONF_COUNTRY_CODE, self._default_country()),
                ): vol.All(cv.string, vol.Upper, vol.Length(min=2, max=2)),
            }
        )

    def _show_mfa_form(
        self,
        *,
        step_id: str,
        values: dict[str, Any] | None = None,
        errors: dict[str, str] | None = None,
    ) -> ConfigFlowResult:
        return self.async_show_form(
            step_id=step_id,
            data_schema=self._mfa_schema(values),
            errors=errors or {},
        )

    def _remember_mfa_credentials(
        self, username: str, password: str, *, reauth: bool
    ) -> None:
        self._pending_username = username
        self._pending_password = password
        self._pending_reauth = reauth

    @staticmethod
    def _same_reauth_account(entry, *, username: str, account_id: str) -> bool:
        """Accept the confirmed account ID or a legacy entry tied to the same username."""
        if entry.unique_id is not None and str(entry.unique_id) == account_id:
            return True
        stored_account_id = entry.data.get(CONF_ACCOUNT_ID)
        if stored_account_id is not None and str(stored_account_id) == account_id:
            return True
        stored_username = entry.data.get(CONF_USERNAME)
        return (
            isinstance(stored_username, str)
            and stored_username.strip().casefold() == username.strip().casefold()
        )

    async def _finish_login(
        self,
        *,
        username: str,
        password: str,
        account_id: str,
        session_data: dict[str, str],
        reauth: bool,
    ) -> ConfigFlowResult:
        await self.async_set_unique_id(account_id)
        data = {
            CONF_USERNAME: username,
            CONF_PASSWORD: password,
            **session_data,
        }
        if reauth:
            entry = self._get_reauth_entry()
            if not self._same_reauth_account(
                entry, username=username, account_id=account_id
            ):
                return self.async_abort(reason="wrong_account")
            return self.async_update_reload_and_abort(
                entry,
                unique_id=account_id,
                data_updates=data,
            )
        self._abort_if_unique_id_configured()
        return self.async_create_entry(title=username, data=data)

    async def _handle_password_login(
        self, *, username: str, password: str, reauth: bool
    ) -> ConfigFlowResult:
        manager = VeSync(
            username,
            password,
            time_zone=str(self.hass.config.time_zone),
            session=async_get_clientsession(self.hass),
        )
        try:
            await manager.login()
        except VeSyncLoginError as err:
            if is_mfa_required_error(err):
                self._remember_mfa_credentials(username, password, reauth=reauth)
                if reauth:
                    return await self.async_step_reauth_mfa()
                return await self.async_step_mfa()
            if reauth:
                return self._show_reauth_form(errors={"base": "invalid_auth"})
            return self._show_user_form(errors={"base": "invalid_auth"})
        except VeSyncError:
            if reauth:
                return self._show_reauth_form(errors={"base": "invalid_auth"})
            return self._show_user_form(errors={"base": "invalid_auth"})

        session_data = session_data_from_manager(manager)
        account_id = session_data.get(CONF_ACCOUNT_ID)
        if not account_id:
            if reauth:
                return self._show_reauth_form(errors={"base": "invalid_auth"})
            return self._show_user_form(errors={"base": "invalid_auth"})
        return await self._finish_login(
            username=username,
            password=password,
            account_id=account_id,
            session_data=session_data,
            reauth=reauth,
        )

    async def _handle_mfa(
        self,
        user_input: dict[str, Any] | None,
        *,
        step_id: str,
        reauth: bool,
    ) -> ConfigFlowResult:
        if user_input is None:
            return self._show_mfa_form(step_id=step_id)
        username = self._pending_username
        password = self._pending_password
        if not username or password is None:
            if reauth:
                return self._show_reauth_form(errors={"base": "invalid_auth"})
            return self._show_user_form(errors={"base": "invalid_auth"})
        otp_code = str(user_input[CONF_OTP_CODE])
        country_code = str(user_input[CONF_COUNTRY_CODE]).upper()
        if not otp_code.isdigit():
            return self._show_mfa_form(
                step_id=step_id,
                values={CONF_COUNTRY_CODE: country_code},
                errors={CONF_OTP_CODE: "invalid_otp"},
            )
        try:
            credentials = await async_login_with_otp(
                async_get_clientsession(self.hass),
                username=username,
                password=password,
                otp_code=otp_code,
                country_code=country_code,
                time_zone=str(self.hass.config.time_zone),
            )
        except MFAInvalidCode:
            return self._show_mfa_form(
                step_id=step_id,
                values={CONF_COUNTRY_CODE: country_code},
                errors={CONF_OTP_CODE: "invalid_otp"},
            )
        except MFARateLimited:
            return self._show_mfa_form(
                step_id=step_id,
                values={CONF_COUNTRY_CODE: country_code},
                errors={"base": "rate_limited"},
            )
        except MFAAccountLocked:
            return self._show_mfa_form(
                step_id=step_id,
                values={CONF_COUNTRY_CODE: country_code},
                errors={"base": "account_locked"},
            )
        except MFAError:
            return self._show_mfa_form(
                step_id=step_id,
                values={CONF_COUNTRY_CODE: country_code},
                errors={"base": "mfa_failed"},
            )

        session_data = {
            CONF_SESSION_TOKEN: credentials.token,
            CONF_ACCOUNT_ID: credentials.account_id,
            CONF_COUNTRY_CODE: credentials.country_code,
            CONF_CURRENT_REGION: credentials.current_region,
        }
        self._pending_password = None
        return await self._finish_login(
            username=username,
            password=password,
            account_id=credentials.account_id,
            session_data=session_data,
            reauth=reauth,
        )

    @override
    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if not user_input:
            return self._show_user_form()
        return await self._handle_password_login(
            username=user_input[CONF_USERNAME],
            password=user_input[CONF_PASSWORD],
            reauth=False,
        )

    async def async_step_mfa(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        return await self._handle_mfa(user_input, step_id="mfa", reauth=False)

    async def async_step_reauth(
        self, entry_data: Mapping[str, Any]
    ) -> ConfigFlowResult:
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if not user_input:
            return self._show_reauth_form()
        return await self._handle_password_login(
            username=user_input[CONF_USERNAME],
            password=user_input[CONF_PASSWORD],
            reauth=True,
        )

    async def async_step_reauth_mfa(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        return await self._handle_mfa(
            user_input, step_id="reauth_mfa", reauth=True
        )
