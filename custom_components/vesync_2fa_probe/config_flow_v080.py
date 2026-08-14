"""Config flow implementation for VeSync 2FA Probe 0.8."""

from __future__ import annotations

from typing import Any, override

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.aiohttp_client import async_get_clientsession
import voluptuous as vol

from .const import (
    API_REGION_EU,
    API_REGION_GLOBAL,
    CONF_API_REGION,
    CONF_COUNTRY_CODE,
    DOMAIN,
    EU_COUNTRY_CODES,
)
from .exact_mfa_v080 import ExactMFAError, async_exact_mfa_flow

CONF_OTP_CODE = "otp_code"


class VeSync2FAProbeConfigFlow(ConfigFlow, domain=DOMAIN):
    """Run the HAR-confirmed VeSync MFA flow without creating a config entry."""

    VERSION = 1

    def __init__(self) -> None:
        self._safe_summary: str | None = None
        self._outcome: str | None = None

    def _default_country(self) -> str:
        country = self.hass.config.country
        if isinstance(country, str) and len(country) == 2:
            return country.upper()
        return "US"

    def _schema(self, user_input: dict[str, Any] | None = None) -> vol.Schema:
        values = user_input or {}
        country = str(values.get(CONF_COUNTRY_CODE, self._default_country())).upper()
        inferred_region = API_REGION_EU if country in EU_COUNTRY_CODES else API_REGION_GLOBAL
        return vol.Schema(
            {
                vol.Required(
                    CONF_USERNAME, default=values.get(CONF_USERNAME, "")
                ): cv.string,
                vol.Required(CONF_PASSWORD): cv.string,
                vol.Required(CONF_OTP_CODE): vol.All(
                    cv.string,
                    vol.Length(min=6, max=8),
                ),
                vol.Required(CONF_COUNTRY_CODE, default=country): vol.All(
                    cv.string,
                    vol.Upper,
                    vol.Length(min=2, max=2),
                ),
                vol.Required(
                    CONF_API_REGION,
                    default=values.get(CONF_API_REGION, inferred_region),
                ): vol.In([API_REGION_EU, API_REGION_GLOBAL]),
            }
        )

    @override
    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if user_input is None:
            return self.async_show_form(
                step_id="user", data_schema=self._schema(), errors={}
            )

        username = user_input[CONF_USERNAME]
        password = user_input[CONF_PASSWORD]
        otp_code = user_input[CONF_OTP_CODE]

        if not otp_code.isdigit():
            safe_defaults = {
                CONF_USERNAME: username,
                CONF_COUNTRY_CODE: user_input[CONF_COUNTRY_CODE],
                CONF_API_REGION: user_input[CONF_API_REGION],
            }
            return self.async_show_form(
                step_id="user",
                data_schema=self._schema(safe_defaults),
                errors={CONF_OTP_CODE: "invalid_otp"},
            )

        session = async_get_clientsession(self.hass)
        try:
            result = await async_exact_mfa_flow(
                session,
                username=username,
                password=password,
                otp_code=otp_code,
                country_code=user_input[CONF_COUNTRY_CODE],
                api_region=user_input[CONF_API_REGION],
                time_zone=str(self.hass.config.time_zone),
            )
        except ExactMFAError:
            safe_defaults = {
                CONF_USERNAME: username,
                CONF_COUNTRY_CODE: user_input[CONF_COUNTRY_CODE],
                CONF_API_REGION: user_input[CONF_API_REGION],
            }
            return self.async_show_form(
                step_id="user",
                data_schema=self._schema(safe_defaults),
                errors={"base": "cannot_connect"},
            )

        password = ""
        otp_code = ""
        self._safe_summary = result.safe_summary
        if result.succeeded:
            self._outcome = (
                "The HAR-confirmed MFA flow succeeded and VeSync returned a session token"
            )
        elif result.authorize_code_found:
            self._outcome = (
                "VeSync MFA succeeded and returned an authorizeCode, but the normal "
                "session-token exchange did not complete"
            )
        else:
            self._outcome = (
                "The HAR-confirmed MFA request ran but did not return an authorizeCode"
            )
        return await self.async_step_result()

    async def async_step_result(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        placeholders = {
            "outcome": self._outcome or "No result available",
            "details": self._safe_summary or "no-safe-metadata-returned",
        }
        if user_input is not None:
            return self.async_abort(
                reason="probe_complete", description_placeholders=placeholders
            )
        return self.async_show_form(
            step_id="result",
            data_schema=vol.Schema({}),
            description_placeholders=placeholders,
            errors={},
        )
