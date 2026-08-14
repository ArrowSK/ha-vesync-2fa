"""Config flow implementation for VeSync 2FA Probe 0.9."""

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
from .session_validation_v090 import async_validate_session

CONF_OTP_CODE = "otp_code"


class VeSync2FAProbeConfigFlow(ConfigFlow, domain=DOMAIN):
    """Run exact MFA auth plus a read-only pyvesync session check."""

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
        time_zone = str(self.hass.config.time_zone)
        try:
            exact = await async_exact_mfa_flow(
                session,
                username=username,
                password=password,
                otp_code=otp_code,
                country_code=user_input[CONF_COUNTRY_CODE],
                api_region=user_input[CONF_API_REGION],
                time_zone=time_zone,
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

        safe_lines = [exact.safe_summary]
        validation = None
        if exact.succeeded:
            validation = await async_validate_session(
                self.hass,
                session=session,
                exact_result=exact,
                country_code=user_input[CONF_COUNTRY_CODE],
                api_region=user_input[CONF_API_REGION],
                time_zone=time_zone,
            )
            safe_lines.append(validation.safe_summary)

        # Drop the only local plaintext references before rendering the result.
        password = ""
        otp_code = ""
        self._safe_summary = "\n".join(safe_lines)

        if validation is not None and validation.device_list_ok:
            if validation.identity_match is True:
                self._outcome = (
                    "The MFA session token works with pyvesync and discovers the same "
                    "device identity set as the loaded Home Assistant VeSync integration"
                )
            elif validation.identity_match is False:
                self._outcome = (
                    "The MFA session token works with pyvesync, but its discovered device "
                    "identity set differs from the loaded Home Assistant VeSync integration"
                )
            else:
                self._outcome = (
                    "The MFA session token works with pyvesync and the read-only device "
                    "list succeeded; no single loaded Core VeSync manager was available "
                    "for identity comparison"
                )
        elif exact.succeeded:
            self._outcome = (
                "The HAR-confirmed MFA flow returned a session token, but the read-only "
                "pyvesync device-list validation did not succeed"
            )
        elif exact.authorize_code_found:
            self._outcome = (
                "VeSync MFA returned an authorizeCode, but the normal session-token "
                "exchange did not complete"
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
