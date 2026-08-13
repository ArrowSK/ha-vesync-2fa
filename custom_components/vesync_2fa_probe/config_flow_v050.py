"""Config flow implementation for VeSync 2FA Probe 0.5."""

from __future__ import annotations

from typing import Any, override

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.aiohttp_client import async_get_clientsession
import voluptuous as vol

from .auth import ProbeResult, VeSyncProbeError, async_probe_auth_with_context
from .const import API_REGION_EU, API_REGION_GLOBAL, CONF_API_REGION, CONF_COUNTRY_CODE, DOMAIN, EU_COUNTRY_CODES
from .continuation_v050 import async_probe_continuation_ladder


def _friendly_outcome(result: ProbeResult, ladder_ran: bool) -> str:
    if result.outcome == "mfa_required" and ladder_ran:
        return "VeSync returned an MFA challenge and the no-code continuation ladder ran"
    if result.outcome == "mfa_required":
        return "VeSync returned an MFA challenge"
    if result.outcome == "password_accepted":
        return "VeSync accepted the password without an MFA challenge"
    return "VeSync rejected the first-stage sign-in request"


class VeSync2FAProbeConfigFlow(ConfigFlow, domain=DOMAIN):
    """Run bounded VeSync MFA discovery without creating a config entry."""

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
                vol.Required(CONF_USERNAME, default=values.get(CONF_USERNAME, "")): cv.string,
                vol.Required(CONF_PASSWORD, default=values.get(CONF_PASSWORD, "")): cv.string,
                vol.Required(CONF_COUNTRY_CODE, default=country): vol.All(cv.string, vol.Upper, vol.Length(min=2, max=2)),
                vol.Required(CONF_API_REGION, default=values.get(CONF_API_REGION, inferred_region)): vol.In([API_REGION_EU, API_REGION_GLOBAL]),
            }
        )

    @override
    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        if user_input is None:
            return self.async_show_form(step_id="user", data_schema=self._schema(), errors={})

        username = user_input[CONF_USERNAME]
        password = user_input[CONF_PASSWORD]
        session = async_get_clientsession(self.hass)

        try:
            exchange = await async_probe_auth_with_context(
                session,
                username=username,
                password=password,
                country_code=user_input[CONF_COUNTRY_CODE],
                api_region=user_input[CONF_API_REGION],
                time_zone=str(self.hass.config.time_zone),
            )
        except VeSyncProbeError:
            return self.async_show_form(step_id="user", data_schema=self._schema(user_input), errors={"base": "cannot_connect"})

        result = exchange.result
        safe_lines = [result.safe_summary]
        ladder_ran = False
        advertised_methods = {method.casefold() for method in result.methods}

        if result.outcome == "mfa_required" and exchange.challenge is not None and "otp" in advertised_methods:
            ladder = await async_probe_continuation_ladder(session, exchange.challenge, password)
            safe_lines.append(ladder.safe_summary)
            ladder_ran = True

        self._safe_summary = "\n".join(safe_lines)
        self._outcome = _friendly_outcome(result, ladder_ran)
        return await self.async_step_result()

    async def async_step_result(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        placeholders = {
            "outcome": self._outcome or "No result available",
            "details": self._safe_summary or "no-safe-metadata-returned",
        }
        if user_input is not None:
            return self.async_abort(reason="probe_complete", description_placeholders=placeholders)
        return self.async_show_form(step_id="result", data_schema=vol.Schema({}), description_placeholders=placeholders, errors={})
