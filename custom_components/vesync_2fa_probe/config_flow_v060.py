"""Config flow implementation for VeSync 2FA Probe 0.6."""

from __future__ import annotations

from hashlib import md5
from typing import Any, override

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.aiohttp_client import async_get_clientsession
import voluptuous as vol

from .auth import ChallengeContext, ProbeResult, VeSyncProbeError, async_probe_auth_with_context
from .const import (
    API_REGION_EU,
    API_REGION_GLOBAL,
    CONF_API_REGION,
    CONF_COUNTRY_CODE,
    DOMAIN,
    EU_COUNTRY_CODES,
)
from .continuation_v060 import (
    PreflightResult,
    async_probe_otp_ladder,
    async_probe_preflight,
)

CONF_OTP_CODE = "otp_code"


def _friendly_outcome(result: ProbeResult, *, otp_ran: bool, success: bool) -> str:
    if success:
        return "VeSync accepted one of the MFA continuation hypotheses"
    if result.outcome == "mfa_required" and otp_ran:
        return "VeSync returned an MFA challenge and the one-code hypothesis ladder ran"
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
        self._initial_result: ProbeResult | None = None
        self._challenge: ChallengeContext | None = None
        self._password_hash: str | None = None
        self._preflight: PreflightResult | None = None

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
                vol.Required(CONF_COUNTRY_CODE, default=country): vol.All(
                    cv.string, vol.Upper, vol.Length(min=2, max=2)
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
            return self.async_show_form(
                step_id="user",
                data_schema=self._schema(user_input),
                errors={"base": "cannot_connect"},
            )

        result = exchange.result
        self._initial_result = result
        self._safe_summary = result.safe_summary
        self._challenge = exchange.challenge

        advertised_methods = {method.casefold() for method in result.methods}
        if (
            result.outcome == "mfa_required"
            and exchange.challenge is not None
            and "otp" in advertised_methods
        ):
            # Keep only the already-hashed password for the continuation step.
            # Plaintext is not stored on the flow object.
            self._password_hash = md5(password.encode("utf-8")).hexdigest()  # noqa: S324
            self._preflight = await async_probe_preflight(session, exchange.challenge)
            self._safe_summary += "\n" + self._preflight.safe_summary

            if any(
                attempt.has_authorize_code or attempt.has_token
                for attempt in self._preflight.attempts
            ):
                self._outcome = _friendly_outcome(
                    result, otp_ran=False, success=True
                )
                return await self.async_step_result()

            if any(
                attempt.message_class in {"rate_limited", "account_locked"}
                for attempt in self._preflight.attempts
            ):
                self._outcome = (
                    "VeSync asked for MFA and the safe preflight stopped because "
                    "the server reported rate limiting or account lock"
                )
                return await self.async_step_result()

            return await self.async_step_otp()

        self._outcome = _friendly_outcome(result, otp_ran=False, success=False)
        return await self.async_step_result()

    async def async_step_otp(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Accept one authenticator code locally and run the bounded ladder."""
        if (
            self._initial_result is None
            or self._challenge is None
            or self._password_hash is None
            or self._preflight is None
        ):
            return self.async_abort(reason="probe_state_lost")

        schema = vol.Schema(
            {
                vol.Required(CONF_OTP_CODE): vol.All(
                    cv.string,
                    vol.Match(r"^\d{6,8}$", msg="Use the current numeric authenticator code"),
                )
            }
        )
        if user_input is None:
            return self.async_show_form(step_id="otp", data_schema=schema, errors={})

        otp_code = user_input[CONF_OTP_CODE]
        session = async_get_clientsession(self.hass)
        ladder = await async_probe_otp_ladder(
            session,
            self._challenge,
            password_hash=self._password_hash,
            otp_code=otp_code,
            preflight=self._preflight,
        )

        # Never retain the OTP after the network calls have completed.
        otp_code = ""
        self._safe_summary = (self._safe_summary or "") + "\n" + ladder.safe_summary
        self._outcome = _friendly_outcome(
            self._initial_result,
            otp_ran=True,
            success=ladder.succeeded,
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
