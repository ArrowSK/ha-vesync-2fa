"""Safe first-stage VeSync authentication probe.

The probe sends only VeSync's known password-authentication request. It never
exchanges an authorization code for a cloud session and never submits a second
factor. Raw response data is parsed immediately into a deliberately small,
public-safe result object.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Literal

from aiohttp import ClientError, ClientSession, ClientTimeout
from pyvesync.const import API_BASE_URL_EU, API_BASE_URL_US
from pyvesync.models.vesync_models import RequestGetTokenModel

from .const import API_REGION_EU

_AUTH_ENDPOINT = "/globalPlatform/api/accountAuth/v1/authByPWDOrOTM"
_TIMEOUT = ClientTimeout(total=10)
_SAFE_TOKEN = re.compile(r"[^A-Za-z0-9_.-]+")

ProbeOutcome = Literal["mfa_required", "password_accepted", "rejected"]


class VeSyncProbeError(Exception):
    """Raised when the probe cannot obtain a usable VeSync response."""


@dataclass(slots=True, frozen=True)
class ProbeResult:
    """Sanitized result of the first VeSync authentication request.

    This object deliberately contains no email address, password, account ID,
    authorization code, cloud token or MFA challenge token.
    """

    outcome: ProbeOutcome
    server_code: int | None
    methods: tuple[str, ...]
    result_keys: tuple[str, ...]
    has_biz_token: bool
    has_verify_email: bool
    has_authorize_code: bool

    @property
    def safe_summary(self) -> str:
        """Return metadata suitable for a public GitHub issue."""
        methods = ",".join(self.methods) if self.methods else "none-returned"
        keys = ",".join(self.result_keys) if self.result_keys else "none-returned"
        return (
            f"outcome={self.outcome}; server_code={self.server_code}; "
            f"methods={methods}; biz_token={'yes' if self.has_biz_token else 'no'}; "
            f"verify_email={'yes' if self.has_verify_email else 'no'}; "
            f"authorize_code={'yes' if self.has_authorize_code else 'no'}; "
            f"result_keys={keys}"
        )


def _safe_name(value: str) -> str:
    """Restrict server-provided field/method names to a harmless character set."""
    return _SAFE_TOKEN.sub("_", value)[:64]


def _safe_methods(value: object) -> tuple[str, ...]:
    """Return bounded, sanitized MFA method names."""
    if not isinstance(value, list):
        return ()
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item:
            continue
        safe = _safe_name(item)
        if safe:
            result.append(safe)
        if len(result) == 8:
            break
    return tuple(result)


def _is_mfa_message(value: object) -> bool:
    """Return whether a server message clearly indicates an MFA requirement."""
    if not isinstance(value, str):
        return False
    text = value.casefold()
    return (
        "requires 2fa" in text
        or "2fa authentication" in text
        or "two-factor" in text
        or "two factor" in text
        or "mfa" in text
    )


def parse_probe_response(response: dict[str, Any]) -> ProbeResult:
    """Reduce a raw VeSync response to non-secret protocol metadata."""
    raw_code = response.get("code")
    server_code = raw_code if isinstance(raw_code, int) else None

    raw_result = response.get("result")
    result = raw_result if isinstance(raw_result, dict) else {}

    methods = _safe_methods(result.get("mfaMethodList"))
    has_biz_token = isinstance(result.get("bizToken"), str) and bool(
        result.get("bizToken")
    )
    has_verify_email = isinstance(result.get("verifyEmail"), str) and bool(
        result.get("verifyEmail")
    )
    has_authorize_code = isinstance(result.get("authorizeCode"), str) and bool(
        result.get("authorizeCode")
    )

    result_keys = tuple(
        sorted(
            _safe_name(str(key))
            for key in result
            if _safe_name(str(key))
        )[:32]
    )

    mfa_required = (
        bool(methods)
        or _is_mfa_message(response.get("msg"))
        or (has_biz_token and not has_authorize_code)
    )

    if mfa_required:
        outcome: ProbeOutcome = "mfa_required"
    elif server_code == 0 and has_authorize_code:
        outcome = "password_accepted"
    else:
        outcome = "rejected"

    return ProbeResult(
        outcome=outcome,
        server_code=server_code,
        methods=methods,
        result_keys=result_keys,
        has_biz_token=has_biz_token,
        has_verify_email=has_verify_email,
        has_authorize_code=has_authorize_code,
    )


async def async_probe_auth(
    session: ClientSession,
    *,
    username: str,
    password: str,
    country_code: str,
    api_region: str,
    time_zone: str,
) -> ProbeResult:
    """Send one first-stage VeSync login request and return only safe metadata."""
    base_url = API_BASE_URL_EU if api_region == API_REGION_EU else API_BASE_URL_US

    request = RequestGetTokenModel(
        email=username,
        method="authByPWDOrOTM",
        password=password,
        userCountryCode=country_code,
        timeZone=time_zone,
    )

    try:
        async with session.post(
            base_url + _AUTH_ENDPOINT,
            json=request.to_dict(),
            timeout=_TIMEOUT,
            raise_for_status=False,
        ) as response:
            if response.status != 200:
                raise VeSyncProbeError(
                    f"VeSync authentication endpoint returned HTTP {response.status}"
                )
            try:
                payload = await response.json(content_type=None)
            except (ValueError, TypeError) as exc:
                raise VeSyncProbeError(
                    "VeSync authentication endpoint returned invalid JSON"
                ) from exc
    except (ClientError, TimeoutError) as exc:
        raise VeSyncProbeError("Unable to reach the VeSync authentication endpoint") from exc

    if not isinstance(payload, dict):
        raise VeSyncProbeError("VeSync authentication response was not an object")

    return parse_probe_response(payload)
