"""Safe first-stage VeSync authentication probe.

The first request is the only VeSync MFA request we have verified from public
implementations and live testing. Raw response data is reduced immediately to a
public-safe result. For protocol discovery, the flow may also retain a minimal
challenge context in memory only; it is never logged or written to a Home
Assistant config entry.
"""

from __future__ import annotations

from dataclasses import dataclass, field
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


@dataclass(slots=True, frozen=True)
class ChallengeContext:
    """Sensitive MFA continuation context kept only inside the live flow.

    Repr is intentionally suppressed for all fields that can identify the
    account or authenticate a continuation request.
    """

    base_url: str = field(repr=False)
    biz_token: str = field(repr=False)
    account_id: str | None = field(default=None, repr=False)
    common_payload: dict[str, Any] = field(default_factory=dict, repr=False)


@dataclass(slots=True, frozen=True)
class ProbeExchange:
    """First-stage safe result plus optional in-memory MFA context."""

    result: ProbeResult
    challenge: ChallengeContext | None = field(default=None, repr=False)


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


def _challenge_context(
    *,
    payload: dict[str, Any],
    base_url: str,
    request_payload: dict[str, Any],
    safe_result: ProbeResult,
) -> ChallengeContext | None:
    """Extract only the secret fields needed for continuation discovery."""
    if safe_result.outcome != "mfa_required":
        return None

    raw_result = payload.get("result")
    if not isinstance(raw_result, dict):
        return None

    biz_token = raw_result.get("bizToken")
    if not isinstance(biz_token, str) or not biz_token:
        return None

    account_id = raw_result.get("accountID")
    if not isinstance(account_id, str) or not account_id:
        account_id = None

    # Reuse the same client identity/metadata as the verified first request, but
    # never retain the password hash. The email may remain in this dictionary for
    # the lifetime of the config flow because an unknown continuation route may
    # require it; the dictionary is never persisted or displayed.
    common_payload = dict(request_payload)
    common_payload.pop("password", None)

    return ChallengeContext(
        base_url=base_url,
        biz_token=biz_token,
        account_id=account_id,
        common_payload=common_payload,
    )


async def async_probe_auth_with_context(
    session: ClientSession,
    *,
    username: str,
    password: str,
    country_code: str,
    api_region: str,
    time_zone: str,
) -> ProbeExchange:
    """Send the verified first-stage request and retain MFA context in memory."""
    base_url = API_BASE_URL_EU if api_region == API_REGION_EU else API_BASE_URL_US

    request = RequestGetTokenModel(
        email=username,
        method="authByPWDOrOTM",
        password=password,
        userCountryCode=country_code,
        timeZone=time_zone,
    )
    request_payload = request.to_dict()

    try:
        async with session.post(
            base_url + _AUTH_ENDPOINT,
            json=request_payload,
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

    safe_result = parse_probe_response(payload)
    return ProbeExchange(
        result=safe_result,
        challenge=_challenge_context(
            payload=payload,
            base_url=base_url,
            request_payload=request_payload,
            safe_result=safe_result,
        ),
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
    """Compatibility wrapper returning only the public-safe first-stage result."""
    exchange = await async_probe_auth_with_context(
        session,
        username=username,
        password=password,
        country_code=country_code,
        api_region=api_region,
        time_zone=time_zone,
    )
    return exchange.result
