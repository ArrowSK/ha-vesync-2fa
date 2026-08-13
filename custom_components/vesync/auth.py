"""Authentication helpers for VeSync accounts, including MFA challenge discovery.

VeSync's current login is a two-step flow. pyvesync 3.4.2 implements the normal
password path, but it raises before Home Assistant can inspect the response when
VeSync requires MFA. This module performs only the already-known first login
request itself so that the MFA challenge metadata can be preserved safely.

The actual OTP submission endpoint is intentionally not guessed. Until it is
verified against a real VeSync MFA challenge, this module stops at a structured
MFA-required result rather than sending a code to an invented endpoint.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from aiohttp import ClientError
from pyvesync import VeSync
from pyvesync.const import API_TIMEOUT, REGION_API_MAP
from pyvesync.models.vesync_models import RequestGetTokenModel
from pyvesync.utils.errors import (
    VeSyncAPIResponseError,
    VeSyncAPIStatusCodeError,
    VeSyncLoginError,
)

_AUTH_ENDPOINT = "/globalPlatform/api/accountAuth/v1/authByPWDOrOTM"


def _is_two_factor_message(message: object) -> bool:
    """Return whether a VeSync response message indicates MFA is required."""
    if not isinstance(message, str):
        return False
    text = message.casefold()
    return "requires 2fa" in text or "2fa authentication" in text or "mfa" in text


def _safe_method_list(value: object) -> tuple[str, ...]:
    """Return a bounded tuple of MFA method names from an API response."""
    if not isinstance(value, list):
        return ()
    return tuple(item[:64] for item in value if isinstance(item, str) and item)[:8]


@dataclass(slots=True, frozen=True)
class VeSyncAuthorizationCode:
    """Successful first-stage authentication result."""

    authorization_code: str = field(repr=False)


@dataclass(slots=True, frozen=True)
class VeSyncMFAChallenge:
    """MFA challenge metadata returned by VeSync.

    Sensitive values are deliberately excluded from repr() and from the safe
    diagnostic string. They remain in config-flow memory only and are not stored
    in the Home Assistant config entry.
    """

    server_code: int | None
    methods: tuple[str, ...]
    result_keys: tuple[str, ...]
    biz_token: str | None = field(default=None, repr=False)
    verify_email: str | None = field(default=None, repr=False)

    @property
    def safe_summary(self) -> str:
        """Return challenge metadata that is safe to paste into a public issue."""
        methods = ",".join(self.methods) if self.methods else "none-returned"
        keys = ",".join(self.result_keys) if self.result_keys else "none-returned"
        return (
            f"server_code={self.server_code}; methods={methods}; "
            f"biz_token={'yes' if self.biz_token else 'no'}; "
            f"verify_email={'yes' if self.verify_email else 'no'}; "
            f"result_keys={keys}"
        )


class VeSyncMFARequired(VeSyncLoginError):
    """Raised when VeSync requires a second authentication factor."""

    def __init__(self, challenge: VeSyncMFAChallenge) -> None:
        super().__init__("VeSync requires two-factor authentication")
        self.challenge = challenge


def parse_auth_response(
    response: dict[str, Any],
) -> VeSyncAuthorizationCode | VeSyncMFAChallenge:
    """Parse the first VeSync authentication response without leaking secrets."""
    raw_code = response.get("code")
    server_code = raw_code if isinstance(raw_code, int) else None
    result = response.get("result")
    result_dict = result if isinstance(result, dict) else {}

    methods = _safe_method_list(result_dict.get("mfaMethodList"))
    biz_token_value = result_dict.get("bizToken")
    biz_token = (
        biz_token_value
        if isinstance(biz_token_value, str) and biz_token_value
        else None
    )
    verify_email_value = result_dict.get("verifyEmail")
    verify_email = (
        verify_email_value
        if isinstance(verify_email_value, str) and verify_email_value
        else None
    )
    result_keys = tuple(sorted(str(key) for key in result_dict))[:32]

    # A populated MFA method list or challenge token is stronger evidence than a
    # generic status code. Prefer the challenge path even if VeSync returns code 0.
    if methods or biz_token or _is_two_factor_message(response.get("msg")):
        return VeSyncMFAChallenge(
            server_code=server_code,
            methods=methods,
            result_keys=result_keys,
            biz_token=biz_token,
            verify_email=verify_email,
        )

    authorization_code = result_dict.get("authorizeCode")
    if (
        server_code == 0
        and isinstance(authorization_code, str)
        and authorization_code
    ):
        return VeSyncAuthorizationCode(authorization_code=authorization_code)

    message = response.get("msg")
    if isinstance(message, str) and message:
        raise VeSyncLoginError(f"VeSync authentication failed: {message}")
    raise VeSyncLoginError("VeSync authentication failed")


async def _first_auth_request(
    manager: VeSync, username: str, password: str
) -> dict[str, Any]:
    """Perform VeSync's known password-authentication request and return raw JSON."""
    request = RequestGetTokenModel(
        email=username,
        method="authByPWDOrOTM",
        password=password,
    )

    session = manager.session
    if session is None:
        raise VeSyncAPIResponseError("VeSync HTTP session is not available")

    base_url = REGION_API_MAP.get(manager.current_region)
    if not base_url:
        raise VeSyncAPIResponseError("Unknown VeSync region")

    try:
        async with asyncio.timeout(API_TIMEOUT):
            async with session.post(
                base_url + _AUTH_ENDPOINT,
                json=request.to_dict(),
                raise_for_status=False,
            ) as response:
                if response.status != 200:
                    raise VeSyncAPIStatusCodeError(str(response.status))
                try:
                    payload = await response.json(content_type=None)
                except (ValueError, TypeError) as exc:
                    raise VeSyncAPIResponseError(
                        "Error parsing VeSync authentication response"
                    ) from exc
    except TimeoutError as exc:
        raise VeSyncAPIResponseError("VeSync authentication request timed out") from exc
    except ClientError as exc:
        raise VeSyncAPIResponseError("VeSync authentication request failed") from exc

    if not isinstance(payload, dict):
        raise VeSyncAPIResponseError("Invalid VeSync authentication response")
    return payload


async def async_authenticate(manager: VeSync, username: str, password: str) -> None:
    """Authenticate a manager while preserving a VeSync MFA challenge.

    Normal accounts continue through pyvesync's existing authorization-code
    exchange. MFA accounts raise VeSyncMFARequired with the challenge metadata so
    Home Assistant can continue an interactive flow once the OTP protocol is
    verified.
    """
    parsed = parse_auth_response(
        await _first_auth_request(manager, username=username, password=password)
    )
    if isinstance(parsed, VeSyncMFAChallenge):
        raise VeSyncMFARequired(parsed)

    # pyvesync 3.4.2 already has the correct second-stage token exchange,
    # including cross-region handling. We intentionally reuse that pinned logic
    # rather than copy it into this integration. This is a private method, so the
    # runtime compatibility test protects us from upstream signature changes.
    await manager.auth._exchange_authorization_code(  # noqa: SLF001
        parsed.authorization_code
    )
    manager.enabled = True
