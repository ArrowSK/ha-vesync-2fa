"""Single conservative hypothesis for VeSync MFA continuation.

This test reuses the already verified ``authByPWDOrOTM`` endpoint. It adds the
server-provided MFA challenge token and advertised ``otp`` method, but deliberately
omits any actual one-time code. It is intended to learn whether VeSync treats the
known endpoint as an MFA continuation route without consuming a real OTP.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from aiohttp import ClientError, ClientSession, ClientTimeout

from .auth import ChallengeContext

_ENDPOINT = "/globalPlatform/api/accountAuth/v1/authByPWDOrOTM"
_TIMEOUT = ClientTimeout(total=7)


@dataclass(slots=True, frozen=True)
class ContinuationProbeResult:
    """Public-safe result from the single continuation hypothesis."""

    http_status: int | None
    server_code: int | None
    message_class: str
    result_keys: tuple[str, ...]
    has_authorize_code: bool

    @property
    def safe_summary(self) -> str:
        """Return metadata safe to paste into a public issue."""
        keys = ",".join(self.result_keys) if self.result_keys else "none"
        return (
            "continuation=c1_same_auth_mfaMethod; "
            f"http={self.http_status}; server_code={self.server_code}; "
            f"message_class={self.message_class}; "
            f"authorize_code={'yes' if self.has_authorize_code else 'no'}; "
            f"result_keys={keys}"
        )


def _safe_key(value: object) -> str:
    """Return a bounded harmless result-field name."""
    text = str(value)
    safe = "".join(ch if ch.isalnum() or ch in "_.-" else "_" for ch in text)
    return safe[:48]


def _message_class(value: object) -> str:
    """Classify the response message without exposing its text."""
    if not isinstance(value, str):
        return "none"
    text = value.casefold()
    if "too many" in text or "rate" in text or "quota" in text:
        return "rate_limited"
    if "locked" in text:
        return "account_locked"
    if "success" in text:
        return "success"
    if "code" in text and any(word in text for word in ("missing", "required", "empty")):
        return "code_required"
    if "code" in text and any(
        word in text for word in ("invalid", "incorrect", "wrong", "expired")
    ):
        return "code_invalid_or_expired"
    if "illegal argument" in text or "invalid parameter" in text or "parameter" in text:
        return "illegal_argument"
    if "mfa" in text or "2fa" in text or "two-factor" in text or "two factor" in text:
        return "mfa"
    if "auth" in text:
        return "auth"
    return "other"


def _safe_result(payload: dict[str, Any], http_status: int) -> ContinuationProbeResult:
    """Reduce a raw response to non-secret protocol metadata."""
    raw_result = payload.get("result")
    result = raw_result if isinstance(raw_result, dict) else {}
    raw_code = payload.get("code")
    authorize_code = result.get("authorizeCode")
    return ContinuationProbeResult(
        http_status=http_status,
        server_code=raw_code if isinstance(raw_code, int) else None,
        message_class=_message_class(payload.get("msg")),
        result_keys=tuple(sorted(filter(None, (_safe_key(key) for key in result)))[:16]),
        has_authorize_code=isinstance(authorize_code, str) and bool(authorize_code),
    )


async def async_probe_same_endpoint_continuation(
    session: ClientSession,
    context: ChallengeContext,
) -> ContinuationProbeResult:
    """Test one no-code continuation hypothesis against the known auth endpoint."""
    payload = dict(context.common_payload)
    payload.pop("password", None)
    payload["method"] = "authByPWDOrOTM"
    payload["bizToken"] = context.biz_token
    payload["mfaMethod"] = "otp"
    if context.account_id:
        payload["accountID"] = context.account_id

    try:
        async with session.post(
            context.base_url + _ENDPOINT,
            json=payload,
            timeout=_TIMEOUT,
            raise_for_status=False,
        ) as response:
            status = response.status
            try:
                raw_payload = await response.json(content_type=None)
            except (ValueError, TypeError):
                raw_payload = None
    except (ClientError, TimeoutError):
        return ContinuationProbeResult(
            http_status=None,
            server_code=None,
            message_class="network_error",
            result_keys=(),
            has_authorize_code=False,
        )

    if not isinstance(raw_payload, dict):
        return ContinuationProbeResult(
            http_status=status,
            server_code=None,
            message_class="non_json",
            result_keys=(),
            has_authorize_code=False,
        )

    return _safe_result(raw_payload, status)
