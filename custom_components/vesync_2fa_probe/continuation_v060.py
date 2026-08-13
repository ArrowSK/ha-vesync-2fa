"""VeSync MFA continuation discovery for probe 0.6.

The module keeps protocol discovery bounded and account-safe:
- two no-code requests are made against VeSync's already-known login endpoint;
- a user-supplied authenticator code can then be tried against a short list of
  plausible field names on the two already-known authentication endpoints;
- attempts stop as soon as VeSync returns anything materially different from the
  baseline MFA challenge, or on rate limiting/account lock;
- secrets are never included in returned summaries or logs.

This remains a diagnostic helper. It does not persist credentials or modify Home
Assistant's built-in ``vesync`` integration.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from aiohttp import ClientError, ClientSession, ClientTimeout

from .auth import ChallengeContext

_TIMEOUT = ClientTimeout(total=8)
_PAUSE = 0.45
_AUTH_ENDPOINT = "/globalPlatform/api/accountAuth/v1/authByPWDOrOTM"
_LOGIN_ENDPOINT = "/user/api/accountManage/v1/loginByAuthorizeCode4Vesync"
_MFA_REQUIRED_CODE = -11257129


@dataclass(slots=True, frozen=True)
class Attempt:
    """Sanitized result from one protocol hypothesis."""

    candidate_id: str
    http_status: int | None
    server_code: int | None
    message_class: str
    result_keys: tuple[str, ...]
    has_authorize_code: bool
    has_token: bool

    @property
    def safe_summary(self) -> str:
        keys = ",".join(self.result_keys) if self.result_keys else "none"
        return (
            f"{self.candidate_id}[http={self.http_status};code={self.server_code};"
            f"msg={self.message_class};authorize_code="
            f"{'yes' if self.has_authorize_code else 'no'};token="
            f"{'yes' if self.has_token else 'no'};keys={keys}]"
        )


@dataclass(slots=True, frozen=True)
class PreflightResult:
    attempts: tuple[Attempt, ...]

    @property
    def safe_summary(self) -> str:
        return "preflight=" + " | ".join(attempt.safe_summary for attempt in self.attempts)


@dataclass(slots=True, frozen=True)
class OtpLadderResult:
    attempts: tuple[Attempt, ...]

    @property
    def safe_summary(self) -> str:
        return "otp_ladder=" + " | ".join(attempt.safe_summary for attempt in self.attempts)

    @property
    def succeeded(self) -> bool:
        return any(a.has_authorize_code or a.has_token for a in self.attempts)


def _safe_key(value: object) -> str:
    text = str(value)
    return "".join(ch if ch.isalnum() or ch in "_.-" else "_" for ch in text)[:48]


def _message_class(status: int, code: int | None, message: object) -> str:
    if status == 429:
        return "rate_limited"
    if status == 404:
        return "not_found"
    if code == _MFA_REQUIRED_CODE:
        return "mfa_required"
    if not isinstance(message, str):
        return "none"
    text = message.casefold()
    if "rate" in text or "too many" in text:
        return "rate_limited"
    if "locked" in text:
        return "account_locked"
    if any(word in text for word in ("expired", "timeout")) and any(
        word in text for word in ("otp", "code", "verify", "mfa")
    ):
        return "code_expired"
    if any(word in text for word in ("incorrect", "invalid", "wrong")) and any(
        word in text for word in ("otp", "code", "verify", "mfa")
    ):
        return "invalid_code"
    if any(word in text for word in ("missing", "required", "empty")) and any(
        word in text for word in ("otp", "code", "verify", "mfa")
    ):
        return "code_required"
    if "illegal argument" in text or "invalid parameter" in text:
        return "illegal_argument"
    if "mfa" in text or "2fa" in text or "two-factor" in text:
        return "mfa_required"
    if "success" in text:
        return "success"
    return "other"


def _base_payload(context: ChallengeContext, *, password_hash: str) -> dict[str, Any]:
    payload = dict(context.common_payload)
    payload["password"] = password_hash
    payload["bizToken"] = context.biz_token
    if context.account_id:
        payload["accountID"] = context.account_id
    return payload


def _login_payload(context: ChallengeContext) -> dict[str, Any]:
    common = context.common_payload
    payload: dict[str, Any] = {
        "method": "loginByAuthorizeCode4Vesync",
        "acceptLanguage": common.get("acceptLanguage", "en"),
        "accountID": context.account_id or "",
        "clientInfo": common.get("clientInfo", "pyvesync"),
        "clientType": common.get("clientType", "vesyncApp"),
        "clientVersion": common.get("clientVersion", ""),
        "debugMode": False,
        "emailSubscriptions": False,
        "osInfo": common.get("osInfo", "Android"),
        "terminalId": common.get("terminalId", ""),
        "timeZone": common.get("timeZone", ""),
        "token": "",
        "bizToken": context.biz_token,
        "userCountryCode": common.get("userCountryCode", ""),
        "traceId": common.get("traceId", ""),
    }
    return payload


async def _request(
    session: ClientSession,
    *,
    context: ChallengeContext,
    candidate_id: str,
    endpoint: str,
    payload: dict[str, Any],
) -> Attempt:
    try:
        async with session.post(
            context.base_url + endpoint,
            json=payload,
            timeout=_TIMEOUT,
            raise_for_status=False,
        ) as response:
            status = response.status
            try:
                raw = await response.json(content_type=None)
            except (ValueError, TypeError):
                raw = None
    except (ClientError, TimeoutError):
        return Attempt(candidate_id, None, None, "network_error", (), False, False)

    if not isinstance(raw, dict):
        return Attempt(candidate_id, status, None, "non_json", (), False, False)

    result = raw.get("result") if isinstance(raw.get("result"), dict) else {}
    code = raw.get("code") if isinstance(raw.get("code"), int) else None
    authorize_code = result.get("authorizeCode")
    token = result.get("token")
    return Attempt(
        candidate_id,
        status,
        code,
        _message_class(status, code, raw.get("msg")),
        tuple(sorted(_safe_key(key) for key in result)[:20]),
        isinstance(authorize_code, str) and bool(authorize_code),
        isinstance(token, str) and bool(token),
    )


def _hard_stop(attempt: Attempt) -> bool:
    return (
        attempt.has_authorize_code
        or attempt.has_token
        or attempt.message_class
        in {"rate_limited", "account_locked", "invalid_code", "code_expired"}
    )


async def async_probe_preflight(
    session: ClientSession,
    context: ChallengeContext,
) -> PreflightResult:
    """Test the known step-two endpoint without a second-factor code."""
    attempts: list[Attempt] = []

    payload = _login_payload(context)
    attempts.append(
        await _request(
            session,
            context=context,
            candidate_id="c7_login_bizToken_only",
            endpoint=_LOGIN_ENDPOINT,
            payload=payload,
        )
    )
    if _hard_stop(attempts[-1]):
        return PreflightResult(tuple(attempts))

    await asyncio.sleep(_PAUSE)
    payload_last_region = dict(payload)
    payload_last_region["regionChange"] = "lastRegion"
    attempts.append(
        await _request(
            session,
            context=context,
            candidate_id="c8_login_bizToken_lastRegion",
            endpoint=_LOGIN_ENDPOINT,
            payload=payload_last_region,
        )
    )
    return PreflightResult(tuple(attempts))


async def async_probe_otp_ladder(
    session: ClientSession,
    context: ChallengeContext,
    *,
    password_hash: str,
    otp_code: str,
    preflight: PreflightResult,
) -> OtpLadderResult:
    """Try one fresh OTP against a bounded set of plausible field names.

    On the verified first-stage endpoint we continue only while VeSync returns the
    exact same MFA-required state. Any different response is useful protocol
    evidence and stops the ladder. If all first-stage field names are ignored,
    three variants are tried against the already-known second-stage login endpoint.
    """
    attempts: list[Attempt] = []

    auth_candidates = (
        ("d1_same_auth_mfaCode", "mfaCode"),
        ("d2_same_auth_otp", "otp"),
        ("d3_same_auth_otpCode", "otpCode"),
        ("d4_same_auth_verificationCode", "verificationCode"),
        ("d5_same_auth_verifyCode", "verifyCode"),
        ("d6_same_auth_code", "code"),
    )

    for index, (candidate_id, field_name) in enumerate(auth_candidates):
        if index:
            await asyncio.sleep(_PAUSE)
        payload = _base_payload(context, password_hash=password_hash)
        payload["method"] = "authByPWDOrOTM"
        payload["mfaMethod"] = "otp"
        payload[field_name] = otp_code
        attempt = await _request(
            session,
            context=context,
            candidate_id=candidate_id,
            endpoint=_AUTH_ENDPOINT,
            payload=payload,
        )
        attempts.append(attempt)
        if _hard_stop(attempt):
            break
        # A response different from the known MFA challenge is valuable evidence;
        # do not spend the same OTP on additional guesses after that point.
        if attempt.server_code != _MFA_REQUIRED_CODE or attempt.message_class != "mfa_required":
            break
    else:
        # All first-stage fields were ignored. Use the known step-two endpoint,
        # comparing against its no-code baseline and stopping on the first change.
        baseline = preflight.attempts[0] if preflight.attempts else None
        login_candidates = (
            ("e1_login_otpCode", "otpCode"),
            ("e2_login_mfaCode", "mfaCode"),
            ("e3_login_verificationCode", "verificationCode"),
        )
        for candidate_id, field_name in login_candidates:
            await asyncio.sleep(_PAUSE)
            payload = _login_payload(context)
            payload["mfaMethod"] = "otp"
            payload[field_name] = otp_code
            attempt = await _request(
                session,
                context=context,
                candidate_id=candidate_id,
                endpoint=_LOGIN_ENDPOINT,
                payload=payload,
            )
            attempts.append(attempt)
            if _hard_stop(attempt):
                break
            if baseline is not None and (
                attempt.server_code != baseline.server_code
                or attempt.message_class != baseline.message_class
                or attempt.result_keys != baseline.result_keys
            ):
                break

    return OtpLadderResult(tuple(attempts))
