"""Single-run VeSync MFA hypothesis ladder for probe 0.7.

The user supplies one fresh authenticator code on the same Home Assistant form as
username/password. After VeSync returns the normal MFA challenge, this module
tries up to 15 bounded request shapes using only the two VeSync authentication
endpoints already used by current open-source clients.

The ladder stops immediately on authorization/session success, rate limiting,
account lock, or an explicit invalid/expired-code response. Secret values are
kept in memory only and never appear in the safe summary or logs.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from aiohttp import ClientError, ClientSession, ClientTimeout

from .auth import ChallengeContext

_TIMEOUT = ClientTimeout(total=8)
_PAUSE = 0.40
_AUTH_ENDPOINT = "/globalPlatform/api/accountAuth/v1/authByPWDOrOTM"
_LOGIN_ENDPOINT = "/user/api/accountManage/v1/loginByAuthorizeCode4Vesync"
_MFA_REQUIRED_CODE = -11257129


@dataclass(slots=True, frozen=True)
class Candidate:
    candidate_id: str
    mode: str
    code_field: str | None = None
    method_value: str = "authByPWDOrOTM"
    mfa_field: str | None = "mfaMethod"
    mfa_value: str | None = "otp"
    nested_field: str | None = None


@dataclass(slots=True, frozen=True)
class Attempt:
    candidate_id: str
    http_status: int | None
    server_code: int | None
    message_class: str
    result_keys: tuple[str, ...]
    authorize_code: str | None = field(default=None, repr=False)
    token: str | None = field(default=None, repr=False)

    @property
    def has_authorize_code(self) -> bool:
        return bool(self.authorize_code)

    @property
    def has_token(self) -> bool:
        return bool(self.token)

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
class LadderResult:
    attempts: tuple[Attempt, ...]
    exchange: Attempt | None = None

    @property
    def succeeded(self) -> bool:
        if self.exchange is not None and self.exchange.has_token:
            return True
        return any(a.has_token for a in self.attempts)

    @property
    def authorize_code_found(self) -> bool:
        return any(a.has_authorize_code for a in self.attempts)

    @property
    def safe_summary(self) -> str:
        body = " | ".join(a.safe_summary for a in self.attempts)
        text = f"otp_ladder={body}"
        if self.exchange is not None:
            text += f" | exchange={self.exchange.safe_summary}"
        return text


# Fifteen distinct payload hypotheses. They vary field names/shape while staying
# on the two auth endpoints already known from pyvesync/current clients.
_CANDIDATES = (
    Candidate("p01_auth_mfaCode", "auth_top", "mfaCode"),
    Candidate("p02_auth_otp", "auth_top", "otp"),
    Candidate("p03_auth_otpCode", "auth_top", "otpCode"),
    Candidate("p04_auth_verificationCode", "auth_top", "verificationCode"),
    Candidate("p05_auth_verifyCode", "auth_top", "verifyCode"),
    Candidate("p06_auth_code", "auth_top", "code"),
    Candidate("p07_auth_oneTimePassword", "auth_top", "oneTimePassword"),
    Candidate("p08_auth_totp", "auth_top", "totp"),
    Candidate("p09_authByOTM_otpCode", "auth_top", "otpCode", method_value="authByOTM"),
    Candidate("p10_authByOTM_code", "auth_top", "code", method_value="authByOTM"),
    Candidate("p11_authByMFA_otpCode", "auth_top", "otpCode", method_value="authByMFA"),
    Candidate("p12_auth_nested_mfa", "auth_nested", nested_field="mfa", mfa_field=None),
    Candidate("p13_auth_nested_mfaInfo", "auth_nested", nested_field="mfaInfo", mfa_field=None),
    Candidate("p14_login_authorizeCode", "login_authorize"),
    Candidate("p15_login_otpCode", "login_top", "otpCode"),
)


def candidate_count() -> int:
    """Return the bounded number of live hypotheses for validation/tests."""
    return len(_CANDIDATES)


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
    if code == -11000129:
        return "illegal_argument"
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


def _auth_payload(
    context: ChallengeContext,
    *,
    password_hash: str,
    otp_code: str,
    candidate: Candidate,
) -> dict[str, Any]:
    payload = dict(context.common_payload)
    payload["password"] = password_hash
    payload["bizToken"] = context.biz_token
    if context.account_id:
        payload["accountID"] = context.account_id
    payload["method"] = candidate.method_value
    if candidate.mfa_field and candidate.mfa_value:
        payload[candidate.mfa_field] = candidate.mfa_value
    if candidate.mode == "auth_nested" and candidate.nested_field:
        payload[candidate.nested_field] = {"method": "otp", "code": otp_code}
    elif candidate.code_field:
        payload[candidate.code_field] = otp_code
    return payload


def _login_base_payload(context: ChallengeContext) -> dict[str, Any]:
    common = context.common_payload
    return {
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


def _candidate_payload(
    context: ChallengeContext,
    *,
    password_hash: str,
    otp_code: str,
    candidate: Candidate,
) -> tuple[str, dict[str, Any]]:
    if candidate.mode.startswith("auth_"):
        return _AUTH_ENDPOINT, _auth_payload(
            context,
            password_hash=password_hash,
            otp_code=otp_code,
            candidate=candidate,
        )

    payload = _login_base_payload(context)
    if candidate.mode == "login_authorize":
        payload["authorizeCode"] = otp_code
    else:
        payload["mfaMethod"] = "otp"
        if candidate.code_field:
            payload[candidate.code_field] = otp_code
    return _LOGIN_ENDPOINT, payload


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
        return Attempt(candidate_id, None, None, "network_error", ())

    if not isinstance(raw, dict):
        return Attempt(candidate_id, status, None, "non_json", ())

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
        authorize_code if isinstance(authorize_code, str) and authorize_code else None,
        token if isinstance(token, str) and token else None,
    )


def _hard_stop(attempt: Attempt) -> bool:
    return (
        attempt.has_authorize_code
        or attempt.has_token
        or attempt.message_class
        in {"rate_limited", "account_locked", "invalid_code", "code_expired"}
    )


async def _exchange_authorize_code(
    session: ClientSession,
    context: ChallengeContext,
    authorize_code: str,
) -> Attempt:
    payload = _login_base_payload(context)
    payload["authorizeCode"] = authorize_code
    return await _request(
        session,
        context=context,
        candidate_id="token_exchange",
        endpoint=_LOGIN_ENDPOINT,
        payload=payload,
    )


async def async_probe_otp_ladder(
    session: ClientSession,
    context: ChallengeContext,
    *,
    password_hash: str,
    otp_code: str,
) -> LadderResult:
    """Try one fresh OTP against up to fifteen bounded payload hypotheses."""
    attempts: list[Attempt] = []
    exchange: Attempt | None = None

    for index, candidate in enumerate(_CANDIDATES):
        if index:
            await asyncio.sleep(_PAUSE)
        endpoint, payload = _candidate_payload(
            context,
            password_hash=password_hash,
            otp_code=otp_code,
            candidate=candidate,
        )
        attempt = await _request(
            session,
            context=context,
            candidate_id=candidate.candidate_id,
            endpoint=endpoint,
            payload=payload,
        )
        attempts.append(attempt)

        if attempt.has_authorize_code:
            exchange = await _exchange_authorize_code(
                session, context, attempt.authorize_code or ""
            )
            break
        if _hard_stop(attempt):
            break

    return LadderResult(tuple(attempts), exchange)
