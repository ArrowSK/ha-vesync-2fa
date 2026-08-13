"""VeSync MFA continuation hypotheses for diagnostic use only.

This module performs a bounded set of no-code continuation requests after the
server has already returned an MFA challenge. It never submits an OTP, email
code or backup code, and it stops on rate limiting or account lock.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from hashlib import md5
from typing import Any

from aiohttp import ClientError, ClientSession, ClientTimeout

from .auth import ChallengeContext

_TIMEOUT = ClientTimeout(total=7)
_PAUSE_BETWEEN_ATTEMPTS = 0.35
_AUTH_ENDPOINT = "/globalPlatform/api/accountAuth/v1/authByPWDOrOTM"
_AUTH_BY_MFA_ENDPOINT = "/globalPlatform/api/accountAuth/v1/authByMFA"
_VERIFY_MFA_ENDPOINT = "/globalPlatform/api/accountAuth/v1/verifyMFA"


@dataclass(slots=True, frozen=True)
class Candidate:
    candidate_id: str
    endpoint: str
    method: str
    extra_fields: tuple[tuple[str, str], ...]


@dataclass(slots=True, frozen=True)
class Attempt:
    candidate_id: str
    http_status: int | None
    server_code: int | None
    message_class: str
    result_keys: tuple[str, ...]
    has_authorize_code: bool

    @property
    def safe_summary(self) -> str:
        keys = ",".join(self.result_keys) if self.result_keys else "none"
        return (
            f"{self.candidate_id}[http={self.http_status};code={self.server_code};"
            f"msg={self.message_class};authorize_code="
            f"{'yes' if self.has_authorize_code else 'no'};keys={keys}]"
        )


@dataclass(slots=True, frozen=True)
class LadderResult:
    attempts: tuple[Attempt, ...]

    @property
    def safe_summary(self) -> str:
        return "continuation_ladder=" + " | ".join(
            attempt.safe_summary for attempt in self.attempts
        )


_CANDIDATES = (
    Candidate("c2_same_auth_password_mfaMethod", _AUTH_ENDPOINT, "authByPWDOrOTM", (("mfaMethod", "otp"),)),
    Candidate("c3_same_auth_password_bizToken_only", _AUTH_ENDPOINT, "authByPWDOrOTM", ()),
    Candidate("c4_same_auth_password_mfaMethodType", _AUTH_ENDPOINT, "authByPWDOrOTM", (("mfaMethodType", "otp"),)),
    Candidate("c5_authByMFA_password_mfaMethod", _AUTH_BY_MFA_ENDPOINT, "authByMFA", (("mfaMethod", "otp"),)),
    Candidate("c6_verifyMFA_password_mfaMethod", _VERIFY_MFA_ENDPOINT, "verifyMFA", (("mfaMethod", "otp"),)),
)


def _safe_key(value: object) -> str:
    text = str(value)
    return "".join(ch if ch.isalnum() or ch in "_.-" else "_" for ch in text)[:48]


def _message_class(status: int, code: int | None, message: object) -> str:
    if status == 429:
        return "rate_limited"
    if status == 404:
        return "not_found"
    if code == -11257129:
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
    if "code" in text and any(word in text for word in ("missing", "required", "empty")):
        return "code_required"
    if "illegal argument" in text or "invalid parameter" in text:
        return "illegal_argument"
    if "mfa" in text or "2fa" in text or "two-factor" in text:
        return "mfa_required"
    if "success" in text:
        return "success"
    return "other"


def _payload(context: ChallengeContext, candidate: Candidate, password: str) -> dict[str, Any]:
    payload = dict(context.common_payload)
    payload["password"] = md5(password.encode("utf-8")).hexdigest()  # noqa: S324
    payload["method"] = candidate.method
    payload["bizToken"] = context.biz_token
    if context.account_id:
        payload["accountID"] = context.account_id
    for key, value in candidate.extra_fields:
        payload[key] = value
    return payload


async def _run(session: ClientSession, context: ChallengeContext, candidate: Candidate, password: str) -> Attempt:
    try:
        async with session.post(
            context.base_url + candidate.endpoint,
            json=_payload(context, candidate, password),
            timeout=_TIMEOUT,
            raise_for_status=False,
        ) as response:
            status = response.status
            try:
                raw = await response.json(content_type=None)
            except (ValueError, TypeError):
                raw = None
    except (ClientError, TimeoutError):
        return Attempt(candidate.candidate_id, None, None, "network_error", (), False)

    if not isinstance(raw, dict):
        return Attempt(candidate.candidate_id, status, None, "non_json", (), False)

    result = raw.get("result") if isinstance(raw.get("result"), dict) else {}
    code = raw.get("code") if isinstance(raw.get("code"), int) else None
    authorize_code = result.get("authorizeCode")
    return Attempt(
        candidate.candidate_id,
        status,
        code,
        _message_class(status, code, raw.get("msg")),
        tuple(sorted(_safe_key(key) for key in result)[:16]),
        isinstance(authorize_code, str) and bool(authorize_code),
    )


async def async_probe_continuation_ladder(
    session: ClientSession,
    context: ChallengeContext,
    password: str,
) -> LadderResult:
    attempts: list[Attempt] = []
    for index, candidate in enumerate(_CANDIDATES):
        if index:
            await asyncio.sleep(_PAUSE_BETWEEN_ATTEMPTS)
        attempt = await _run(session, context, candidate, password)
        attempts.append(attempt)
        if attempt.has_authorize_code or attempt.message_class in {"rate_limited", "account_locked"}:
            break
    return LadderResult(tuple(attempts))
