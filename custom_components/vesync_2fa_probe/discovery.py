"""Conservative VeSync MFA continuation-route discovery.

This module intentionally does *not* submit an OTP, backup code or email code.
It reuses the already-issued MFA challenge token and sends a bounded set of
candidate continuation requests with the code field omitted. The goal is to
learn which route/payload shape the server recognises without burning a real
second-factor code or brute-forcing authentication.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from aiohttp import ClientError, ClientSession, ClientTimeout

from .auth import ChallengeContext

_TIMEOUT = ClientTimeout(total=7)


@dataclass(slots=True, frozen=True)
class DiscoveryCandidate:
    """One guessed MFA continuation route and payload shape."""

    candidate_id: str
    endpoint: str
    method: str
    mfa_field: str = "mfaMethod"


@dataclass(slots=True, frozen=True)
class DiscoveryAttempt:
    """Public-safe metadata from one candidate request."""

    candidate_id: str
    http_status: int | None
    server_code: int | None
    message_class: str
    result_keys: tuple[str, ...]
    has_authorize_code: bool

    @property
    def safe_summary(self) -> str:
        """Return a compact, non-secret summary."""
        keys = ",".join(self.result_keys) if self.result_keys else "none"
        return (
            f"{self.candidate_id}[http={self.http_status};code={self.server_code};"
            f"msg={self.message_class};auth={'yes' if self.has_authorize_code else 'no'};"
            f"keys={keys}]"
        )


@dataclass(slots=True, frozen=True)
class DiscoveryResult:
    """Combined result of the bounded route-discovery ladder."""

    attempts: tuple[DiscoveryAttempt, ...]

    @property
    def safe_summary(self) -> str:
        """Return all candidate outcomes in one public-safe line."""
        if not self.attempts:
            return "route_scan=no-attempts"
        return "route_scan=" + " | ".join(item.safe_summary for item in self.attempts)


# Ordered from least speculative to more speculative. The first candidate reuses
# the only verified account-auth endpoint. The remaining names follow VeSync's
# existing camelCase API naming style. None of these are claimed to be correct;
# this file exists specifically to test them safely and visibly.
_CANDIDATES: tuple[DiscoveryCandidate, ...] = (
    DiscoveryCandidate(
        "c1_same_auth_mfaMethod",
        "/globalPlatform/api/accountAuth/v1/authByPWDOrOTM",
        "authByPWDOrOTM",
        "mfaMethod",
    ),
    DiscoveryCandidate(
        "c2_same_auth_mfaMethodType",
        "/globalPlatform/api/accountAuth/v1/authByPWDOrOTM",
        "authByPWDOrOTM",
        "mfaMethodType",
    ),
    DiscoveryCandidate(
        "c3_authByMFA",
        "/globalPlatform/api/accountAuth/v1/authByMFA",
        "authByMFA",
    ),
    DiscoveryCandidate(
        "c4_authByMfa",
        "/globalPlatform/api/accountAuth/v1/authByMfa",
        "authByMfa",
    ),
    DiscoveryCandidate(
        "c5_verifyMFA",
        "/globalPlatform/api/accountAuth/v1/verifyMFA",
        "verifyMFA",
    ),
    DiscoveryCandidate(
        "c6_verifyMfa",
        "/globalPlatform/api/accountAuth/v1/verifyMfa",
        "verifyMfa",
    ),
    DiscoveryCandidate(
        "c7_mfaVerify",
        "/globalPlatform/api/accountAuth/v1/mfaVerify",
        "mfaVerify",
    ),
    DiscoveryCandidate(
        "c8_accountManage_verifyMfa",
        "/user/api/accountManage/v1/verifyMfa",
        "verifyMfa",
    ),
)


def _safe_key(value: object) -> str:
    """Return a bounded safe result-key token."""
    text = str(value)
    safe = "".join(ch if ch.isalnum() or ch in "_.-" else "_" for ch in text)
    return safe[:48]


def _message_class(value: object) -> str:
    """Classify a server message without exposing the message itself."""
    if not isinstance(value, str):
        return "none"
    text = value.casefold()
    if "too many" in text or "rate" in text or "quota" in text:
        return "rate_limited"
    if "locked" in text:
        return "account_locked"
    if "success" in text:
        return "success"
    if "not found" in text or "404" in text:
        return "not_found"
    if "method" in text and ("not" in text or "unsupported" in text):
        return "method_rejected"
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


def _result_keys(payload: dict[str, Any]) -> tuple[str, ...]:
    """Return only names of response result fields."""
    raw = payload.get("result")
    if not isinstance(raw, dict):
        return ()
    return tuple(sorted(filter(None, (_safe_key(key) for key in raw)))[:16])


def _has_authorize_code(payload: dict[str, Any]) -> bool:
    """Return whether the response contains a non-empty authorization code."""
    raw = payload.get("result")
    return (
        isinstance(raw, dict)
        and isinstance(raw.get("authorizeCode"), str)
        and bool(raw.get("authorizeCode"))
    )


def _candidate_payload(
    context: ChallengeContext, candidate: DiscoveryCandidate
) -> dict[str, Any]:
    """Build a continuation request with deliberately no second-factor code."""
    payload = dict(context.common_payload)
    payload.pop("password", None)
    payload["method"] = candidate.method
    payload["bizToken"] = context.biz_token
    payload[candidate.mfa_field] = "otp"
    if context.account_id:
        payload["accountID"] = context.account_id
    return payload


async def async_discover_mfa_route(
    session: ClientSession,
    context: ChallengeContext,
) -> DiscoveryResult:
    """Try a small candidate ladder without submitting any real MFA code."""
    attempts: list[DiscoveryAttempt] = []

    for candidate in _CANDIDATES:
        try:
            async with session.post(
                context.base_url + candidate.endpoint,
                json=_candidate_payload(context, candidate),
                timeout=_TIMEOUT,
                raise_for_status=False,
            ) as response:
                status = response.status
                try:
                    raw_payload = await response.json(content_type=None)
                except (ValueError, TypeError):
                    raw_payload = None
        except (ClientError, TimeoutError):
            attempts.append(
                DiscoveryAttempt(
                    candidate_id=candidate.candidate_id,
                    http_status=None,
                    server_code=None,
                    message_class="network_error",
                    result_keys=(),
                    has_authorize_code=False,
                )
            )
            continue

        if not isinstance(raw_payload, dict):
            attempts.append(
                DiscoveryAttempt(
                    candidate_id=candidate.candidate_id,
                    http_status=status,
                    server_code=None,
                    message_class="non_json",
                    result_keys=(),
                    has_authorize_code=False,
                )
            )
            continue

        raw_code = raw_payload.get("code")
        attempt = DiscoveryAttempt(
            candidate_id=candidate.candidate_id,
            http_status=status,
            server_code=raw_code if isinstance(raw_code, int) else None,
            message_class=_message_class(raw_payload.get("msg")),
            result_keys=_result_keys(raw_payload),
            has_authorize_code=_has_authorize_code(raw_payload),
        )
        attempts.append(attempt)

        # Stop immediately on an actual auth code, an account lock, or rate
        # limiting. Continuing in those cases adds risk and no useful evidence.
        if attempt.has_authorize_code or attempt.message_class in {
            "account_locked",
            "rate_limited",
        }:
            break

    return DiscoveryResult(attempts=tuple(attempts))
