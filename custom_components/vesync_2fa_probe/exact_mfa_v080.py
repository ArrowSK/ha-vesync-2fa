"""HAR-confirmed VeSync MFA flow for probe 0.8.

This module implements the browser flow captured from account.vesync.com:

1. /globalPlatform/api/accountAuth/v1/authByPWDOrOTM
2. /globalPlatform/api/accountAuth/v1/authBy2fa
3. /user/api/accountManage/v1/loginByAuthorizeCode4Vesync

Secret values remain in memory only. Public results expose only status/code/message
classes, response key names, and booleans for authorize-code/token presence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import md5
import secrets
from typing import Any
from uuid import uuid4

from aiohttp import ClientError, ClientSession, ClientTimeout
from pyvesync.const import API_BASE_URL_EU, API_BASE_URL_US
from pyvesync.models.vesync_models import RequestLoginTokenModel

from .const import API_REGION_EU

_ACCOUNT_GLOBAL = "https://accountapi.vesync.com"
_ACCOUNT_EU = "https://accountapi.vesync.eu"
_AUTH_ENDPOINT = "/globalPlatform/api/accountAuth/v1/authByPWDOrOTM"
_MFA_ENDPOINT = "/globalPlatform/api/accountAuth/v1/authBy2fa"
_LOGIN_ENDPOINT = "/user/api/accountManage/v1/loginByAuthorizeCode4Vesync"
_TIMEOUT = ClientTimeout(total=12)
_MFA_REQUIRED_CODE = -11257129
_BIZ_SYSTEM_ID = "28005ad6-fca3-4634-9b43-ac47129c3b70"


class ExactMFAError(Exception):
    """Raised when the exact flow cannot obtain a usable VeSync response."""


@dataclass(slots=True, frozen=True)
class Attempt:
    """Sanitized metadata for one HTTP step."""

    label: str
    http_status: int | None
    server_code: int | None
    message_class: str
    result_keys: tuple[str, ...]
    authorize_code: str | None = field(default=None, repr=False)
    token: str | None = field(default=None, repr=False)
    biz_token: str | None = field(default=None, repr=False)
    account_id: str | None = field(default=None, repr=False)

    @property
    def safe_summary(self) -> str:
        keys = ",".join(self.result_keys) if self.result_keys else "none"
        return (
            f"{self.label}[http={self.http_status};code={self.server_code};"
            f"msg={self.message_class};authorize_code="
            f"{'yes' if self.authorize_code else 'no'};token="
            f"{'yes' if self.token else 'no'};keys={keys}]"
        )


@dataclass(slots=True, frozen=True)
class ExactFlowResult:
    """Sanitized result for the full browser-confirmed flow."""

    attempts: tuple[Attempt, ...]
    account_host: str

    @property
    def succeeded(self) -> bool:
        return any(attempt.token for attempt in self.attempts)

    @property
    def authorize_code_found(self) -> bool:
        return any(attempt.authorize_code for attempt in self.attempts)

    @property
    def safe_summary(self) -> str:
        return (
            f"exact_flow={self.account_host}:"
            + " > ".join(attempt.safe_summary for attempt in self.attempts)
        )


def _safe_key(value: object) -> str:
    text = str(value)
    return "".join(
        ch if ch.isalnum() or ch in "_.-" else "_" for ch in text
    )[:48]


def _message_class(status: int, code: int | None, message: object) -> str:
    if status == 429:
        return "rate_limited"
    if code == _MFA_REQUIRED_CODE:
        return "mfa_required"
    if not isinstance(message, str):
        return "none"
    text = message.casefold()
    if "rate" in text or "too many" in text:
        return "rate_limited"
    if "locked" in text or "frozen" in text:
        return "account_locked"
    if any(word in text for word in ("expired", "timeout")) and any(
        word in text for word in ("otp", "code", "verify", "2fa", "mfa")
    ):
        return "code_expired"
    if any(word in text for word in ("incorrect", "invalid", "wrong")) and any(
        word in text for word in ("otp", "code", "verify", "2fa", "mfa")
    ):
        return "invalid_code"
    if "illegal argument" in text or "invalid parameter" in text:
        return "illegal_argument"
    if "2fa" in text or "mfa" in text or "two-factor" in text:
        return "mfa_required"
    if "success" in text:
        return "success"
    return "other"


def _attempt(label: str, status: int, raw: object) -> Attempt:
    if not isinstance(raw, dict):
        return Attempt(label, status, None, "non_json", ())
    result = raw.get("result") if isinstance(raw.get("result"), dict) else {}
    code = raw.get("code") if isinstance(raw.get("code"), int) else None
    authorize_code = result.get("authorizeCode")
    token = result.get("token")
    biz_token = result.get("bizToken")
    account_id = result.get("accountID")
    return Attempt(
        label=label,
        http_status=status,
        server_code=code,
        message_class=_message_class(status, code, raw.get("msg")),
        result_keys=tuple(sorted(_safe_key(key) for key in result)[:24]),
        authorize_code=authorize_code
        if isinstance(authorize_code, str) and authorize_code
        else None,
        token=token if isinstance(token, str) and token else None,
        biz_token=biz_token if isinstance(biz_token, str) and biz_token else None,
        account_id=account_id if isinstance(account_id, str) and account_id else None,
    )


def _web_context(
    *,
    method: str,
    time_zone: str,
    terminal_id: str,
    app_id: str,
    account_id: str = "common",
) -> dict[str, Any]:
    """Build the account-web context shape confirmed by the HAR capture."""
    return {
        "timeZone": time_zone,
        "clientType": "mobile",
        "osInfo": "AndroidOS",
        "phoneOS": "AndroidOS",
        "clientInfo": "Home Assistant",
        "phoneBrand": "HomeAssistant",
        "clientVersion": "V1.0.1",
        "appVersion": "Home Assistant",
        "terminalId": terminal_id,
        "debugMode": False,
        "bizSystemId": _BIZ_SYSTEM_ID,
        "acceptLanguage": "en",
        "traceId": f"HA{secrets.token_hex(10)}",
        "appID": app_id,
        "sourceAppID": app_id,
        "token": "common",
        "accountID": account_id or "common",
        "method": method,
    }


async def _post_wrapped(
    session: ClientSession,
    *,
    base_url: str,
    endpoint: str,
    context: dict[str, Any],
    data: dict[str, Any],
    label: str,
) -> Attempt:
    try:
        async with session.post(
            base_url + endpoint,
            json={"context": context, "data": data},
            timeout=_TIMEOUT,
            raise_for_status=False,
        ) as response:
            status = response.status
            try:
                raw = await response.json(content_type=None)
            except (ValueError, TypeError):
                raw = None
    except (ClientError, TimeoutError) as exc:
        raise ExactMFAError("Unable to reach the VeSync account API") from exc
    return _attempt(label, status, raw)


async def _exchange(
    session: ClientSession,
    *,
    authorize_code: str,
    api_region: str,
    country_code: str,
    time_zone: str,
    terminal_id: str,
) -> Attempt:
    base_url = API_BASE_URL_EU if api_region == API_REGION_EU else API_BASE_URL_US
    request = RequestLoginTokenModel(
        method="loginByAuthorizeCode4Vesync",
        authorizeCode=authorize_code,
        terminalId=terminal_id,
        timeZone=time_zone,
        userCountryCode=country_code,
    )
    payload = request.to_dict()
    try:
        async with session.post(
            base_url + _LOGIN_ENDPOINT,
            json=payload,
            timeout=_TIMEOUT,
            raise_for_status=False,
        ) as response:
            status = response.status
            try:
                raw = await response.json(content_type=None)
            except (ValueError, TypeError):
                raw = None
    except (ClientError, TimeoutError) as exc:
        raise ExactMFAError("Unable to reach the VeSync token endpoint") from exc
    return _attempt("token_exchange", status, raw)


def _hard_stop(attempt: Attempt) -> bool:
    return attempt.message_class in {
        "rate_limited",
        "account_locked",
        "invalid_code",
        "code_expired",
    }


async def _run_host(
    session: ClientSession,
    *,
    account_base: str,
    host_label: str,
    username: str,
    password: str,
    otp_code: str,
    country_code: str,
    api_region: str,
    time_zone: str,
) -> ExactFlowResult:
    terminal_id = f"MallWeb-{uuid4()}"
    app_id = secrets.token_hex(4)
    password_hash = md5(password.encode("utf-8")).hexdigest()  # noqa: S324

    first = await _post_wrapped(
        session,
        base_url=account_base,
        endpoint=_AUTH_ENDPOINT,
        context=_web_context(
            method="authByPWDOrOTM",
            time_zone=time_zone,
            terminal_id=terminal_id,
            app_id=app_id,
        ),
        data={
            "password": password_hash,
            "email": username,
            "authProtocolType": "generic",
        },
        label="password",
    )
    attempts = [first]
    password_hash = ""

    if _hard_stop(first):
        return ExactFlowResult(tuple(attempts), host_label)
    if first.server_code != _MFA_REQUIRED_CODE or not first.biz_token:
        if first.authorize_code:
            exchange = await _exchange(
                session,
                authorize_code=first.authorize_code,
                api_region=api_region,
                country_code=country_code,
                time_zone=time_zone,
                terminal_id=terminal_id,
            )
            attempts.append(exchange)
        return ExactFlowResult(tuple(attempts), host_label)

    second = await _post_wrapped(
        session,
        base_url=account_base,
        endpoint=_MFA_ENDPOINT,
        context=_web_context(
            method="authBy2fa",
            time_zone=time_zone,
            terminal_id=terminal_id,
            app_id=app_id,
            account_id=first.account_id or "common",
        ),
        data={
            "mfaMethod": "otp",
            "bizToken": first.biz_token,
            "otpCode": otp_code,
        },
        label="authBy2fa",
    )
    attempts.append(second)

    if _hard_stop(second) or not second.authorize_code:
        return ExactFlowResult(tuple(attempts), host_label)

    exchange = await _exchange(
        session,
        authorize_code=second.authorize_code,
        api_region=api_region,
        country_code=country_code,
        time_zone=time_zone,
        terminal_id=terminal_id,
    )
    attempts.append(exchange)
    return ExactFlowResult(tuple(attempts), host_label)


async def async_exact_mfa_flow(
    session: ClientSession,
    *,
    username: str,
    password: str,
    otp_code: str,
    country_code: str,
    api_region: str,
    time_zone: str,
) -> ExactFlowResult:
    """Run the captured account-web MFA protocol and normal token exchange.

    The user's HAR used the global account API even for the Hungarian account, so
    that confirmed host is tried first. If it cannot produce an MFA continuation
    and the selected service is EU, the EU account host is tried once as a
    bounded fallback. A recognized invalid/expired OTP, lock, or rate limit stops
    the flow immediately.
    """
    primary = await _run_host(
        session,
        account_base=_ACCOUNT_GLOBAL,
        host_label="global",
        username=username,
        password=password,
        otp_code=otp_code,
        country_code=country_code,
        api_region=api_region,
        time_zone=time_zone,
    )
    if primary.succeeded or primary.authorize_code_found:
        return primary
    if primary.attempts and _hard_stop(primary.attempts[-1]):
        return primary
    if api_region != API_REGION_EU:
        return primary

    return await _run_host(
        session,
        account_base=_ACCOUNT_EU,
        host_label="eu",
        username=username,
        password=password,
        otp_code=otp_code,
        country_code=country_code,
        api_region=api_region,
        time_zone=time_zone,
    )
