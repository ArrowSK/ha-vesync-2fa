"""VeSync authenticator-code flow captured from the official account website."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import md5
import secrets
from typing import Any
from uuid import uuid4

from aiohttp import ClientError, ClientSession, ClientTimeout
from pyvesync.const import API_BASE_URL_EU, API_BASE_URL_US, NON_EU_COUNTRY_CODES
from pyvesync.models.vesync_models import RequestLoginTokenModel

_ACCOUNT_GLOBAL = "https://accountapi.vesync.com"
_ACCOUNT_EU = "https://accountapi.vesync.eu"
_AUTH_ENDPOINT = "/globalPlatform/api/accountAuth/v1/authByPWDOrOTM"
_MFA_ENDPOINT = "/globalPlatform/api/accountAuth/v1/authBy2fa"
_LOGIN_ENDPOINT = "/user/api/accountManage/v1/loginByAuthorizeCode4Vesync"
_MFA_REQUIRED_CODE = -11257129
_BIZ_SYSTEM_ID = "28005ad6-fca3-4634-9b43-ac47129c3b70"
_TIMEOUT = ClientTimeout(total=12)


class MFAError(Exception):
    """Base error for the VeSync MFA flow."""


class MFAInvalidCode(MFAError):
    """The submitted authenticator code was rejected or expired."""


class MFARateLimited(MFAError):
    """VeSync rate-limited the authentication flow."""


class MFAAccountLocked(MFAError):
    """VeSync reported the account as locked or frozen."""


@dataclass(slots=True, frozen=True)
class MFASession:
    """Authenticated session credentials returned by VeSync."""

    token: str
    account_id: str
    country_code: str
    current_region: str


def region_for_country(country_code: str) -> str:
    """Map an account country to the pyvesync service region."""
    return "US" if country_code.upper() in NON_EU_COUNTRY_CODES else "EU"


def is_mfa_required_error(error: Exception) -> bool:
    """Recognize pyvesync's current MFA-required login error."""
    text = str(error).casefold()
    return "2fa authentication" in text or "requires 2fa" in text


def _web_context(
    *,
    method: str,
    time_zone: str,
    terminal_id: str,
    app_id: str,
    account_id: str = "common",
) -> dict[str, Any]:
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
) -> tuple[int, dict[str, Any]]:
    try:
        async with session.post(
            base_url + endpoint,
            json={"context": context, "data": data},
            timeout=_TIMEOUT,
            raise_for_status=False,
        ) as response:
            status = response.status
            raw = await response.json(content_type=None)
    except (ClientError, TimeoutError, ValueError, TypeError) as exc:
        raise MFAError("Unable to obtain a usable response from VeSync") from exc
    if not isinstance(raw, dict):
        raise MFAError("VeSync returned an invalid authentication response")
    return status, raw


def _raise_auth_error(status: int, raw: dict[str, Any]) -> None:
    message = str(raw.get("msg") or "").casefold()
    if status == 429 or "too many" in message or "rate" in message:
        raise MFARateLimited("VeSync rate-limited the authentication request")
    if "locked" in message or "frozen" in message:
        raise MFAAccountLocked("VeSync reported the account as locked")
    if any(word in message for word in ("invalid", "incorrect", "wrong", "expired")):
        raise MFAInvalidCode("The authenticator code was rejected or expired")
    raise MFAError("VeSync rejected the MFA request")


async def _exchange_authorize_code(
    session: ClientSession,
    *,
    authorize_code: str,
    country_code: str,
    region: str,
    time_zone: str,
    terminal_id: str,
) -> MFASession:
    base_url = API_BASE_URL_EU if region == "EU" else API_BASE_URL_US
    request = RequestLoginTokenModel(
        method="loginByAuthorizeCode4Vesync",
        authorizeCode=authorize_code,
        terminalId=terminal_id,
        timeZone=time_zone,
        userCountryCode=country_code,
    )
    try:
        async with session.post(
            base_url + _LOGIN_ENDPOINT,
            json=request.to_dict(),
            timeout=_TIMEOUT,
            raise_for_status=False,
        ) as response:
            status = response.status
            raw = await response.json(content_type=None)
    except (ClientError, TimeoutError, ValueError, TypeError) as exc:
        raise MFAError("Unable to exchange the VeSync authorization code") from exc
    if not isinstance(raw, dict) or raw.get("code") != 0:
        _raise_auth_error(status, raw if isinstance(raw, dict) else {})
    result = raw.get("result")
    if not isinstance(result, dict):
        raise MFAError("VeSync token response did not contain a result")
    token = result.get("token")
    account_id = result.get("accountID")
    if not isinstance(token, str) or not token or not isinstance(account_id, str) or not account_id:
        raise MFAError("VeSync token response did not contain session credentials")
    actual_country = result.get("countryCode")
    actual_region = result.get("currentRegion")
    return MFASession(
        token=token,
        account_id=account_id,
        country_code=actual_country if isinstance(actual_country, str) and actual_country else country_code,
        current_region=actual_region if isinstance(actual_region, str) and actual_region else region,
    )


async def _login_on_account_host(
    session: ClientSession,
    *,
    account_base: str,
    username: str,
    password: str,
    otp_code: str,
    country_code: str,
    region: str,
    time_zone: str,
) -> MFASession:
    terminal_id = f"MallWeb-{uuid4()}"
    app_id = secrets.token_hex(4)
    password_hash = md5(password.encode("utf-8")).hexdigest()  # noqa: S324

    status, first = await _post_wrapped(
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
    )
    password_hash = ""
    first_result = first.get("result") if isinstance(first.get("result"), dict) else {}
    if first.get("code") == 0:
        authorize_code = first_result.get("authorizeCode")
        if isinstance(authorize_code, str) and authorize_code:
            return await _exchange_authorize_code(
                session,
                authorize_code=authorize_code,
                country_code=country_code,
                region=region,
                time_zone=time_zone,
                terminal_id=terminal_id,
            )
        raise MFAError("VeSync password response did not contain an authorization code")
    if first.get("code") != _MFA_REQUIRED_CODE:
        _raise_auth_error(status, first)

    biz_token = first_result.get("bizToken")
    account_id = first_result.get("accountID")
    if not isinstance(biz_token, str) or not biz_token:
        raise MFAError("VeSync MFA challenge did not contain a challenge token")

    status, second = await _post_wrapped(
        session,
        base_url=account_base,
        endpoint=_MFA_ENDPOINT,
        context=_web_context(
            method="authBy2fa",
            time_zone=time_zone,
            terminal_id=terminal_id,
            app_id=app_id,
            account_id=account_id if isinstance(account_id, str) and account_id else "common",
        ),
        data={
            "mfaMethod": "otp",
            "bizToken": biz_token,
            "otpCode": otp_code,
        },
    )
    if second.get("code") != 0:
        _raise_auth_error(status, second)
    second_result = second.get("result") if isinstance(second.get("result"), dict) else {}
    authorize_code = second_result.get("authorizeCode")
    if not isinstance(authorize_code, str) or not authorize_code:
        raise MFAError("VeSync MFA response did not contain an authorization code")

    return await _exchange_authorize_code(
        session,
        authorize_code=authorize_code,
        country_code=country_code,
        region=region,
        time_zone=time_zone,
        terminal_id=terminal_id,
    )


async def async_login_with_otp(
    session: ClientSession,
    *,
    username: str,
    password: str,
    otp_code: str,
    country_code: str,
    time_zone: str,
) -> MFASession:
    """Complete the verified VeSync password + authenticator flow."""
    region = region_for_country(country_code)
    try:
        return await _login_on_account_host(
            session,
            account_base=_ACCOUNT_GLOBAL,
            username=username,
            password=password,
            otp_code=otp_code,
            country_code=country_code,
            region=region,
            time_zone=time_zone,
        )
    except (MFAInvalidCode, MFARateLimited, MFAAccountLocked):
        raise
    except MFAError:
        if region != "EU":
            raise
    return await _login_on_account_host(
        session,
        account_base=_ACCOUNT_EU,
        username=username,
        password=password,
        otp_code=otp_code,
        country_code=country_code,
        region=region,
        time_zone=time_zone,
    )
