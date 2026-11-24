"""VeSync authenticator-code flow on the app API host, the host pyvesync uses."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from aiohttp import ClientError, ClientSession, ClientTimeout
from pyvesync.const import API_BASE_URL_EU, API_BASE_URL_US, NON_EU_COUNTRY_CODES
from pyvesync.models.vesync_models import RequestGetTokenModel, RequestLoginTokenModel

_AUTH_ENDPOINT = "/globalPlatform/api/accountAuth/v1/authByPWDOrOTM"
_MFA_ENDPOINT = "/globalPlatform/api/accountAuth/v1/authBy2fa"
_LOGIN_ENDPOINT = "/user/api/accountManage/v1/loginByAuthorizeCode4Vesync"
_MFA_REQUIRED_CODE = -11257129
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


async def _post_json(
    session: ClientSession,
    *,
    base_url: str,
    endpoint: str,
    body: dict[str, Any],
) -> tuple[int, dict[str, Any]]:
    try:
        async with session.post(
            base_url + endpoint,
            json=body,
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
    if any(
        word in message
        for word in ("invalid", "incorrect", "wrong", "expired", "does not match")
    ):
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


async def _login_on_api_host(
    session: ClientSession,
    *,
    api_base: str,
    username: str,
    password: str,
    otp_code: str,
    country_code: str,
    region: str,
    time_zone: str,
) -> MFASession:
    # All three steps go to the same app API host with one terminalId. The token
    # exchange only accepts an authorizeCode issued by that host: one issued by the
    # account website host was refused there with -11265129 "login temporary auth
    # code expired".
    first_request = RequestGetTokenModel(
        email=username, method="authByPWDOrOTM", password=password
    ).to_dict()
    terminal_id = first_request["terminalId"]

    status, first = await _post_json(
        session, base_url=api_base, endpoint=_AUTH_ENDPOINT, body=first_request
    )
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
    if not isinstance(biz_token, str) or not biz_token:
        raise MFAError("VeSync MFA challenge did not contain a challenge token")

    second_request = {
        key: value
        for key, value in first_request.items()
        if key not in ("email", "password", "authProtocolType")
    }
    second_request.update(
        {
            "method": "authBy2fa",
            "mfaMethod": "otp",
            "bizToken": biz_token,
            "otpCode": otp_code,
        }
    )
    status, second = await _post_json(
        session, base_url=api_base, endpoint=_MFA_ENDPOINT, body=second_request
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
        return await _login_on_api_host(
            session,
            api_base=API_BASE_URL_US,
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
    return await _login_on_api_host(
        session,
        api_base=API_BASE_URL_EU,
        username=username,
        password=password,
        otp_code=otp_code,
        country_code=country_code,
        region=region,
        time_zone=time_zone,
    )
