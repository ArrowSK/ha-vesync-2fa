"""Constants for the VeSync 2FA compatibility layer."""

from homeassistant.components.vesync.const import DOMAIN

CONF_ACCOUNT_ID = "account_id"
CONF_COUNTRY_CODE = "country_code"
CONF_CURRENT_REGION = "current_region"
CONF_OTP_CODE = "otp_code"
CONF_SESSION_TOKEN = "token"

__all__ = [
    "CONF_ACCOUNT_ID",
    "CONF_COUNTRY_CODE",
    "CONF_CURRENT_REGION",
    "CONF_OTP_CODE",
    "CONF_SESSION_TOKEN",
    "DOMAIN",
]
