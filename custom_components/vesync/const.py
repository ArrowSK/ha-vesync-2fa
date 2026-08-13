"""Constants for the VeSync session bridge."""

from homeassistant.components.vesync.const import DOMAIN

CONF_AUTH_TOKEN = "auth_token"
CONF_AUTH_ACCOUNT_ID = "auth_account_id"
CONF_AUTH_COUNTRY_CODE = "auth_country_code"
CONF_AUTH_REGION = "auth_region"

AUTH_DATA_KEYS = (
    CONF_AUTH_TOKEN,
    CONF_AUTH_ACCOUNT_ID,
    CONF_AUTH_COUNTRY_CODE,
    CONF_AUTH_REGION,
)
