"""Helpers for persisting a VeSync authenticated session.

VeSync currently blocks password login when account-level 2FA is enabled, while
pyvesync does not yet expose the interactive OTP challenge. A successful VeSync
login does, however, return a reusable authenticated session. This module stores
that session in the Home Assistant config entry and restores it on restart.
"""

from collections.abc import Mapping
from typing import Any

from pyvesync import VeSync

from .const import (
    AUTH_DATA_KEYS,
    CONF_AUTH_ACCOUNT_ID,
    CONF_AUTH_COUNTRY_CODE,
    CONF_AUTH_REGION,
    CONF_AUTH_TOKEN,
)


def has_saved_session(data: Mapping[str, Any]) -> bool:
    """Return True when all fields required to restore a session are present."""
    return all(isinstance(data.get(key), str) and data[key] for key in AUTH_DATA_KEYS)


def restore_session(manager: VeSync, data: Mapping[str, Any]) -> bool:
    """Restore saved VeSync credentials into a manager instance."""
    if not has_saved_session(data):
        return False

    manager.set_credentials(
        token=data[CONF_AUTH_TOKEN],
        account_id=data[CONF_AUTH_ACCOUNT_ID],
        country_code=data[CONF_AUTH_COUNTRY_CODE],
        region=data[CONF_AUTH_REGION],
    )
    # pyvesync's set_credentials() restores auth state but intentionally does not
    # flip the manager's runtime flag. update() checks this flag before API calls.
    manager.enabled = True
    return True


def session_data(manager: VeSync) -> dict[str, str]:
    """Return the current VeSync session in config-entry form."""
    credentials = manager.output_credentials_dict()
    if not credentials:
        return {}

    token = credentials.get("token")
    account_id = credentials.get("account_id")
    country_code = credentials.get("country_code")
    region = credentials.get("current_region")

    if not all(isinstance(value, str) and value for value in (token, account_id, country_code, region)):
        return {}

    return {
        CONF_AUTH_TOKEN: token,
        CONF_AUTH_ACCOUNT_ID: account_id,
        CONF_AUTH_COUNTRY_CODE: country_code,
        CONF_AUTH_REGION: region,
    }


def merged_with_session(data: Mapping[str, Any], manager: VeSync) -> dict[str, Any]:
    """Return config-entry data with the manager's current session merged in."""
    merged = dict(data)
    merged.update(session_data(manager))
    return merged
