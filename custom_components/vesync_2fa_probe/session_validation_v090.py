"""Read-only session validation for VeSync 2FA Probe 0.9.

After the HAR-confirmed MFA flow returns a session token, this module hydrates a
fresh pyvesync manager with that token and performs only the normal device-list
read. It optionally compares the discovered device identity set with the already
loaded Home Assistant Core VeSync manager. No entities, config entries, registry
records or devices are created or changed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from homeassistant.core import HomeAssistant
from pyvesync import VeSync
from pyvesync.utils.errors import VeSyncError

from .const import API_REGION_EU
from .exact_mfa_v080 import ExactFlowResult

_CORE_DOMAIN = "vesync"


@dataclass(slots=True, frozen=True)
class SessionValidationResult:
    """Public-safe metadata from read-only session validation."""

    device_list_ok: bool
    device_count: int | None
    core_entry_count: int
    core_loaded: bool
    core_device_count: int | None
    identity_match: bool | None

    @property
    def safe_summary(self) -> str:
        if self.identity_match is None:
            identity = "not_compared"
        else:
            identity = "yes" if self.identity_match else "no"
        return (
            "session_validation="
            f"device_list={'ok' if self.device_list_ok else 'failed'};"
            f"devices={self.device_count if self.device_count is not None else 'unknown'};"
            f"core_entries={self.core_entry_count};"
            f"core_loaded={'yes' if self.core_loaded else 'no'};"
            f"core_devices={self.core_device_count if self.core_device_count is not None else 'unknown'};"
            f"identity_match={identity}"
        )


def _identity_set(manager: Any) -> set[tuple[str, str]]:
    """Build an in-memory device identity set without exposing the identifiers."""
    identities: set[tuple[str, str]] = set()
    for device in manager.devices:
        cid = getattr(device, "cid", None)
        if not isinstance(cid, str) or not cid:
            continue
        sub_device_no = getattr(device, "sub_device_no", None)
        identities.add((cid, "" if sub_device_no is None else str(sub_device_no)))
    return identities


def _token_attempt(result: ExactFlowResult):
    """Return the successful token-exchange attempt, if present."""
    for attempt in reversed(result.attempts):
        if attempt.token and attempt.account_id:
            return attempt
    return None


async def async_validate_session(
    hass: HomeAssistant,
    *,
    session,
    exact_result: ExactFlowResult,
    country_code: str,
    api_region: str,
    time_zone: str,
) -> SessionValidationResult:
    """Hydrate pyvesync with the returned token and perform a read-only device list."""
    token_attempt = _token_attempt(exact_result)
    core_entries = hass.config_entries.async_entries(_CORE_DOMAIN)

    if token_attempt is None:
        return SessionValidationResult(
            device_list_ok=False,
            device_count=None,
            core_entry_count=len(core_entries),
            core_loaded=False,
            core_device_count=None,
            identity_match=None,
        )

    region = "EU" if api_region == API_REGION_EU else "US"
    # Username/password are deliberately blank here. The fresh manager is
    # authenticated only with the session credentials returned by the exact MFA
    # flow, so plaintext account credentials are not retained for this step.
    manager = VeSync(
        username="",
        password="",
        country_code=country_code,
        session=session,
        time_zone=time_zone,
    )
    manager.set_credentials(
        token_attempt.token or "",
        token_attempt.account_id or "",
        country_code,
        region,
    )
    manager.enabled = True

    try:
        device_list_ok = await manager.get_devices()
    except VeSyncError:
        device_list_ok = False

    device_count = len(manager.devices) if device_list_ok else None

    loaded_managers: list[Any] = []
    for entry in core_entries:
        runtime_data = getattr(entry, "runtime_data", None)
        core_manager = getattr(runtime_data, "manager", None)
        if core_manager is not None:
            loaded_managers.append(core_manager)

    core_loaded = bool(loaded_managers)
    core_device_count: int | None = None
    identity_match: bool | None = None

    if len(loaded_managers) == 1:
        core_manager = loaded_managers[0]
        core_device_count = len(core_manager.devices)
        if device_list_ok:
            identity_match = _identity_set(manager) == _identity_set(core_manager)
    elif loaded_managers:
        core_device_count = sum(len(item.devices) for item in loaded_managers)

    # The fresh manager uses Home Assistant's shared aiohttp session and owns no
    # external resource that needs closing. Secret token/account values remain
    # referenced only by these local objects and are not persisted or logged.
    return SessionValidationResult(
        device_list_ok=device_list_ok,
        device_count=device_count,
        core_entry_count=len(core_entries),
        core_loaded=core_loaded,
        core_device_count=core_device_count,
        identity_match=identity_match,
    )
