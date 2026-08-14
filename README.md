# VeSync 2FA for Home Assistant

`ha-vesync-2fa` adds authenticator-based two-factor authentication to Home Assistant's VeSync integration while keeping Home Assistant's existing VeSync device and entity model intact.

Version 1.0.1 is the current production release. The installable HACS package exposes exactly one integration, `custom_components/vesync`. The earlier isolated probe is preserved in Git history rather than shipped alongside the production integration, so HACS has an unambiguous integration domain.

## What has been proven

The current VeSync account-level MFA flow was captured from VeSync's own account website and then reproduced from Home Assistant.

The working sequence is:

```text
password authentication
  -> MFA challenge + bizToken
  -> POST /globalPlatform/api/accountAuth/v1/authBy2fa
       mfaMethod=otp
       bizToken=<challenge token>
       otpCode=<current authenticator code>
  -> authorizeCode
  -> POST /user/api/accountManage/v1/loginByAuthorizeCode4Vesync
  -> session token
```

A live Home Assistant test confirmed all three stages: the password request returned the known `-11257129` MFA challenge, `authBy2fa` returned an `authorizeCode`, and the standard VeSync token exchange returned a session token.

A second live test injected that MFA-issued token into `pyvesync` through `VeSync.set_credentials()` and performed the normal read-only `get_devices()` call. Device discovery succeeded and returned the expected device. This proves the MFA session works with the normal `pyvesync` device stack rather than being a web-only session.

The HAR used during protocol discovery is not stored in this repository because it contained account identifiers and short-lived authentication material.

## What the production build changes

The production component deliberately uses Home Assistant's normal `vesync` domain. That allows it to operate on an existing VeSync config entry and its registry identities instead of creating a parallel integration with duplicate entities.

The change is intentionally narrow:

- Home Assistant Core's existing VeSync entity platforms are imported unchanged: fan, sensor, binary sensor, humidifier, light, number, select, switch and update.
- The Core VeSync config-entry version and minor version are retained.
- Core's existing entity-registry migration and device-removal guard are reused.
- Only authentication, session restoration, session persistence and reauthentication behavior are extended.

The production component does not define replacement entity unique IDs. Existing automations, dashboards and integrations therefore continue to use the existing VeSync registry entries rather than a newly created set.

## Setup and reauthentication

For an account without 2FA, setup still begins with email and password and uses the normal `pyvesync` login path.

For an account protected by authenticator-based 2FA:

1. Home Assistant submits the normal username/password login.
2. If VeSync says a second factor is required, Home Assistant opens a local authenticator-code step.
3. The current code is submitted once through the confirmed `authBy2fa` flow.
4. The resulting session token, account ID, country and current region are stored in the same Home Assistant config entry.
5. The authenticator code is discarded and never stored.

At startup, a stored VeSync session is restored directly with `VeSync.set_credentials()` rather than asking for another MFA code while the session remains valid.

If VeSync later invalidates the session and `pyvesync` can no longer refresh it, the coordinator raises Home Assistant's normal `ConfigEntryAuthFailed` signal. Home Assistant then starts reauthentication. Successful MFA updates and reloads the same config entry; it does not delete and recreate it.

### Existing Core entries and the 1.0.1 fix

Some older Core-created VeSync entries can reach successful MFA and still have a legacy config-entry unique ID that does not equal the account ID returned by the current VeSync token exchange. Version 1.0.0 treated that as a different account and aborted after VeSync had already authenticated successfully.

Version 1.0.1 keeps the account-safety guard but adds a migration-safe fallback for that specific case. Reauthentication is accepted when either the existing unique ID matches, an already-stored VeSync account ID matches, or the successfully authenticated username matches the username already stored in the exact config entry being reauthenticated. The entry is then normalized to the confirmed VeSync account ID. A genuinely different stored username/account is still rejected.

This migration updates the existing config entry in place and does not recreate the VeSync device or entity registry records.

## Important upgrade note for users of the 0.x probe

The diagnostic releases were installed by HACS under the separate domain `vesync_2fa_probe`. The production release intentionally changes the installable domain to `vesync`. HACS remembers the domain/path of an already-added custom integration, so the old probe should not be treated as an ordinary in-place update.

Use this migration instead:

1. In HACS, uninstall **VeSync 2FA Probe**. This removes only the old custom probe files.
2. Restart Home Assistant.
3. Do **not** delete the existing **VeSync** entry under **Settings → Devices & services**, and do not delete its device or entities.
4. In HACS, remove the old custom repository entry if it is still recorded, then add `https://github.com/ArrowSK/ha-vesync-2fa` again as an **Integration** repository. HACS will now detect the single production domain, `vesync`.
5. Install **VeSync 2FA** 1.0.1 and restart Home Assistant.
6. If the existing VeSync entry requires reauthentication, enter the account credentials there and then the current authenticator code when prompted.

The config entry under Home Assistant's Devices & services is separate from the old HACS probe installation. Preserving that config entry is what preserves the ownership link to the existing VeSync entities.

Because `custom_components/vesync` has the same domain as Home Assistant Core's built-in integration, the custom component intentionally takes precedence while installed. If native 2FA support later lands upstream, remove the custom component and restart Home Assistant to return to Core. Do not delete the VeSync config entry merely to remove the custom code.

## Security model

Passwords and authenticator codes are entered only in Home Assistant's local config flow.

The password is MD5-hashed before the account-web authentication request, matching VeSync's current protocol. The one-time authenticator code, MFA challenge token and intermediate `authorizeCode` exist only in memory during authentication.

Home Assistant persists only the information needed to restore the VeSync cloud session:

- session token;
- VeSync account ID;
- account country;
- current VeSync API region;
- the existing username/password fields already used by the Core integration.

The OTP, `bizToken` and `authorizeCode` are not persisted. The integration does not log raw authentication responses or secret values.

Do not publish passwords, authenticator codes, HAR files, cookies, authorization headers, account IDs, device CIDs/MACs, `bizToken` values, `authorizeCode` values or session tokens when reporting problems.

## Compatibility and validation

Version 1.0.1 is built and tested against:

- Home Assistant Core 2026.8.1;
- `pyvesync==3.4.2`.

Home Assistant Core 2026.8.1 still pins `pyvesync==3.4.2`, matching this custom integration.

The production compatibility layer imports the Core 2026.8 VeSync platforms instead of copying their entity implementations. This keeps normal device behavior aligned with the Home Assistant version for which this release is validated.

CI checks repository structure, Python compilation, Hassfest, HACS validation, Home Assistant runtime imports, config-flow schema serialization, the confirmed MFA protocol markers, session persistence invariants, legacy reauthentication identity migration and the production same-domain compatibility layer. The repository is also checked to expose only the single `vesync` integration to HACS and to contain no HAR or captured token material.

## Upstream status

The long-term solution belongs upstream rather than in a permanent same-domain custom override.

`webdjoe/pyvesync#367` is the open, planned 2FA enhancement for the library. The confirmed protocol and successful Home Assistant/`pyvesync` session test from this project have been posted there so the library maintainers have a reproducible implementation path.

The earlier Home Assistant issue `home-assistant/core#153551` documents the same 2FA login failure, but that issue is closed and its conversation is locked, so new findings cannot be posted to it directly.

The clean upstream sequence is therefore:

1. implement the confirmed MFA challenge/verification flow in `pyvesync`;
2. expose an MFA-aware library API rather than making Home Assistant reproduce VeSync's web protocol itself;
3. update the Home Assistant VeSync setup and reauthentication flow to use that API;
4. once those releases are available, retire this custom compatibility layer without recreating users' VeSync entities.

A Home Assistant Core pull request is most useful after, or together with, the corresponding `pyvesync` change because Core currently treats `pyvesync` as the authentication/device library.

## Diagnostic history

Versions 0.3 through 0.9 used a separate `vesync_2fa_probe` domain so protocol discovery could not alter the working Core integration. That probe is no longer included in the installable `custom_components` tree; its source and results remain available in the repository history and changelog.

The discovery sequence was deliberately conservative: capture the MFA challenge, eliminate incorrect request shapes, capture the official website flow, prove token issuance, prove that the token works with ordinary `pyvesync` device discovery, and only then introduce a production `vesync` compatibility layer.

## Attribution

This project builds on `pyvesync` and Home Assistant's VeSync integration. VeSync, Etekcity and Levoit names belong to their respective owners. This project is not affiliated with or endorsed by VeSync, Etekcity, Levoit, Home Assistant or the `pyvesync` maintainers.

## Licence

Apache License 2.0. See `LICENSE` and `NOTICE`.
