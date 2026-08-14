# VeSync 2FA for Home Assistant

`ha-vesync-2fa` adds authenticator-based two-factor authentication to Home Assistant's VeSync integration while deliberately keeping the existing Home Assistant device and entity model intact.

Version 1.0.0 is the production build. The earlier `vesync_2fa_probe` component remains in the repository as a diagnostic/research record, but normal use is through the `vesync` integration supplied by `custom_components/vesync`.

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

A second live test then injected that MFA-issued token into `pyvesync` through `VeSync.set_credentials()` and performed the normal read-only `get_devices()` call. Device discovery succeeded and returned the expected single device. This proves the MFA session is usable by the normal `pyvesync` device stack, rather than being a web-only session.

The HAR used during protocol discovery is not stored in this repository because it contained account identifiers and short-lived authentication material.

## What 1.0.0 changes

The production component deliberately uses the normal Home Assistant domain, `vesync`. This is necessary to operate on the existing VeSync config entry and registry identities instead of creating a second set of devices and entities.

The change is intentionally narrow:

- Home Assistant's existing VeSync entity platforms are imported from Core unchanged: fan, sensor, binary sensor, humidifier, light, number, select, switch and update.
- The Core VeSync config-entry version and minor version are retained.
- Core's existing entity-registry migration and device-removal guard are reused.
- Only authentication, session restoration, session persistence and reauthentication behavior are extended.

In particular, 1.0.0 does **not** invent new VeSync entity unique IDs or recreate devices. Existing automations, dashboards and integrations that refer to existing VeSync entity IDs should therefore continue to refer to the same registry entries.

## Setup and reauthentication

For an account without 2FA, setup still starts with the usual email and password and uses the normal `pyvesync` login path.

For an account with authenticator-based 2FA:

1. Home Assistant first submits the normal username/password login.
2. If VeSync responds that 2FA is required, Home Assistant shows a separate local authenticator-code form.
3. The current code is sent once through the confirmed `authBy2fa` flow.
4. The resulting VeSync session token, account ID, country and current region are saved in the existing Home Assistant config entry.
5. The authenticator code itself is discarded and is never saved.

At startup, a stored VeSync session is restored directly with `VeSync.set_credentials()` instead of unnecessarily repeating MFA.

If VeSync later invalidates the session and `pyvesync` can no longer refresh it, the coordinator raises Home Assistant's normal `ConfigEntryAuthFailed` signal. Home Assistant then opens the reauthentication flow. The same config entry is updated and reloaded after successful MFA; it is not deleted and recreated.

## Existing VeSync installations

The production design is specifically intended for an already-configured Home Assistant VeSync account.

When upgrading from the diagnostic releases:

1. Update this HACS repository to 1.0.0.
2. Restart Home Assistant.
3. **Do not delete the existing VeSync integration, device or entities.**
4. If Home Assistant asks the existing VeSync entry to reauthenticate, enter the account credentials there.
5. When VeSync requires the second factor, enter a fresh authenticator code in Home Assistant.

The existing config entry remains the ownership anchor for the VeSync entities. The new session fields are added to that entry during successful authentication.

Because `custom_components/vesync` has the same domain as Home Assistant Core's built-in integration, the custom component intentionally takes precedence while installed. If native 2FA support later lands in Home Assistant/`pyvesync`, remove this custom component and restart Home Assistant to return to Core. Do not delete the VeSync config entry merely to remove the custom code.

## Security model

Passwords and authenticator codes are entered only in Home Assistant's local config flow.

The password is MD5-hashed before the account-web authentication request, matching VeSync's current client protocol. The one-time authenticator code, MFA challenge token and intermediate `authorizeCode` exist only in memory during authentication.

Home Assistant persists only the information required to restore the VeSync cloud session:

- session token;
- VeSync account ID;
- account country;
- current VeSync API region;
- the existing username/password fields already used by the Core integration.

The OTP, `bizToken` and `authorizeCode` are not persisted. The integration does not log raw authentication responses or secret values.

Do not publish passwords, authenticator codes, HAR files, cookies, authorization headers, account IDs, device CIDs/MACs, `bizToken` values, `authorizeCode` values or session tokens when reporting problems.

## Compatibility

Version 1.0.0 is built and tested against:

- Home Assistant Core 2026.8.0;
- `pyvesync==3.4.2`.

The production compatibility layer imports the Core 2026.8 VeSync platforms rather than copying their entity implementations. This keeps normal device behavior aligned with the Home Assistant version for which this release is validated.

CI checks include repository validation, Python compilation, Hassfest, HACS validation, Home Assistant runtime imports, frontend schema serialization, the captured MFA protocol shape, `pyvesync` session hydration, and the production same-domain compatibility layer.

## Why upstreaming should happen in two places

The long-term solution belongs upstream rather than in a permanent same-domain custom override.

`pyvesync` already has an open 2FA enhancement, issue `webdjoe/pyvesync#367`. A Home Assistant VeSync maintainer noted there that once the library supports 2FA, the Home Assistant device flow can be updated as well.

Home Assistant also has the open integration issue `home-assistant/core#153551`, which documents the current failure when a VeSync account requires 2FA.

The protocol findings from this project are suitable for both discussions. The clean upstream implementation would normally be:

1. add the confirmed MFA challenge/verification support to `pyvesync`;
2. expose an MFA-aware API from the library;
3. add the corresponding setup and reauthentication steps to Home Assistant Core;
4. once released, retire this custom same-domain layer without recreating users' entities.

## Diagnostic history

The repository includes the earlier isolated `vesync_2fa_probe` component because it documents how the protocol was established safely. That component uses a different domain and does not create persistent VeSync entities. It is no longer required for normal operation once 1.0.0 is installed.

The discovery sequence was intentionally conservative: first capture the MFA challenge, then eliminate incorrect request shapes, then capture the official website flow, then prove token issuance, and finally prove that the token works with normal `pyvesync` device discovery before touching the production `vesync` domain.

## Attribution

This project builds on `pyvesync` and Home Assistant's VeSync integration. VeSync, Etekcity and Levoit names belong to their respective owners. This project is not affiliated with or endorsed by VeSync, Etekcity, Levoit, Home Assistant or the `pyvesync` maintainers.

## Licence

Apache License 2.0. See `LICENSE` and `NOTICE`.
