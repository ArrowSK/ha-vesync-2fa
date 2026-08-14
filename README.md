# VeSync 2FA Probe for Home Assistant

`ha-vesync-2fa` is an isolated Home Assistant diagnostic integration for VeSync accounts protected by two-factor authentication.

It is **not** a replacement for Home Assistant's built-in **VeSync** integration. The probe uses its own domain, `vesync_2fa_probe`, so the existing Home Assistant VeSync config entry, devices and entities stay untouched.

## Current status — 0.9.0

The authentication protocol is now proven end to end from Home Assistant.

A browser HAR captured from VeSync's own `account.vesync.com` sign-in flow confirmed the missing MFA request:

```text
POST /globalPlatform/api/accountAuth/v1/authBy2fa
```

For the authenticator method the flow is:

```text
password authentication
  -> MFA challenge + bizToken
  -> authBy2fa(mfaMethod=otp, bizToken, otpCode)
  -> authorizeCode
  -> loginByAuthorizeCode4Vesync
  -> session token
```

A live Home Assistant 0.8.0 run confirmed every stage: the password request returned VeSync's `-11257129` MFA challenge, `authBy2fa` returned an `authorizeCode`, and the normal token exchange returned a session token.

The HAR itself contained account identifiers and short-lived authentication material, so it is deliberately **not** committed to this repository. Only the sanitized protocol shape is retained.

## What 0.9.0 adds

0.9.0 keeps the exact 0.8 authentication flow and adds one read-only compatibility check after a token is issued.

The same run:

1. performs the confirmed password -> `authBy2fa` -> authorize-code -> token flow;
2. creates a fresh `pyvesync` manager with blank username/password fields;
3. injects only the returned session token/account context through `VeSync.set_credentials()`;
4. performs the normal read-only `get_devices()` request;
5. if exactly one Home Assistant Core VeSync config entry is already loaded, compares the in-memory device identity set returned by the new session with the identity set used by the working Core integration;
6. reports only counts and a yes/no identity match.

This is specifically intended to answer the last question before designing a production integration: does a session obtained through the real MFA flow behave like a normal `pyvesync` session and resolve the same devices as the existing Home Assistant integration?

0.9.0 does **not** create or update Home Assistant config entries, entities, devices or registry records. It does not change the built-in VeSync manager.

## Security model

Email, password and authenticator code are entered only in the local Home Assistant config flow.

The password is MD5-hashed before the account-web authentication request, matching VeSync's current clients. Passwords, password hashes, OTPs, account IDs, device identifiers, `bizToken` values, `authorizeCode` values and session tokens are kept only in memory for the running flow and are never included in the safe result.

For the 0.9 session check, the fresh `pyvesync` manager is constructed with blank username/password values and receives only the already-issued session credentials through `set_credentials()`.

No persistent Home Assistant config entry is created. No authentication material is written to logs or files by the integration.

The result screen contains only sanitized protocol metadata plus:

- whether the normal `pyvesync` device-list call succeeded;
- number of devices discovered by that temporary session;
- number of existing Core VeSync config entries;
- whether one Core manager is currently loaded;
- its device count when available;
- whether the two in-memory device identity sets match.

Do not post HAR files, passwords, OTPs, raw VeSync responses, cookies, authorization headers, account IDs, device CIDs/MACs, `bizToken` values, authorization codes or session tokens in GitHub issues.

## Installation and testing

1. Add `https://github.com/ArrowSK/ha-vesync-2fa` to HACS as a custom **Integration** repository if it is not already installed.
2. Update **VeSync 2FA Probe** to 0.9.0.
3. Restart Home Assistant.
4. Leave the existing built-in **VeSync** integration alone.
5. Go to **Settings -> Devices & services -> Add integration -> VeSync 2FA Probe**.
6. Enter the VeSync email and password, a fresh current authenticator code, the account country code, and the VeSync API region.
7. Submit once.
8. Copy only the safe metadata shown on the final screen.

The probe intentionally finishes without creating a persistent Home Assistant config entry.

## Isolation from Home Assistant Core VeSync

The diagnostic package uses `vesync_2fa_probe`, not `vesync`. It does not create VeSync entities and does not replace Home Assistant Core's integration.

This separation is deliberate. An earlier same-domain experiment temporarily masked the working built-in VeSync connection while installed. Removing that custom component and restarting Home Assistant restored the original connection, confirming that production changes must preserve Core behavior and registry identity rather than casually replacing another layer.

## Compatibility and validation

The project is validated against Home Assistant Core 2026.8.0 and `pyvesync==3.4.2`.

CI runs structural checks, Python compilation, Hassfest, HACS validation, a Home Assistant runtime smoke test, and initial config-flow schema serialization. The 0.9 checks additionally require that:

- the active flow remains on the isolated `vesync_2fa_probe` domain;
- the exact HAR-confirmed MFA implementation remains active;
- session validation uses `VeSync.set_credentials()` and the normal read-only `get_devices()` path;
- the temporary session manager receives blank username/password fields;
- Core comparison is read-only and uses in-memory device identities only;
- no config-entry, entity-registry or platform mutation API is used by the validation step;
- no HAR file is committed;
- strings and English translations remain synchronized.

## Roadmap

1. **Complete:** capture the real first-stage MFA challenge.
2. **Complete:** eliminate guessed continuation shapes.
3. **Complete:** capture the official web `authBy2fa` request.
4. **Complete:** verify `authBy2fa -> authorizeCode -> VeSync session token` end to end from Home Assistant.
5. **Current:** verify that the MFA-issued session works through normal `pyvesync` device discovery and resolves the same devices as the loaded Core integration.
6. Build a production reauthentication/session-persistence design that preserves the existing Home Assistant VeSync config entry and entity IDs.
7. Regression-test that production design against Home Assistant Core 2026.8 behavior before replacing any working layer.
8. Upstream the protocol work to `pyvesync` and Home Assistant where practical.

The final goal is normal Home Assistant operation with VeSync 2FA enabled, without disabling MFA or recreating existing entities.

## Attribution

This project builds on `pyvesync` and Home Assistant's VeSync integration. VeSync, Etekcity and Levoit names belong to their respective owners. This project is not affiliated with or endorsed by VeSync, Etekcity, Levoit, Home Assistant or the `pyvesync` maintainers.

## Licence

Apache License 2.0. See `LICENSE` and `NOTICE`.
