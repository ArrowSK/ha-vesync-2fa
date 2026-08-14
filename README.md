# VeSync 2FA Probe for Home Assistant

`ha-vesync-2fa` is an isolated Home Assistant diagnostic integration for VeSync accounts protected by two-factor authentication.

It is **not** a replacement for Home Assistant's built-in **VeSync** integration. The probe uses its own domain, `vesync_2fa_probe`, so the existing Home Assistant VeSync config entry, devices and entities stay untouched.

## Current status — 0.8.0

Protocol guessing is no longer the main path.

A browser HAR captured from VeSync's own `account.vesync.com` sign-in flow confirmed the missing MFA request:

```text
POST /globalPlatform/api/accountAuth/v1/authBy2fa
```

The browser sends the password step first, receives the known `-11257129` MFA challenge and a `bizToken`, then sends the selected second factor to `authBy2fa`. For the authenticator method, the request data is:

```text
mfaMethod = otp
bizToken = <challenge token>
otpCode = <current authenticator code>
```

A successful response contains the `authorizeCode` that was missing from every earlier probe. That authorize code can then be passed to VeSync's already-known normal token endpoint:

```text
POST /user/api/accountManage/v1/loginByAuthorizeCode4Vesync
```

The official web bundle also shows the general MFA code-field rule: `email` uses `emailCode`, `otp` uses `otpCode`, and `backupCode` uses `backupCode`.

The HAR itself contained account identifiers and short-lived authentication material, so it is deliberately **not** committed to this repository. Only the protocol shape above is documented.

## What 0.8.0 does

The probe now performs the confirmed flow in one Home Assistant submission:

1. Send the password authentication request using the account-web request wrapper.
2. If VeSync returns the expected MFA challenge, send `authBy2fa` with `mfaMethod=otp`, the returned `bizToken`, and the locally entered `otpCode`.
3. If VeSync returns an `authorizeCode`, perform the normal `loginByAuthorizeCode4Vesync` token exchange.
4. Show only sanitized metadata stating whether each stage produced an MFA challenge, authorization code or session token.

The official account website capture used the global account API host even for the tested Hungarian account, so 0.8.0 tries that confirmed host first. If it cannot progress and the selected service is EU, it performs one bounded retry against the EU account API host.

There is no 15-way guessing ladder in the active 0.8 flow.

## Security model

Email, password and authenticator code are entered only in the local Home Assistant config flow.

The password is MD5-hashed before the account-web authentication request, matching VeSync's current clients. Passwords, password hashes, OTPs, account IDs, `bizToken` values, `authorizeCode` values and session tokens are kept only in memory for the running flow and are never included in the safe result.

No persistent Home Assistant config entry is created. No authentication material is written to logs or files by the integration.

The result screen contains only:

- HTTP status;
- VeSync numeric response code;
- a coarse message classification;
- response field names;
- booleans indicating whether an authorization code or session token appeared.

Do not post HAR files, passwords, OTPs, raw VeSync responses, cookies, authorization headers, account IDs, `bizToken` values, authorization codes or session tokens in GitHub issues.

## Installation and testing

1. Add `https://github.com/ArrowSK/ha-vesync-2fa` to HACS as a custom **Integration** repository if it is not already installed.
2. Update **VeSync 2FA Probe** to 0.8.0.
3. Restart Home Assistant.
4. Leave the existing built-in **VeSync** integration alone.
5. Go to **Settings → Devices & services → Add integration → VeSync 2FA Probe**.
6. Enter the VeSync email and password, a fresh current authenticator code, the account country code, and the VeSync API region.
7. Submit once.
8. Copy only the final safe metadata line if further debugging is needed.

The probe intentionally finishes without creating a persistent Home Assistant config entry.

## Isolation from Home Assistant Core VeSync

The diagnostic package uses `vesync_2fa_probe`, not `vesync`. It does not create VeSync entities and does not replace Home Assistant Core's integration.

This separation is deliberate. An earlier same-domain experiment temporarily masked the working built-in VeSync connection while installed. Removing that custom component and restarting Home Assistant restored the original connection, confirming that protocol experiments must remain isolated until the authentication flow is fully proven.

## Compatibility and validation

The project is validated against Home Assistant Core 2026.8.0 and `pyvesync==3.4.2`.

CI runs structural checks, Python compilation, Hassfest, HACS validation, a Home Assistant runtime smoke test, and initial config-flow schema serialization. The 0.8 checks additionally verify that:

- the active flow uses the isolated `vesync_2fa_probe` domain;
- the frontend schema contains no unsupported regex validator;
- the active implementation references the HAR-confirmed `authBy2fa` endpoint;
- the exact OTP fields are `mfaMethod`, `bizToken`, and `otpCode`;
- the old 15-way ladder is not imported by the active config flow;
- no persistent config entry or entity platform is created;
- translations remain synchronized.

## Roadmap

1. **Complete:** capture the real first-stage MFA challenge.
2. **Complete:** eliminate guessed continuation shapes.
3. **Complete:** capture the official web MFA flow.
4. **Current:** verify `authBy2fa → authorizeCode → VeSync session token` end to end from Home Assistant.
5. Verify VeSync's official trusted-device flow using a stable Home Assistant client identity, without weakening 2FA.
6. Implement safe session persistence and reauthentication in an isolated integration.
7. Design the production migration path that preserves existing Home Assistant VeSync config entries and entity IDs.
8. Upstream the protocol work where practical.

The final goal is normal Home Assistant operation with VeSync 2FA enabled, without disabling MFA or recreating existing entities.

## Attribution

This project builds on `pyvesync` and Home Assistant's VeSync integration. VeSync, Etekcity and Levoit names belong to their respective owners. This project is not affiliated with or endorsed by VeSync, Etekcity, Levoit, Home Assistant or the `pyvesync` maintainers.

## Licence

Apache License 2.0. See `LICENSE` and `NOTICE`.
