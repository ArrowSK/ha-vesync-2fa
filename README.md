# VeSync 2FA Probe for Home Assistant

`ha-vesync-2fa` is an isolated Home Assistant diagnostic integration for investigating VeSync account-level two-factor authentication.

It is **not** a replacement for Home Assistant's built-in **VeSync** integration. The probe uses its own domain, `vesync_2fa_probe`, so the existing Home Assistant VeSync config entry, devices and entities stay untouched.

## Current status — 0.5.0

A live VeSync account with 2FA enabled returned this sanitized challenge shape:

```text
outcome=mfa_required; server_code=-11257129; methods=email,otp,backupCode; biz_token=yes; verify_email=no; authorize_code=no; ...
```

That confirms VeSync returns a `bizToken`, advertises available MFA methods and withholds the normal `authorizeCode` until a second authentication stage succeeds.

Version 0.4.0 then tested C1: the known `authByPWDOrOTM` endpoint was reused with the issued `bizToken` and `mfaMethod=otp`, but the password field and OTP were deliberately omitted. VeSync replied with HTTP 200 and server code `-11000129`, classified as `illegal_argument`.

Version 0.5.0 reduces the amount of manual testing. One Home Assistant form submission now runs several bounded no-code continuation hypotheses automatically.

## C2–C6 ladder

After the normal first-stage challenge, and only when VeSync advertises `otp`, the probe tries:

1. `c2_same_auth_password_mfaMethod` — same known endpoint, credential hash restored, `bizToken`, `mfaMethod=otp`.
2. `c3_same_auth_password_bizToken_only` — same endpoint and credential hash with `bizToken`, but no explicit MFA-method field.
3. `c4_same_auth_password_mfaMethodType` — same endpoint with `mfaMethodType=otp`.
4. `c5_authByMFA_password_mfaMethod` — guessed `authByMFA` account-auth route with the same request context.
5. `c6_verifyMFA_password_mfaMethod` — guessed `verifyMFA` account-auth route with the same request context.

The last two endpoint names are hypotheses, not documented VeSync APIs. The probe is specifically meant to test those hypotheses safely.

The ladder sends **no OTP, email code or backup code**. It pauses briefly between attempts and stops if VeSync signals rate limiting, an account lock, or unexpectedly returns an `authorizeCode`.

## Security model

Credentials are entered only in the local Home Assistant config flow. `pyvesync`'s request model hashes the password for the VeSync authentication request. Version 0.5.0 may reconstruct that same hash in memory for the continuation candidates because C1 showed that removing the credential field produced an illegal-argument response.

Neither the plaintext password nor its hash is logged, displayed, written to a Home Assistant config entry or sent anywhere except VeSync. The same applies to the live `bizToken`, account ID and raw responses.

The result screen contains only public-safe metadata: HTTP status, VeSync server code, coarse message classification, response field names and whether an `authorizeCode` appeared.

Do not post passwords, OTPs, email addresses, account IDs, `bizToken` values, authorization codes, session tokens, raw VeSync responses, device CIDs or MAC addresses in GitHub issues.

## Installation and testing

If an old 0.1.x or 0.2.x build remains installed, remove it and restart Home Assistant first. Those historical builds used the `vesync` domain and must not remain in `custom_components/vesync`.

For the current diagnostic build:

1. Add `https://github.com/ArrowSK/ha-vesync-2fa` to HACS as a custom **Integration** repository.
2. Install or update **VeSync 2FA Probe**.
3. Restart Home Assistant.
4. Leave the existing built-in **VeSync** integration alone.
5. Open **Settings → Devices & services → Add integration → VeSync 2FA Probe**.
6. Enter the VeSync credentials locally in Home Assistant and run it once.
7. Copy only the safe metadata shown on the result screen.

The probe intentionally finishes without creating a persistent Home Assistant config entry.

## Isolation from Home Assistant Core VeSync

The diagnostic package uses `vesync_2fa_probe`, not `vesync`. It does not create VeSync entities and does not replace Home Assistant Core's integration.

This separation exists because an earlier same-domain experiment could temporarily mask the working built-in VeSync connection. Removing that custom component and restarting Home Assistant restored the original connection, proving the stored Core config entry had not been deleted but also proving same-domain protocol experiments were not safe enough for production.

The built-in integration therefore remains the source of truth while MFA protocol discovery happens separately.

## Compatibility and validation

The project is validated against Home Assistant Core 2026.8.0 and `pyvesync==3.4.2`.

CI runs repository structural checks, Python compilation, Hassfest, HACS validation and the existing Home Assistant runtime smoke test. The 0.5 structural checks additionally require the C2–C6 ladder, rate-limit/account-lock stops, the separate probe domain and the absence of any second-factor submission fields.

## Roadmap

1. **Complete:** capture the real first-stage MFA challenge.
2. **Complete:** run C1 and identify the illegal-argument result after credentials were removed.
3. **Current:** run C2–C6 automatically in one diagnostic attempt.
4. Find the first request shape VeSync recognises beyond the generic MFA challenge.
5. Only then add one local Home Assistant OTP step against that exact request shape.
6. Verify `authorizeCode` issuance, normal VeSync token exchange and later reauthentication with 2FA still enabled.
7. Add regression tests for existing VeSync config entries and entity IDs before considering any production integration strategy.

The final goal is normal Home Assistant operation with VeSync 2FA enabled, without asking users to weaken account security or recreate their existing entities.

## Attribution

This project builds on `pyvesync` and is intended to produce reproducible protocol evidence that can eventually be upstreamed if practical.

Home Assistant Core is licensed under Apache License 2.0. `pyvesync` is an independent MIT-licensed project and is installed as a dependency rather than bundled here.

VeSync, Etekcity and Levoit names belong to their respective owners. This project is not affiliated with or endorsed by VeSync, Etekcity, Levoit, Home Assistant or the `pyvesync` maintainers.

## Licence

Apache License 2.0. See `LICENSE` and `NOTICE`.
