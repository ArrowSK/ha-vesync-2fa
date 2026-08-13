# VeSync 2FA Probe for Home Assistant

`ha-vesync-2fa` is an isolated Home Assistant diagnostic integration for investigating VeSync account-level two-factor authentication.

It is **not** a replacement for Home Assistant's built-in **VeSync** integration. The probe uses its own domain, `vesync_2fa_probe`, so the existing Home Assistant VeSync config entry, devices and entities stay untouched.

## Current status — 0.6.0

A live VeSync account with 2FA enabled returned this sanitized challenge shape:

```text
outcome=mfa_required; server_code=-11257129; methods=email,otp,backupCode; biz_token=yes; verify_email=no; authorize_code=no; ...
```

That confirms VeSync returns a `bizToken`, advertises available MFA methods and withholds the normal `authorizeCode` until a second authentication stage succeeds.

The 0.5.0 batch then produced the following useful protocol evidence:

- C2, C3 and C4 all returned the same `-11257129` MFA challenge even when the known password-auth endpoint was retried with the credential hash, `bizToken`, and several plausible MFA-method field shapes. In other words, those no-code fields did not visibly advance the challenge.
- C5 and C6, which tried guessed `authByMFA` and `verifyMFA` paths, both returned HTTP 200 with VeSync code `-11102086` and no result fields. The project does not assign a meaning to that undocumented code; the only safe conclusion is that those guesses did not produce a usable continuation.

Version 0.6.0 therefore stops spending user effort on one hypothesis per Home Assistant run. It uses the two VeSync authentication endpoints that are already present in current open-source clients and performs a bounded multi-candidate test around them.

## What 0.6.0 does

After the verified first-stage challenge, and only when VeSync advertises the `otp` MFA method, the probe performs two no-code preflight requests automatically against the known `loginByAuthorizeCode4Vesync` endpoint:

1. challenge `bizToken` without an `authorizeCode`;
2. the same request with `regionChange=lastRegion`, because current `pyvesync` already uses that combination for VeSync's cross-region token flow.

If neither preflight request succeeds or triggers a safety stop, Home Assistant shows one additional form asking for a **fresh authenticator code**. The code is entered locally in Home Assistant and is not copied into GitHub or chat.

That one code is then tried against a short, ordered list of plausible field names on the already-known password-auth endpoint: `mfaCode`, `otp`, `otpCode`, `verificationCode`, `verifyCode`, and `code`. Every request includes the real challenge `bizToken`, the advertised `mfaMethod=otp`, the existing client identity, and the same password hash already used by the verified first-stage request.

If all of those are completely ignored and VeSync simply repeats the original MFA challenge, the probe tries three final code-field variants against the already-known `loginByAuthorizeCode4Vesync` endpoint.

The ladder stops immediately if VeSync:

- returns an `authorizeCode` or session token;
- reports rate limiting or an account lock;
- explicitly reports an invalid or expired code;
- or returns a materially different response that gives us a new protocol signal.

This is still protocol discovery, not a finished production login implementation. Because VeSync does not document this MFA API, any incorrect candidate could theoretically count as a failed MFA attempt. The probe limits requests, pauses between them, and stops on the first meaningful response to reduce that risk.

## Security model

Credentials are entered only in the local Home Assistant config flow. The verified first request uses `pyvesync`'s normal request model, which hashes the password before sending it to VeSync.

For the MFA step, the flow retains only the password hash and the minimum challenge context needed for the live diagnostic attempt. The plaintext password is not stored on the flow object. The authenticator code is held only long enough to make the bounded requests and is discarded immediately afterwards.

No password, password hash, authenticator code, email address, account ID, `bizToken`, `authorizeCode`, cloud token or raw VeSync response is written to a Home Assistant config entry, log, file, GitHub issue or safe result string.

The result screen contains only public-safe metadata: HTTP status, VeSync server code, coarse message classification, response field names, and booleans indicating whether an `authorizeCode` or token appeared.

Do not post passwords, OTPs, email addresses, account IDs, `bizToken` values, authorization codes, session tokens, raw VeSync responses, device CIDs or MAC addresses in GitHub issues.

## Installation and testing

If an old 0.1.x or 0.2.x build remains installed, remove it and restart Home Assistant first. Those historical builds used the `vesync` domain and must not remain in `custom_components/vesync`.

For the current diagnostic build:

1. Add `https://github.com/ArrowSK/ha-vesync-2fa` to HACS as a custom **Integration** repository.
2. Install or update **VeSync 2FA Probe** to 0.6.0.
3. Restart Home Assistant.
4. Leave the existing built-in **VeSync** integration alone.
5. Open **Settings → Devices & services → Add integration → VeSync 2FA Probe**.
6. Enter the VeSync credentials locally in Home Assistant and use the correct account country/API region.
7. If Home Assistant asks for an authenticator code, enter a fresh current code there. Do not paste the code into GitHub or chat.
8. Copy only the safe metadata shown on the final result screen.

The probe intentionally finishes without creating a persistent Home Assistant config entry.

## Isolation from Home Assistant Core VeSync

The diagnostic package uses `vesync_2fa_probe`, not `vesync`. It does not create VeSync entities and does not replace Home Assistant Core's integration.

This separation exists because an earlier same-domain experiment could temporarily mask the working built-in VeSync connection. Removing that custom component and restarting Home Assistant restored the original connection, proving the stored Core config entry had not been deleted but also proving same-domain protocol experiments were not safe enough for production.

The built-in integration therefore remains the source of truth while MFA protocol discovery happens separately.

## Compatibility and validation

The project is validated against Home Assistant Core 2026.8.0 and `pyvesync==3.4.2`.

CI runs repository structural checks, Python compilation, Hassfest, HACS validation and a Home Assistant runtime smoke test. The 0.6 structural checks require the separate probe domain, forbid persistent config entries and Core VeSync imports, restrict the live ladder to VeSync's two already-known authentication endpoints, and check that OTP values cannot appear in safe output or persistence code.

## Roadmap

1. **Complete:** capture the real first-stage MFA challenge.
2. **Complete:** test C1 and determine that removing credentials produces `-11000129`.
3. **Complete:** run C2–C6 in one batch and eliminate several no-code continuation shapes.
4. **Current:** use one fresh local authenticator code to test a bounded set of field-name hypotheses against VeSync's already-known auth endpoints.
5. Identify the first request shape that yields an `authorizeCode` or another clear MFA-specific response.
6. Verify the normal `loginByAuthorizeCode4Vesync` token exchange end to end.
7. Add safe token/session persistence and reauthentication behavior in an isolated implementation.
8. Only after that, design a production strategy that preserves existing Home Assistant VeSync config entries and entity IDs.

The final goal is normal Home Assistant operation with VeSync 2FA enabled, without asking users to weaken account security or recreate their existing entities.

## Attribution

This project builds on `pyvesync` and is intended to produce reproducible protocol evidence that can eventually be upstreamed if practical.

Home Assistant Core is licensed under Apache License 2.0. `pyvesync` is an independent MIT-licensed project and is installed as a dependency rather than bundled here.

VeSync, Etekcity and Levoit names belong to their respective owners. This project is not affiliated with or endorsed by VeSync, Etekcity, Levoit, Home Assistant or the `pyvesync` maintainers.

## Licence

Apache License 2.0. See `LICENSE` and `NOTICE`.
