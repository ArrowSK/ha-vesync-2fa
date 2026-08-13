# VeSync 2FA Probe for Home Assistant

`ha-vesync-2fa` is an isolated Home Assistant diagnostic integration for investigating VeSync account-level two-factor authentication.

It is **not** a replacement for Home Assistant's built-in **VeSync** integration. The probe uses its own domain, `vesync_2fa_probe`, so the existing Home Assistant VeSync config entry, devices and entities stay untouched.

## Current status — 0.7.0

A live VeSync account with 2FA enabled returned this sanitized challenge shape:

```text
outcome=mfa_required; server_code=-11257129; methods=email,otp,backupCode; biz_token=yes; verify_email=no; authorize_code=no; ...
```

That confirms VeSync returns a `bizToken`, advertises available MFA methods and withholds the normal `authorizeCode` until a second authentication stage succeeds.

The 0.5.0 batch then established that adding plausible MFA fields without a code did not advance the challenge: C2, C3 and C4 all returned the same `-11257129` response. Guessed `authByMFA` and `verifyMFA` paths also did not provide a usable continuation.

Version 0.6.0 introduced a separate OTP step in the Home Assistant config flow. On a real HA 2026.8 installation that multi-step form produced a frontend/config-flow validation error where the original username/password/country/region keys were submitted against the OTP-only schema. Version 0.7.0 removes that entire failure mode rather than trying to patch around it.

## What 0.7.0 does

0.7.0 uses **one Home Assistant form only**. The user enters:

- VeSync email;
- VeSync password;
- a fresh current authenticator code;
- account country code;
- VeSync API region.

After submission the probe performs the already-verified first-stage password request. If VeSync returns the known MFA challenge and advertises the `otp` method, the same run automatically tries up to **15 bounded MFA payload hypotheses**.

The candidates vary plausible code field names and payload shapes while staying on only the two VeSync authentication endpoints already used by current open-source clients:

- `/globalPlatform/api/accountAuth/v1/authByPWDOrOTM`
- `/user/api/accountManage/v1/loginByAuthorizeCode4Vesync`

The ladder covers common field names such as `mfaCode`, `otp`, `otpCode`, `verificationCode`, `verifyCode`, `code`, `oneTimePassword` and `totp`; a small number of method-name and nested-object variants; and two candidates on the known authorize-code login endpoint.

If any candidate returns a real `authorizeCode`, the probe automatically performs the normal `loginByAuthorizeCode4Vesync` exchange in memory to verify whether VeSync will issue a session token. The token value itself is never displayed or persisted.

The ladder pauses briefly between requests and stops immediately when VeSync reports:

- an `authorizeCode` or session token;
- rate limiting;
- account lock;
- an explicit invalid/expired MFA code response.

If none of the 15 shapes is recognised, the result still gives one sanitized line containing every attempt, so the next development step can be chosen without asking the tester to repeat 15 separate Home Assistant runs.

## Why one form

The 0.6.0 multi-step config flow was technically valid in isolation but failed in the actual Home Assistant frontend with errors such as:

```text
extra keys not allowed @ data['username']
extra keys not allowed @ data['password']
extra keys not allowed @ data['country_code']
extra keys not allowed @ data['api_region']
```

0.7.0 deliberately avoids any `async_step_otp` transition. The same schema receives all values once, so Home Assistant never has to switch from a credential schema to an OTP-only schema inside the same temporary flow.

## Security model

Credentials are entered only in the local Home Assistant config flow. The verified first request uses `pyvesync`'s normal request model, which hashes the password before sending it to VeSync.

For the MFA ladder, the probe keeps only the password hash, challenge context and authenticator code in memory for the duration of that one run. The local references are dropped immediately afterwards.

No password, password hash, authenticator code, email address, account ID, `bizToken`, `authorizeCode`, cloud token or raw VeSync response is written to a Home Assistant config entry, log, file, GitHub issue or safe result string.

The result screen contains only public-safe metadata: HTTP status, VeSync server code, coarse message classification, response field names, and booleans indicating whether an `authorizeCode` or token appeared.

Do not post passwords, OTPs, email addresses, account IDs, `bizToken` values, authorization codes, session tokens, raw VeSync responses, device CIDs or MAC addresses in GitHub issues.

## Installation and testing

If an old 0.1.x or 0.2.x build remains installed, remove it and restart Home Assistant first. Those historical builds used the `vesync` domain and must not remain in `custom_components/vesync`.

For the current diagnostic build:

1. Add `https://github.com/ArrowSK/ha-vesync-2fa` to HACS as a custom **Integration** repository.
2. Install or update **VeSync 2FA Probe** to 0.7.0.
3. Restart Home Assistant.
4. Leave the existing built-in **VeSync** integration alone.
5. Start a **new** flow at **Settings → Devices & services → Add integration → VeSync 2FA Probe**. Do not reuse a browser form that was already open before the restart.
6. Enter the VeSync credentials locally, a fresh current authenticator code, `HU` (for a Hungarian account) and `EU`.
7. Submit once and wait for the automatic ladder to finish.
8. Copy only the safe metadata shown on the final result screen.

The probe intentionally finishes without creating a persistent Home Assistant config entry.

## Isolation from Home Assistant Core VeSync

The diagnostic package uses `vesync_2fa_probe`, not `vesync`. It does not create VeSync entities and does not replace Home Assistant Core's integration.

This separation exists because an earlier same-domain experiment could temporarily mask the working built-in VeSync connection. Removing that custom component and restarting Home Assistant restored the original connection, proving the stored Core config entry had not been deleted but also proving same-domain protocol experiments were not safe enough for production.

The built-in integration therefore remains the source of truth while MFA protocol discovery happens separately.

## Compatibility and validation

The project is validated against Home Assistant Core 2026.8.0 and `pyvesync==3.4.2`.

CI runs repository structural checks, Python compilation, Hassfest, HACS validation and a Home Assistant runtime smoke test. The 0.7 structural checks additionally require:

- the separate `vesync_2fa_probe` domain;
- the single-form config flow with no `async_step_otp`;
- exactly 15 bounded MFA candidates;
- only the two already-known VeSync authentication endpoints;
- no persistent config entry or entity-platform forwarding;
- no authentication-data logging.

## Roadmap

1. **Complete:** capture the real first-stage MFA challenge.
2. **Complete:** eliminate several no-code continuation shapes.
3. **Complete:** replace the failed multi-step OTP UI with a single-pass Home Assistant flow.
4. **Current:** run one fresh authenticator code through 15 bounded payload hypotheses in a single attempt.
5. Identify the first request shape that yields an `authorizeCode` or a clear MFA-specific error.
6. Verify the normal token exchange end to end.
7. Implement safe session persistence and reauthentication in an isolated integration.
8. Only after that, design a production strategy that preserves existing Home Assistant VeSync config entries and entity IDs.

The final goal is normal Home Assistant operation with VeSync 2FA enabled, without asking users to weaken account security or recreate their existing entities.

## Attribution

This project builds on `pyvesync` and is intended to produce reproducible protocol evidence that can eventually be upstreamed if practical.

Home Assistant Core is licensed under Apache License 2.0. `pyvesync` is an independent MIT-licensed project and is installed as a dependency rather than bundled here.

VeSync, Etekcity and Levoit names belong to their respective owners. This project is not affiliated with or endorsed by VeSync, Etekcity, Levoit, Home Assistant or the `pyvesync` maintainers.

## Licence

Apache License 2.0. See `LICENSE` and `NOTICE`.
