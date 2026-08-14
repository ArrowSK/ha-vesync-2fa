# Changelog

## 1.0.0 — 2026-08-14

Production VeSync 2FA support after the authentication and normal-device-session paths were proven end to end from Home Assistant.

- Adds the production `custom_components/vesync` compatibility layer using the same `vesync` domain as Home Assistant Core so existing config entries, device registry records, entity registry records and entity IDs remain the ownership anchor.
- Ships exactly one HACS integration domain, `vesync`. The historical `vesync_2fa_probe` source remains in Git history but is no longer included in the installable `custom_components` tree.
- Documents the required HACS migration for 0.x probe users: uninstall the old probe/repository record, keep the existing Home Assistant VeSync config entry and entities, re-add this repository so HACS detects the production `vesync` domain, then install 1.0.0.
- Keeps Home Assistant Core 2026.8.0's VeSync entity platforms unchanged by delegating fan, sensor, binary sensor, humidifier, light, number, select, switch and update setup directly to Core.
- Retains Core's config-flow version/minor version, entity-registry migration and device-removal guard.
- Adds the confirmed authenticator flow: password authentication -> `authBy2fa(mfaMethod=otp, bizToken, otpCode)` -> `authorizeCode` -> `loginByAuthorizeCode4Vesync` -> session token.
- Stores the resulting session token, account ID, account country and API region in the existing Home Assistant config entry; OTP, `bizToken` and `authorizeCode` are never persisted.
- Restores stored sessions with `VeSync.set_credentials()` on startup, avoiding unnecessary MFA prompts while a session remains valid.
- Preserves normal username/password login for accounts that do not require MFA and persists the resulting normal `pyvesync` session as well.
- Adds setup and reauthentication MFA steps. Reauthentication updates/reloads the existing config entry rather than deleting and recreating it, and rejects a different account ID.
- Extends the Core coordinator only to persist refreshed session credentials and surface an expired/failed authentication session as Home Assistant `ConfigEntryAuthFailed`, causing the normal reauthentication UI to appear.
- Records the final 0.9 field result: an MFA-issued session successfully hydrated `pyvesync` through `set_credentials()` and the ordinary read-only `get_devices()` call succeeded with the expected device count.
- Adds production runtime/schema validation and checks that the HACS package exposes only the production domain and contains no HAR/token material.

The long-term target is upstream support in `pyvesync` and Home Assistant Core. Once native support ships, the custom same-domain layer should be removed without deleting the existing VeSync config entry.

## 0.9.0 — 2026-08-14

Read-only session compatibility validation after the exact MFA flow succeeded in Home Assistant.

- Records the live 0.8.0 result: password authentication returned the expected `-11257129` MFA challenge, `authBy2fa` returned `code=0` with an `authorizeCode`, and `loginByAuthorizeCode4Vesync` returned `code=0` with a session token.
- Keeps the confirmed authentication protocol unchanged; there is no return to endpoint or field-name guessing.
- After a token is issued, hydrates a fresh `pyvesync.VeSync` manager through `set_credentials()` using blank username/password fields.
- Performs one normal read-only `get_devices()` request with that MFA-issued session.
- When exactly one Home Assistant Core VeSync manager is loaded, compares its in-memory device identity set with the temporary MFA-session manager and reports only counts plus `identity_match=yes/no`.
- Does not create or update config entries, entity/device registry records, entities or platforms.
- Adds repository checks that require the session validation to stay read-only and keep the probe on its separate diagnostic domain.

This is the final compatibility proof before a production session-persistence/reauthentication design is allowed to touch the existing VeSync integration layer.

## 0.8.0 — 2026-08-14

Exact MFA protocol implementation based on a browser HAR captured from VeSync's own account website.

- Replaces the active 15-way OTP guessing ladder with VeSync's confirmed MFA endpoint: `/globalPlatform/api/accountAuth/v1/authBy2fa`.
- Reproduces the account-web request wrapper with separate `context` and `data` objects.
- Uses the confirmed authenticator payload fields `mfaMethod=otp`, `bizToken`, and `otpCode`.
- Performs the normal `loginByAuthorizeCode4Vesync` exchange automatically when `authBy2fa` returns an `authorizeCode`.
- Tries the globally hosted account API first because that is what the live VeSync website used for the tested Hungarian account; EU is a single bounded fallback when appropriate.
- Keeps the HAR itself out of the repository because it contains account identifiers and short-lived authentication material.
- Adds a manually validated numeric-OTP check without reintroducing the unsupported `vol.Match` frontend-schema problem.
- Keeps the built-in Home Assistant VeSync integration completely untouched.

The official web bundle also confirmed VeSync's MFA field mapping: `email` -> `emailCode`, `otp` -> `otpCode`, and `backupCode` -> `backupCode`. The bundle exposes a separate trusted-device endpoint as well; 0.8.0 does not call it.

## 0.7.1 — 2026-08-13

Home Assistant frontend schema compatibility fix.

- Replaces the non-serializable `vol.Match` OTP validator that caused a generic 500 before the config flow could render.
- Adds a CI smoke test that serializes the initial Home Assistant config-flow schema so this class of frontend failure is caught automatically.

## 0.7.0 — 2026-08-13

Single-pass MFA discovery after the 0.6 multi-step form failed in a real Home Assistant frontend.

- Removes the separate `async_step_otp` flow that produced `extra keys not allowed` errors when Home Assistant submitted the original credential fields against the OTP-only schema.
- Replaces it with one form containing email, password, authenticator code, country code and API region.
- Runs the verified first-stage password authentication and, on the known MFA challenge, automatically tests up to 15 bounded OTP payload hypotheses in the same request flow.
- Restricts live protocol guesses to the two VeSync authentication endpoints already used by current open-source clients.
- Covers common OTP field names, a few method-name/nested-object variants, and two candidates on the known authorize-code login endpoint.
- If any candidate returns an `authorizeCode`, automatically performs the normal `loginByAuthorizeCode4Vesync` exchange in memory to check whether a session token is issued.
- Stops on success, rate limiting, account lock, or explicit invalid/expired-code responses.
- Keeps passwords, OTPs, account IDs, `bizToken`, authorization codes, session tokens and raw responses out of logs, config entries and safe output.
- Keeps the diagnostic `vesync_2fa_probe` domain isolated from Home Assistant Core's existing `vesync` integration.

## 0.6.0 — 2026-08-13

One-code bounded MFA discovery after the C2–C6 batch results.

- Records the observed 0.5.0 batch behavior: C2, C3 and C4 repeated the same `-11257129` MFA challenge, while C5/C6 returned `-11102086` with no result fields.
- Adds C7/C8 no-code preflight requests against VeSync's already-known `loginByAuthorizeCode4Vesync` endpoint.
- Adds one local Home Assistant authenticator-code step only when VeSync advertises the `otp` method.
- Uses that single fresh code in a bounded D1–D6 field-name ladder on the verified password-auth endpoint, then E1–E3 variants on the known login endpoint only if the first ladder is completely ignored.
- Stops immediately on authorization/session success, rate limiting, account lock, explicit invalid/expired-code responses, or the first materially different protocol response.
- Does not persist or display plaintext passwords, password hashes, authenticator codes, account IDs, challenge tokens, authorization codes, session tokens, or raw API responses.
- Keeps the diagnostic `vesync_2fa_probe` domain isolated from Home Assistant Core's working `vesync` integration.

## 0.5.0 — 2026-08-13

Batch continuation discovery after the first live C1 result.

- Records the observed C1 response: HTTP 200 with server code `-11000129` (`illegal_argument`) after the password field was deliberately removed.
- Adds a single-run C2–C6 continuation ladder so one Home Assistant form submission tests five bounded request shapes automatically instead of requiring repeated manual runs.
- Restores the same password hash used by the verified first-stage VeSync request for the C2–C6 candidates while keeping it local to the running config flow.
- Keeps every continuation attempt no-code: no OTP, email code or backup code is submitted.
- Adds a short pause between attempts and stops on rate limiting, account lock or unexpected `authorizeCode` issuance.
- Keeps the diagnostic `vesync_2fa_probe` domain separate from Home Assistant Core's working `vesync` integration.

## 0.4.0 — 2026-08-13

Controlled continuation hypothesis after confirming the real MFA challenge.

- Added C1, which reused the known `authByPWDOrOTM` endpoint with the live `bizToken` and advertised `mfaMethod=otp`.
- Deliberately omitted the OTP and removed the password hash from C1.
- Reduced the C1 response to safe metadata only.
- C1 returned HTTP 200, server code `-11000129`, classified as `illegal_argument`, with no result fields or `authorizeCode`.
- Preserved the separate diagnostic domain and existing built-in VeSync entry.

## 0.3.0 — 2026-08-13

Safety redesign after live testing of the same-domain override.

- Moved the diagnostic integration from `vesync` to the separate `vesync_2fa_probe` domain.
- Stopped overriding or importing Home Assistant Core's built-in VeSync integration during protocol discovery.
- Removed VeSync entity/platform adapters, coordinator overrides, session persistence and registry migration code from the diagnostic build.
- Added a one-shot config flow that sends the known first-stage VeSync password-authentication request and finishes without creating a persistent config entry.
- Reduced raw responses to a safe metadata summary.
- Added EU/global endpoint selection and account country-code input.
- Confirmed a real live MFA response with server code `-11257129`, advertised methods `email`, `otp`, `backupCode`, a `bizToken`, and no usable `authorizeCode`.

The redesign followed a live Home Assistant test where version 0.2.0 masked the existing built-in VeSync connection while the same-domain custom component was installed. Removing the custom component and restarting restored the original connection, confirming the stored Core config entry had not been deleted.

## 0.2.0 — 2026-08-13

Authentication design reset around native two-factor support.

- Dropped the session-only workaround as the intended final solution.
- Added first-stage MFA challenge discovery and public-safe metadata output.
- Kept the same `vesync` domain in an attempt to preserve existing registry identity.

This release was superseded by 0.3.0 after live testing showed that a same-domain custom component could mask the working built-in VeSync connection.

## 0.1.0 — 2026-08-13

Initial public prototype.

- Saved and restored authenticated `pyvesync` sessions.
- Delegated VeSync entity platforms to Home Assistant Core.
- Added HACS packaging, validation and documentation.

This session-only approach was superseded because it could not complete future reauthentication on accounts protected by 2FA.
