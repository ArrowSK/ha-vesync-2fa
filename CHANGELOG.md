# Changelog

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
