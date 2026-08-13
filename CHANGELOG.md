# Changelog

## Unreleased

Field-test findings after the 0.3.0 isolation redesign.

- Confirmed a real VeSync MFA challenge with 2FA left enabled.
- Confirmed server code `-11257129` and advertised MFA methods `email`, `otp` and
  `backupCode`.
- Confirmed the challenge supplies a `bizToken` but no usable `authorizeCode`,
  which establishes that the second factor must be verified before the normal
  authorization-code exchange can continue.
- Added the sanitized live challenge shape to runtime tests so future parser
  changes are checked against the response actually observed in Home Assistant.
- Marked first-stage protocol discovery complete in the documentation. The exact
  second-factor verification endpoint and payload remain deliberately
  unimplemented until verified from reproducible evidence.

## 0.3.0 — 2026-08-13

Safety redesign after live testing of the same-domain override.

- Moves the diagnostic integration from `vesync` to the separate
  `vesync_2fa_probe` domain.
- Stops overriding or importing Home Assistant Core's built-in VeSync
  integration during protocol discovery.
- Removes all VeSync entity/platform adapters, coordinator overrides, session
  persistence and registry migration code from the diagnostic build.
- Adds a one-shot config flow that sends only the known first-stage VeSync
  password-authentication request and always finishes without creating a
  persistent Home Assistant config entry.
- Reduces raw responses to a safe metadata summary containing only the server
  code, sanitized MFA method names, presence flags and response field names.
- Explicitly does not exchange authorization codes or submit a second factor.
- Adds EU/global endpoint selection and account country-code input.
- Adds regression checks that fail if `custom_components/vesync` returns to the
  repository, if the probe creates entries, or if authorization-code exchange
  logic is added to the diagnostic build.
- Updates runtime tests so Home Assistant Core's `vesync` component and the
  custom probe import side by side with different domains.

The redesign follows a live Home Assistant test where version 0.2.0 masked the
existing built-in VeSync connection while the same-domain custom component was
installed. Removing the custom component and restarting Home Assistant restored
the original connection, confirming that the stored Core config entry had not
been deleted. Protocol discovery is now isolated from the working integration.

## 0.2.0 — 2026-08-13

Authentication design reset around native two-factor support.

- Dropped the session-only workaround as the intended final solution.
- Added first-stage MFA challenge discovery and public-safe metadata output.
- Kept the same `vesync` domain in an attempt to preserve existing registry
  identity.

This release was superseded by 0.3.0 after live testing showed that a same-domain
custom component could mask the working built-in VeSync connection. Do not use
0.2.0 for protocol discovery.

## 0.1.0 — 2026-08-13

Initial public prototype.

- Saved and restored authenticated `pyvesync` sessions.
- Delegated VeSync entity platforms to Home Assistant Core.
- Added HACS packaging, validation and documentation.

This session-only approach was superseded because it could not complete future
reauthentication on accounts protected by 2FA.
