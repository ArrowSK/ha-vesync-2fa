# Changelog

## 0.2.0 — 2026-08-13

Authentication design reset around native two-factor support.

- Drops the session-only workaround as the product solution. Session persistence
  remains useful, but the integration no longer tells users to weaken account
  security to bootstrap it.
- Adds a dedicated VeSync first-stage authentication layer that preserves the raw
  MFA branch before `pyvesync` turns it into a generic login failure.
- Detects `mfaMethodList`, `bizToken` and VeSync's known 2FA-required response
  without logging or storing challenge secrets.
- Adds a Home Assistant MFA discovery step that displays only a public-safe
  challenge summary.
- Keeps the exact OTP submission request unimplemented until it has been verified
  from a real VeSync MFA challenge. No speculative authentication endpoints are
  called.
- Promotes expired/revoked sessions into Home Assistant reauthentication so the
  final OTP flow can be reused when VeSync asks for authentication again.
- Keeps the existing `vesync` domain, config-entry version and Home Assistant Core
  platform implementations to protect existing entity/device registry identity.
- Expands runtime tests to cover normal authorization-code responses, MFA
  challenge detection, challenge precedence and secret redaction.
- Adds a repository validation rule preventing the obsolete disable-2FA workaround
  from returning to the public UI/documentation.

## 0.1.0 — 2026-08-13

Initial public prototype.

- Kept the Home Assistant Core `vesync` domain so an existing VeSync config entry
  and entity registry could be retained.
- Saved the authenticated `pyvesync` session after a successful login.
- Restored that session on Home Assistant restart instead of forcing another
  password login.
- Delegated all VeSync entity platforms and diagnostics to Home Assistant Core
  2026.8.x to minimise behavioural drift.
- Added HACS packaging, Hassfest/HACS validation, local structural checks,
  documentation, security guidance and upstream attribution.

The 0.1.0 session-only authentication approach was superseded by 0.2.0 because it
could not recover correctly when VeSync later required authentication on an
account protected by 2FA.
