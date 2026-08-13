# Changelog

## 0.1.0 — 2026-08-13

Initial public release.

- Keeps the Home Assistant Core `vesync` domain so an existing VeSync config
  entry and entity registry can be retained.
- Saves the authenticated `pyvesync` session after a successful login.
- Restores that session on Home Assistant restart instead of forcing another
  password login.
- Detects VeSync's known account-level 2FA rejection and explains the one-time
  bootstrap procedure rather than returning only a generic authentication error.
- Delegates all VeSync entity platforms and diagnostics to Home Assistant Core
  2026.8.x to minimise behavioural drift.
- Adds HACS packaging, Hassfest/HACS validation, local structural checks,
  documentation, security guidance and upstream attribution.

Known limitation: native VeSync OTP entry is not implemented because `pyvesync`
3.4.2 does not expose the 2FA challenge API. If VeSync revokes a saved session,
2FA must currently be disabled for one reauthentication and can then be enabled
again immediately.
