# VeSync 2FA for Home Assistant

This repository is a Home Assistant custom integration for VeSync accounts that
use account-level two-factor authentication.

The goal is narrow: make VeSync authentication work properly with 2FA enabled,
including future reauthentication, without creating a second set of Home
Assistant entities.

This is an override of Home Assistant's built-in `vesync` integration. It keeps
the same integration domain, config-entry version, device identifiers and entity
implementations. Only the authentication/session layer is changed.

## Current status

**0.2.0 is a protocol-discovery build, not the final OTP implementation.**

It already does three useful things that the built-in integration cannot do:

- it sends VeSync's current first-stage authentication request itself instead of
  letting `pyvesync` discard the MFA response;
- it detects a real VeSync MFA challenge and preserves the challenge state in
  memory without logging or storing its secrets;
- it turns an expired/revoked VeSync session into Home Assistant
  reauthentication instead of repeatedly attempting a password-only background
  login.

What is still missing is the exact request used by VeSync to verify the second
factor. That request is not implemented in `pyvesync` 3.4.2 and no verified
open-source implementation has been found. The repository therefore does not
invent an endpoint or send your one-time code to a guessed API.

The next field test is designed to obtain the small piece of non-secret protocol
metadata needed to finish that implementation. You can run it with 2FA left on.

## Why the previous session-only approach was dropped

Saving a valid VeSync cloud token is useful because Home Assistant should not ask
for MFA on every restart. It is not a complete solution by itself: a cloud token
can eventually expire or be revoked, and `pyvesync` currently responds by trying
username/password authentication again. An account that requires MFA cannot
complete that password-only retry.

Session persistence remains in this project, but it is now only one part of the
design. The required end state is:

1. Home Assistant sends username/password to VeSync.
2. If VeSync requires MFA, Home Assistant continues to an MFA step.
3. The user enters the VeSync second factor.
4. VeSync returns an authenticated session.
5. Home Assistant stores and reuses that session across restarts.
6. When VeSync later requires authentication again, Home Assistant opens the
   same MFA reauthentication flow.

No account-security downgrade is part of that design.

## What we know about the VeSync login protocol

The current `pyvesync` login is a two-stage exchange:

1. `POST /globalPlatform/api/accountAuth/v1/authByPWDOrOTM`
2. `POST /user/api/accountManage/v1/loginByAuthorizeCode4Vesync`

For an ordinary login, the first response contains an `authorizeCode`, which is
then exchanged for the cloud token in step 2.

The first response schema also contains `bizToken`, `mfaMethodList` and
`verifyEmail`. Those fields are present in current open-source VeSync clients and
in `pyvesync`'s own test fixtures, but `pyvesync` 3.4.2 models only the account ID
and authorization code. When VeSync requires 2FA, the library raises a login
error before Home Assistant can use the additional challenge information.

Version 0.2.0 reads that first response directly and extracts only the information
needed to classify the challenge. The challenge token itself remains private in
memory; the UI exposes only a sanitized summary such as:

```text
server_code=-12345; methods=TOTP,EMAIL; biz_token=yes; verify_email=yes; result_keys=...
```

That summary is intentionally designed to be safe for a public GitHub issue. It
does not contain the password, account ID, email address, authorization code,
cloud token or MFA challenge token.

## First field test

Do not remove your existing VeSync integration entry.

1. Add this repository to HACS as a custom **Integration** repository:
   `https://github.com/ArrowSK/ha-vesync-2fa`
2. Install **VeSync 2FA**.
3. Restart Home Assistant.
4. Open the existing VeSync integration and start reauthentication if Home
   Assistant requests it. If the existing entry is already in a failed state,
   use its **Reconfigure/Reauthenticate** action.
5. Enter the same VeSync email and password while leaving 2FA enabled.
6. When **VeSync two-factor challenge detected** appears, copy only the line
   labelled **Safe metadata** and post it in repository issue #1.

Do not post a screenshot if it contains your email address elsewhere on the
page. The safe metadata line is sufficient for the first test.

This test does not ask for the one-time code and cannot consume or invalidate a
code. It makes one normal first-stage login request and stops when VeSync returns
the MFA branch.

## Preserving existing entities

The custom integration deliberately remains `vesync` rather than using a new
Home Assistant domain. It also continues to use Home Assistant Core's VeSync
entity platforms directly.

That matters because Home Assistant's existing VeSync registry identity is based
on the VeSync device identifiers returned by the account. Replacing the domain or
rewriting the entity implementations would create needless migration risk.

For an existing setup:

- leave the current VeSync config entry in place;
- install this repository over the built-in integration;
- restart Home Assistant;
- reauthenticate the existing entry when needed;
- confirm the existing entity IDs before changing dashboards, automations or
  dependent integrations.

If an entity unexpectedly appears with an `_2` suffix, stop there and open an
issue. Do not "fix" dashboards around the duplicate. The registry mapping should
be corrected instead.

## Authentication and session behaviour

A completed VeSync session contains a cloud token, account ID, country code and
region. The integration stores those values in the existing Home Assistant config
entry and restores them on restart.

This is intentional: a valid session should not trigger MFA again merely because
Home Assistant restarted.

If VeSync later rejects the token, `pyvesync` may first attempt its own
password-based reauthentication. The custom coordinator watches the resulting
authentication state. When the manager becomes unauthenticated, Home Assistant is
told that the config entry needs reauthentication rather than leaving the VeSync
entities silently stale.

Once the second-factor request is verified and implemented, that reauthentication
flow will lead to the same OTP step as initial setup.

## Security model

Authentication code has stricter rules than the rest of the integration:

- passwords are never logged by this integration;
- VeSync cloud tokens are never logged;
- `bizToken`/MFA challenge tokens are never logged and are not written to the
  config entry;
- authorization codes are never logged;
- account IDs and email addresses are not included in public-safe MFA metadata;
- the authentication module contains no debug logger by design;
- an unknown MFA protocol stops the flow instead of trying speculative endpoints.

The normal authenticated VeSync session is stored in Home Assistant's config
entry, alongside the credentials Home Assistant already keeps for this
integration. Treat `.storage/core.config_entries` as sensitive and never post it
publicly.

There is no relay service, external developer server or telemetry backend in this
project. Home Assistant talks directly to VeSync through its local HTTP session
and `pyvesync`.

## Compatibility

Version 0.2.0 is intentionally pinned to:

- Home Assistant Core 2026.8.x, validated against 2026.8.0;
- `pyvesync` 3.4.2;
- Python/runtime versions supported by that Home Assistant release.

The pin is deliberate. The integration currently reuses `pyvesync`'s private
second-stage authorization-code exchange so that cross-region login behaviour is
not duplicated. CI imports the integration against the exact pinned runtime to
catch an upstream signature change before release.

## Automated checks

Every change on `main` runs:

- repository-specific structural validation;
- Python compilation;
- Home Assistant Hassfest;
- HACS validation;
- a runtime smoke test with Home Assistant 2026.8.0 and `pyvesync` 3.4.2.

The smoke test verifies:

- every custom integration module imports;
- a VeSync authenticated session survives a save/restore round trip;
- an ordinary first-stage auth response produces an authorization code;
- an MFA response produces a structured MFA challenge;
- challenge metadata is sanitized and does not expose account IDs, email
  addresses or challenge tokens;
- MFA metadata takes precedence over an authorization code if both are ever
  returned together.

CI cannot manufacture a real MFA challenge for a private VeSync account. That is
why the first field test above is still required.

## HACS installation

This project overrides a Home Assistant Core integration, so it is installed as a
HACS custom repository rather than pretending to be a separate VeSync
integration.

In HACS:

1. Open **Custom repositories**.
2. Add `https://github.com/ArrowSK/ha-vesync-2fa`.
3. Select **Integration**.
4. Install **VeSync 2FA**.
5. Restart Home Assistant.

Do not remove the built-in VeSync config entry first.

## Troubleshooting

### The MFA challenge screen appears

That is the expected result for 0.2.0 on a 2FA-enabled account. Copy the safe
metadata line to issue #1. Do not post the full Home Assistant config entry or raw
VeSync HTTP response.

### The login form says invalid authentication

First verify the credentials in the official VeSync app. If they are correct,
open an issue with the Home Assistant version and the exact sanitized error. Do
not enable pyvesync raw request/response logging with a real account unless you
intend to inspect and redact it locally before sharing anything.

### VeSync works after restart but later becomes unavailable

A stale/expired cloud token should now cause Home Assistant to request
reauthentication. That is expected. The final MFA implementation will complete
that flow interactively rather than relying on `pyvesync`'s password-only retry.

### Entities appeared with `_2`

Do not rename or rebuild your automations. Open an issue and include only the
entity IDs, device model and Home Assistant version. Never include device CIDs,
MAC addresses or raw registry/config-entry files.

## Reporting bugs

Useful information:

- Home Assistant Core version;
- this integration version;
- VeSync device model;
- whether the problem occurs during initial setup, MFA detection,
  reauthentication or normal polling;
- sanitized traceback if one exists;
- the **Safe metadata** line if the MFA challenge screen is involved.

Do not post passwords, one-time codes, email addresses, VeSync tokens, account
IDs, `bizToken` values, authorization codes, device CIDs, MAC addresses or
`.storage/core.config_entries`.

## Upstream work and attribution

This project builds on the VeSync integration in Home Assistant Core and on
`pyvesync`. Native 2FA support is also tracked upstream in `pyvesync` issue #367
and Home Assistant Core issue #153551.

The entity/platform behaviour in this repository is intentionally delegated to
Home Assistant Core rather than copied and forked. That keeps the override small
and makes later upstreaming of the authentication work more realistic.

Home Assistant Core is licensed under Apache License 2.0. `pyvesync` is an
independent MIT-licensed project and is installed as a dependency rather than
bundled here.

VeSync, Etekcity and Levoit names belong to their respective owners. This project
is not affiliated with or endorsed by VeSync, Etekcity, Levoit, Home Assistant or
the `pyvesync` maintainers.

## Licence

Apache License 2.0. See `LICENSE` and `NOTICE`.
