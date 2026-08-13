# VeSync 2FA Probe for Home Assistant

This repository is a small Home Assistant diagnostic integration for investigating
VeSync's account-level two-factor authentication flow.

It is deliberately **not** a replacement for Home Assistant's built-in VeSync
integration.

The probe uses its own Home Assistant domain, `vesync_2fa_probe`, so the normal
`vesync` integration can stay installed and keep its existing config entry,
devices, entities, dashboards and automations untouched.

## Current status

Version 0.3.0 is a protocol-discovery build.

It solves one specific problem: current `pyvesync` can tell us that VeSync wants
2FA, but it does not expose the complete second-factor exchange needed to finish a
native Home Assistant login flow.

The probe therefore sends exactly one known VeSync first-stage authentication
request and reduces the response to a small sanitized summary. It does **not**:

- replace Home Assistant's built-in VeSync integration;
- create VeSync devices or entities;
- modify the existing VeSync config entry;
- exchange an authorization code for a cloud session;
- submit a TOTP, email code or other second factor;
- save the supplied VeSync email or password in a Home Assistant config entry.

Once the real MFA verification request is known and tested, the project can move
back toward the original goal: a proper VeSync integration that handles 2FA and
reauthentication without changing existing entity identities.

## Why 0.3.0 uses a separate domain

Versions 0.1.0 and 0.2.0 used the same `vesync` domain as Home Assistant Core. The
reasoning was straightforward: a same-domain override looked like the safest way
to preserve the existing VeSync config entry and entity registry.

In a live Home Assistant installation that assumption did not hold safely enough.
Installing the custom component caused the existing built-in VeSync connection to
disappear from the UI until the custom component was removed and Home Assistant
was restarted. The original connection returned afterwards, confirming that the
stored Core config entry had not been deleted, but the custom component had still
masked the working integration while it was present.

That is not acceptable for a diagnostic build.

Version 0.3.0 therefore moves all experimental authentication work to
`vesync_2fa_probe`. The working Core integration remains the source of truth until
we have a complete, verified MFA implementation and explicit migration tests.

## What the probe sends

VeSync's current first authentication request is:

```text
POST /globalPlatform/api/accountAuth/v1/authByPWDOrOTM
```

The request body is built with `pyvesync` 3.4.2's `RequestGetTokenModel`, including
its existing password hashing and client metadata. The probe lets you choose the
VeSync API region and account country code because VeSync has separate EU and
non-EU service endpoints.

The probe stops after the first response.

For an ordinary login, that response can contain an `authorizeCode`. The probe
records only whether such a field was present; it deliberately discards the value
and does not exchange it.

For a 2FA-protected login, the response can include challenge-related fields such
as `mfaMethodList`, `bizToken` and `verifyEmail`. The probe records only:

- the server status code;
- sanitized MFA method names;
- whether `bizToken`, `verifyEmail` and `authorizeCode` were present;
- the names of fields present in the response's `result` object.

A typical safe result looks like:

```text
outcome=mfa_required; server_code=-12345; methods=TOTP,EMAIL; biz_token=yes; verify_email=yes; authorize_code=no; result_keys=...
```

No password, email address, account ID, authorization code, cloud token or
`bizToken` value is included in that line.

## Confirmed live MFA challenge

The first isolated field test succeeded on 13 August 2026 with account-level 2FA
left enabled. VeSync returned:

```text
outcome=mfa_required; server_code=-11257129; methods=email,otp,backupCode; biz_token=yes; verify_email=no; authorize_code=no; result_keys=accountID,accountLockTimeInSec,authorizeCode,avatarIcon,bizToken,emailUpdateToSame,mailConfirmation,mfaMethodList,nickName,registerAppVersion,registerSourceDetail,registerTime,userType,verifyEmail
```

This is useful because it removes several assumptions from the investigation.
The live account advertises three second-factor choices: `email`, `otp` and
`backupCode`. A `bizToken` challenge value is returned, while `authorizeCode` is
not. In other words, VeSync is gating the normal authorization-code exchange
behind a separate MFA verification step.

`verify_email=no` in the safe line means the `verifyEmail` field was empty in this
response. It does **not** mean that email MFA is unavailable; `email` is explicitly
present in `mfaMethodList`.

The exact endpoint and payload that consume the `bizToken` plus the selected
second factor are still unknown. The project will not guess them. The confirmed
challenge shape has been added to the runtime tests so later parser changes cannot
silently break the real response we observed.

## Installation

If you previously installed version 0.1.0 or 0.2.0, remove that HACS integration
first and restart Home Assistant before installing 0.3.0. The older builds used
the `vesync` domain and must not be left in `custom_components/vesync`.

Then:

1. In HACS, open **Custom repositories**.
2. Add `https://github.com/ArrowSK/ha-vesync-2fa` as an **Integration** repository.
3. Install **VeSync 2FA Probe**.
4. Restart Home Assistant.
5. Leave the existing built-in **VeSync** integration alone.
6. Go to **Settings → Devices & services → Add integration** and add
   **VeSync 2FA Probe**.

The probe flow always finishes without creating a persistent Home Assistant
config entry.

## Running the first field test

The first field test is now complete. Its sanitized result is documented above
and in issue #1. Repeating the same password-stage probe is not normally useful
unless we are comparing another account, region or future VeSync API change.

Keep VeSync 2FA enabled. Do not post the raw VeSync response. Do not post
screenshots containing the account email address. Do not post passwords, one-time
codes, account IDs, authorization codes, cloud tokens, `bizToken` values, device
CIDs or MAC addresses.

## What happens to the normal VeSync integration

Nothing.

Version 0.3.0 has a different domain and does not import or override Home
Assistant Core's `vesync` component. It has no VeSync entity platforms and does
not create devices.

This separation is now enforced by repository checks. CI fails if:

- `custom_components/vesync` exists in this repository;
- the diagnostic manifest uses the `vesync` domain;
- the probe starts importing Home Assistant Core's VeSync entity/platform code;
- the config flow starts creating persistent entries;
- the probe adds the authorization-code exchange endpoint;
- documentation reintroduces the old advice to disable 2FA.

The runtime smoke test also imports Home Assistant Core's `vesync` integration and
the custom `vesync_2fa_probe` integration in the same Python environment and
verifies that their domains are different.

## Security model

This code deals with authentication, so the rules are intentionally strict.

The probe does not log raw authentication requests or responses. The password is
used only to construct the one first-stage request. The email and password are not
saved because the config flow never creates an entry. Challenge tokens and
authorization codes are reduced to yes/no presence flags and then discarded.

The probe contains no second-factor submission endpoint. Until we have verified
the real VeSync MFA request from reproducible evidence, it will not send a TOTP or
email code anywhere.

There is no relay server, telemetry service or project backend. Home Assistant
talks directly to VeSync.

## Compatibility

Version 0.3.0 is validated against:

- Home Assistant Core 2026.8.0;
- `pyvesync` 3.4.2;
- the Python runtime supported by that Home Assistant release.

The dependency is pinned because the probe relies on the exact request model used
by that version of `pyvesync`.

## Automated checks

Every change on `main` runs:

- repository-specific structural validation;
- Python compilation;
- Home Assistant Hassfest;
- HACS validation;
- a runtime compatibility smoke test with Home Assistant 2026.8.0 and
  `pyvesync` 3.4.2.

The tests verify the isolation boundary, request-model behaviour, MFA response
classification, the confirmed live challenge shape and redaction. They do not
pretend to reproduce VeSync's private server-side MFA flow.

## Roadmap

The work is intentionally split into stages:

1. **Complete:** safely capture the real first-stage MFA challenge shape.
2. **In progress:** identify the actual second-factor request from reproducible
   evidence.
3. Implement that request in a testable authentication layer.
4. Prove token persistence and later reauthentication with 2FA still enabled.
5. Add regression tests for existing VeSync config entries and entity IDs.
6. Only then evaluate replacing or upstreaming the built-in VeSync authentication
   flow.

The final implementation should require the second factor when VeSync genuinely
asks for it, not every time Home Assistant restarts.

## Reporting results and bugs

Issue #1 tracks the protocol investigation and contains the first confirmed live
challenge. For bugs, include the Home Assistant version, probe version, selected
API region, account country code, and a sanitized traceback if one exists. Do not
include credentials or raw VeSync payloads.

## Upstream work and attribution

This project builds on `pyvesync` and is intended to help close the gap described
in upstream VeSync 2FA reports, including `pyvesync` issue #367 and Home Assistant
Core issue #153551.

Home Assistant Core is licensed under Apache License 2.0. `pyvesync` is an
independent MIT-licensed project and is installed as a dependency rather than
bundled here.

VeSync, Etekcity and Levoit names belong to their respective owners. This project
is not affiliated with or endorsed by VeSync, Etekcity, Levoit, Home Assistant or
the `pyvesync` maintainers.

## Licence

Apache License 2.0. See `LICENSE` and `NOTICE`.
