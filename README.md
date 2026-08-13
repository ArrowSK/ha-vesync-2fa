# VeSync 2FA Probe for Home Assistant

This repository is a small Home Assistant diagnostic integration for investigating
VeSync's account-level two-factor authentication flow.

It is deliberately **not** a replacement for Home Assistant's built-in VeSync
integration.

The probe uses its own Home Assistant domain, `vesync_2fa_probe`, so the normal
`vesync` integration can stay installed and keep its existing config entry,
devices, entities, dashboards and automations untouched.

## Current status

Version 0.4.0 is a protocol-discovery build.

We now know the real first-stage MFA response from a live VeSync account, but the
private second-factor request is still undocumented. Rather than waiting forever
for somebody else to publish it, the project now tests **small, explicit
hypotheses one at a time**.

That does not mean spraying random requests at the account. Each hypothesis is
bounded, documented and chosen to answer one question. If it fails, its sanitized
server response becomes evidence for the next hypothesis.

Version 0.4.0 tests only hypothesis **C1**:

- start with the verified password-auth request;
- keep the returned MFA `bizToken` in memory only;
- reuse the same known `authByPWDOrOTM` endpoint;
- add the server-advertised `otp` method as `mfaMethod=otp`;
- deliberately send **no OTP value**;
- record only sanitized response metadata.

The purpose of C1 is simply to find out whether the known password-auth endpoint
also acts as the MFA continuation endpoint, and whether the server tells us what
field is missing. If not, the next build will try the next narrow hypothesis.

The probe still does **not**:

- replace Home Assistant's built-in VeSync integration;
- create VeSync devices or entities;
- modify the existing VeSync config entry;
- exchange an authorization code for a cloud session;
- submit a TOTP, email code, backup code or guessed code;
- save the supplied VeSync email or password in a Home Assistant config entry.

Once the MFA verification request is working end to end, the project can move
back toward the original goal: a proper VeSync integration that handles 2FA and
reauthentication without changing existing entity identities.

## Why the probe uses a separate domain

Versions 0.1.0 and 0.2.0 used the same `vesync` domain as Home Assistant Core. The
reasoning was straightforward: a same-domain override looked like the safest way
to preserve the existing VeSync config entry and entity registry.

In a live Home Assistant installation that assumption did not hold safely enough.
Installing the custom component caused the existing built-in VeSync connection to
disappear from the UI until the custom component was removed and Home Assistant
was restarted. The original connection returned afterwards, confirming that the
stored Core config entry had not been deleted, but the custom component had still
masked the working integration while it was present.

That is not acceptable for protocol discovery.

All experimental authentication work therefore stays under `vesync_2fa_probe`.
The working Core integration remains the source of truth until we have a complete,
verified MFA implementation and explicit migration tests.

## What the first request sends

VeSync's current first authentication request is:

```text
POST /globalPlatform/api/accountAuth/v1/authByPWDOrOTM
```

The request body is built with `pyvesync` 3.4.2's `RequestGetTokenModel`, including
its existing password hashing and client metadata. The probe lets you choose the
VeSync API region and account country code because VeSync has separate EU and
non-EU service endpoints.

For an ordinary login, the response can contain an `authorizeCode`. The probe
records only whether such a field was present; it deliberately does not exchange
the value.

For a 2FA-protected login, the response can include challenge-related fields such
as `mfaMethodList`, `bizToken` and `verifyEmail`. The public-safe result records
only:

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
left enabled. VeSync returned the following sanitized shape:

```text
outcome=mfa_required; server_code=-11257129; methods=email,otp,backupCode; biz_token=yes; verify_email=no; authorize_code=no; result_keys=accountID,accountLockTimeInSec,authorizeCode,avatarIcon,bizToken,emailUpdateToSame,mailConfirmation,mfaMethodList,nickName,registerAppVersion,registerSourceDetail,registerTime,userType,verifyEmail
```

This removes several assumptions from the investigation. The live account
advertises three second-factor choices: `email`, `otp` and `backupCode`. A
`bizToken` challenge value is returned, while `authorizeCode` is not. VeSync is
therefore gating the normal authorization-code exchange behind a separate MFA
step.

`verify_email=no` means the `verifyEmail` field was empty in that response. It
does not mean email MFA is unavailable because `email` is explicitly present in
`mfaMethodList`.

## Hypothesis C1 in 0.4.0

C1 makes one extra request only when all of the following are true:

- the first request returned `mfa_required`;
- a non-empty `bizToken` was present;
- `otp` was one of the advertised MFA methods.

The second request goes to the **same verified endpoint** and reuses the same
client metadata. The password hash is removed. The request adds the challenge
`bizToken` and `mfaMethod=otp`, but it contains no OTP/code field.

The response is reduced to a second safe line such as:

```text
continuation=c1_same_auth_mfaMethod; http=200; server_code=-12345; message_class=code_required; authorize_code=no; result_keys=...
```

The raw server message is not shown. It is classified into broad categories such
as `code_required`, `illegal_argument`, `mfa`, `rate_limited` or `account_locked`.
That gives us useful protocol evidence without exposing account data.

If C1 produces a useful "code required"-type response, the next step will be a
single fresh OTP submission using that exact route. If C1 is rejected, the next
build will test another specific route/payload hypothesis instead. We will keep
moving through the possibilities until the real exchange is identified, but we
will not brute-force OTP values or submit the same code repeatedly.

## Installation

If you previously installed version 0.1.0 or 0.2.0, remove that old HACS package
first and restart Home Assistant before installing the current probe. Those older
builds used the `vesync` domain and must not be left in `custom_components/vesync`.

Then:

1. In HACS, open **Custom repositories**.
2. Add `https://github.com/ArrowSK/ha-vesync-2fa` as an **Integration** repository.
3. Install or update **VeSync 2FA Probe**.
4. Restart Home Assistant.
5. Leave the existing built-in **VeSync** integration alone.
6. Go to **Settings → Devices & services → Add integration** and add
   **VeSync 2FA Probe**.

The probe flow always finishes without creating a persistent Home Assistant
config entry.

## Running the 0.4.0 field test

Keep VeSync 2FA enabled.

Run **VeSync 2FA Probe** once and enter the same account details as before. The
result should now contain the original `outcome=...` line and, for an OTP-capable
challenge, a second `continuation=c1_...` line.

Copy only those safe metadata lines into issue #1 or the current troubleshooting
conversation.

Do not post the raw VeSync response. Do not post screenshots containing the
account email address. Do not post passwords, one-time codes, account IDs,
authorization codes, cloud tokens, `bizToken` values, device CIDs or MAC
addresses.

## What happens to the normal VeSync integration

Nothing.

Version 0.4.0 has a different domain and does not import or override Home
Assistant Core's `vesync` component. It has no VeSync entity platforms and does
not create devices.

The runtime smoke test imports Home Assistant Core's `vesync` integration and the
custom `vesync_2fa_probe` integration in the same Python environment and verifies
that their domains are different.

## Security model

The probe does not log raw authentication requests or responses. The password is
used only to build the verified first-stage request. The email and password are
not saved because the config flow never creates an entry.

For an MFA response, version 0.4.0 temporarily keeps the `bizToken`, account ID and
first-request client metadata in the running config-flow object. The password hash
is removed before the continuation hypothesis is built. These values exist only
in memory for the duration of that one flow and are never displayed, logged or
written to Home Assistant storage.

C1 sends no actual second-factor value. There is no OTP guessing, no backup-code
probing and no retry loop. Later hypotheses will continue to use the smallest
possible request needed to learn the next piece of the protocol.

There is no relay server, telemetry service or project backend. Home Assistant
talks directly to VeSync.

## Compatibility

Version 0.4.0 is validated against:

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
classification, the confirmed live challenge shape and redaction. The 0.4
repository check also verifies that the diagnostic package still does not create
a persistent config entry and that C1 removes the password hash before building
the continuation request.

## Roadmap

The work is intentionally incremental:

1. **Complete:** capture the real first-stage MFA challenge shape.
2. **Current:** test C1 — same known auth endpoint + `bizToken` + `mfaMethod=otp`,
   with no OTP value.
3. If C1 fails, test the next narrow continuation-route/payload hypothesis.
4. Once the server identifies a plausible route, submit one fresh user-provided
   second factor through that route and inspect only sanitized output.
5. Exchange the resulting `authorizeCode` through the already-known VeSync token
   endpoint.
6. Prove session persistence and later reauthentication while 2FA remains enabled.
7. Add regression tests for existing VeSync config entries and entity IDs.
8. Only then evaluate replacing or upstreaming Home Assistant's built-in VeSync
   authentication flow.

The final implementation should require the second factor only when VeSync
actually asks for it, not every time Home Assistant restarts.

## Reporting results and bugs

Issue #1 tracks the protocol investigation and contains the first confirmed live
challenge. For bugs, include the Home Assistant version, probe version, selected
API region, account country code and a sanitized traceback if one exists. Do not
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
