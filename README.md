# VeSync 2FA Session Bridge for Home Assistant

This is a small Home Assistant override for the built-in VeSync integration.
It exists for one specific problem: VeSync accounts with account-level two-factor
authentication enabled cannot currently complete a fresh password login through
`pyvesync`, which is the library used by Home Assistant.

The integration does **not** pretend that the missing OTP API has been solved.
Instead, it keeps the authenticated VeSync session obtained from one successful
login and restores that same session after Home Assistant restarts. That lets you
turn VeSync 2FA back on and leave it on during normal Home Assistant use.

## What this changes

Home Assistant Core 2026.8.0 logs into VeSync again when the integration starts.
That works for ordinary accounts, but VeSync rejects the password login when 2FA
is enabled with the message `user login requires 2fa authentication`.

This override changes only the authentication/session layer:

- after a successful VeSync login, the returned session token, account ID,
  country code and VeSync region are saved in the existing Home Assistant config
  entry;
- on the next Home Assistant restart, those values are restored into `pyvesync`
  instead of forcing another password login;
- the normal Home Assistant Core VeSync entity platforms are used unchanged;
- if VeSync invalidates the saved session, the next integration setup or reload
  cannot reuse it and Home Assistant will require authentication again. Normal
  device polling still follows `pyvesync`'s own error handling, so a revoked
  token may first show up as stale or failed device updates rather than an
  immediate reauthentication prompt.

Everything that creates fans, sensors, switches, numbers, selects, lights,
humidifiers and update entities is still Home Assistant Core's VeSync code.

## Important limitation: this is not native OTP support

`pyvesync` 3.4.2 does not expose VeSync's interactive 2FA/OTP challenge. There is
an open upstream request for it: [webdjoe/pyvesync#367](https://github.com/webdjoe/pyvesync/issues/367).
Home Assistant has the corresponding feature request and issue history as well.

Because that API is not documented and no reliable open-source implementation of
the challenge is available, this repository does not guess at private endpoints
or ask you to paste a one-time code into a flow that cannot actually verify it.

For the first login, or after VeSync revokes the saved session, the current
bootstrap procedure is:

1. Temporarily disable two-factor authentication in the VeSync app.
2. Complete the VeSync login/reauthentication in Home Assistant once.
3. Confirm that your devices and entities are back.
4. Re-enable two-factor authentication in the VeSync app immediately.
5. If VeSync offers to trust the newly logged-in client/device, accept that for
   the Home Assistant session.

After step 2, this integration stores the authenticated VeSync session and reuses
it on subsequent Home Assistant restarts. You should not need to repeat the
bootstrap unless VeSync expires or revokes that session.

If upstream `pyvesync` gains a proper 2FA challenge API, the intention is to
replace this bootstrap with a normal OTP step rather than maintain a competing
VeSync protocol implementation here.

## Preserving an existing Home Assistant setup

If you already use the built-in VeSync integration, **do not delete it before
installing this repository**.

This custom integration deliberately keeps the domain `vesync`, the existing
config-entry format, the built-in entity implementations, the built-in unique-ID
logic and the built-in device identifiers. Home Assistant therefore continues to
use the existing config entry and entity registry records.

That is especially important if dashboards, automations, scripts, Powercalc or
other integrations refer to your current entity IDs.

Installing the override is intended to be an in-place change:

1. Install the custom repository.
2. Restart Home Assistant.
3. Reauthenticate the existing VeSync entry only if Home Assistant asks you to.
4. Verify the existing entity IDs before changing any automations or dashboards.

Removing the VeSync config entry and adding it again is unnecessary and defeats
part of the entity-preservation design.

## Installation with HACS

This repository is meant to be installed as a **custom repository**. HACS does
not accept integrations that override a Home Assistant Core integration into its
default catalogue, so you need to add this repository manually.

1. Open HACS in Home Assistant.
2. Open the three-dot menu and choose **Custom repositories**.
3. Add:
   `https://github.com/ArrowSK/ha-vesync-2fa`
4. Select **Integration** as the category.
5. Install **VeSync 2FA Session Bridge**.
6. Restart Home Assistant.

After restart, the VeSync integration card should show that a custom component is
overriding the built-in integration.

### Existing VeSync entry

Leave the existing VeSync entry in place. If it loads successfully, check your
entities and you are done.

If Home Assistant asks you to reauthenticate and VeSync reports that 2FA is
required, use the one-time bootstrap procedure described above. Once the login
succeeds, turn 2FA back on before returning to normal use.

### New VeSync entry

For a new setup, install this custom integration first and restart Home Assistant.
Then add VeSync from **Settings → Devices & services**. If the account already has
2FA enabled, use the same one-time bootstrap procedure for the initial login.

## Security notes

The saved VeSync session token is a credential. Treat it like a password.

Home Assistant already stores the VeSync username and password in the config
entry. This integration adds the VeSync session token and its associated account
metadata to that same entry. Do not publish or upload your Home Assistant
`.storage/core.config_entries` file.

The integration never writes the session token to its own logs. The diagnostic
handler remains Home Assistant Core's VeSync diagnostic implementation and does
not export config-entry credentials, but you should still review any diagnostic
bundle before posting it publicly.

There is no external relay, developer server or telemetry service in this
project. VeSync traffic goes from Home Assistant to VeSync through `pyvesync`, as
it does with the built-in integration.

## Compatibility

The first release is intentionally narrow:

- Home Assistant: **2026.8.0 or newer within the 2026.8 line**
- `pyvesync`: **3.4.2**
- integration domain: **`vesync`**

The platform modules are thin adapters to the VeSync implementation shipped with
Home Assistant Core. That keeps device and entity behaviour aligned with your
installed Home Assistant version rather than copying thousands of lines that
would immediately start drifting upstream.

A future Home Assistant release can still change internal VeSync interfaces. The
repository therefore runs HACS validation, Hassfest, structural checks and a
runtime import/session smoke test against Home Assistant 2026.8.0 on every
change. Updates should still be tested before installing them on a production
Home Assistant instance.

## Why the repository uses the same `vesync` domain

Home Assistant supports a custom integration overriding a built-in integration
when both use the same domain. That is exactly what is needed here: using a new
domain would create a second integration and would make preserving the existing
VeSync config entry and entity registry much harder.

The trade-off is that the custom integration becomes responsible for staying
compatible with Home Assistant's built-in VeSync implementation. This repository
tries to keep that surface small: authentication is local code; entity platforms
are delegated directly to Home Assistant Core.

## Troubleshooting

### `VeSync requires 2FA for this sign-in`

This means there is no usable saved session yet, or the previous one was revoked.
Temporarily disable VeSync 2FA, submit the Home Assistant login once, confirm the
integration loads, and re-enable 2FA immediately.

### The integration works until a VeSync session is revoked

That is the main remaining upstream limitation. Repeat the bootstrap. A native OTP
flow cannot be added safely until the VeSync challenge protocol is known or
`pyvesync` exposes it. If controls stop updating before Home Assistant asks for
reauthentication, reload the VeSync integration; that forces setup to validate
the saved session again.

### Entities appeared with `_2`

Stop before editing dashboards or automations. Check whether the original VeSync
config entry was removed and re-added. This override is designed to retain the
existing entry. Please open an issue with sanitized entity-registry information;
do not include passwords, tokens, account IDs, MAC addresses or raw config-entry
storage.

### Home Assistant says the custom component is incompatible after an upgrade

Do not work around it by deleting the VeSync integration. Open an issue with the
Home Assistant version, this integration version and the relevant traceback. The
right fix is to update the override to the new Core VeSync interface while
preserving the registry identifiers.

## Reporting bugs

Please include:

- Home Assistant Core version;
- this integration version;
- device model;
- whether the problem happens during initial login, restart, reauthentication or
  normal polling;
- a sanitized traceback if there is one.

Please remove email addresses, passwords, VeSync tokens, account IDs, MAC
addresses, device CIDs and anything from `.storage/core.config_entries` before
posting.

## Development and validation

Run the local structural checks with:

```bash
python scripts/validate.py
python -m compileall -q custom_components scripts
```

The GitHub Actions suite also runs:

- repository-specific structural validation and Python compilation;
- Home Assistant Hassfest;
- HACS repository validation;
- a runtime smoke test that installs Home Assistant 2026.8.0 and `pyvesync`
  3.4.2, imports every custom-component module and verifies the saved-session
  round trip.

The repository intentionally contains one Home Assistant integration only:
`custom_components/vesync`.

## Upstream and attribution

This project is an override of the VeSync integration shipped in
[Home Assistant Core](https://github.com/home-assistant/core/tree/dev/homeassistant/components/vesync)
and depends on [pyvesync](https://github.com/webdjoe/pyvesync).

Home Assistant Core is licensed under Apache License 2.0. `pyvesync` is an
independent project distributed under its own MIT licence. This repository does
not bundle `pyvesync`; Home Assistant installs the declared package dependency.

VeSync, Etekcity and Levoit names belong to their respective owners. This project
is not affiliated with or endorsed by VeSync, Etekcity, Levoit, Home Assistant or
the `pyvesync` maintainers.

## Licence

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
