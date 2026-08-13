# Contributing

Keep changes narrow. This repository exists to patch VeSync authentication, not
to become a second independent VeSync integration.

Before changing entity or device code, check whether the change belongs in Home
Assistant Core or `pyvesync` instead. Preserving existing Home Assistant entity
and device identifiers is a hard compatibility requirement here.

For a pull request:

1. Explain the failure being fixed.
2. Link the relevant Home Assistant or `pyvesync` upstream issue when one exists.
3. Do not include captured credentials, tokens, account IDs, device CIDs or other
   private VeSync data.
4. Run `python scripts/validate.py` and `python -m compileall -q custom_components scripts`.
5. Keep the documentation honest about behaviour that has not been verified
   against a real VeSync account.

Native 2FA support is welcome when the protocol is known, but it needs either an
upstream `pyvesync` API or reproducible, sanitized evidence of the VeSync
challenge flow. Do not merge guessed endpoints or hard-coded secrets.
