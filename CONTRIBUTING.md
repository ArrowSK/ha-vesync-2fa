# Contributing

Keep changes narrow. The current repository is a diagnostic probe for VeSync
2FA, not a replacement VeSync integration.

The working Home Assistant Core `vesync` integration must remain completely
separate from this code while the MFA protocol is still being discovered.

For a pull request:

1. Explain the failure or protocol question being addressed.
2. Link the relevant Home Assistant or `pyvesync` upstream issue when one exists.
3. Do not add `custom_components/vesync` to this repository.
4. Do not create VeSync entities, devices or persistent config entries in the
   probe.
5. Do not include captured credentials, email addresses, tokens, account IDs,
   authorization codes, `bizToken` values, device CIDs, MAC addresses or raw
   VeSync responses.
6. Do not add a guessed second-factor endpoint. MFA submission code needs
   reproducible, sanitized evidence of the real VeSync request first.
7. Run `python scripts/validate.py` and
   `python -m compileall -q custom_components scripts`.
8. Keep documentation explicit about what has and has not been verified against
   a real VeSync account.

Once the actual MFA verification request is known, implement and test it in an
isolated authentication layer first. Moving that work into a same-domain VeSync
replacement requires separate regression tests for existing Home Assistant config
entries, device identifiers and entity IDs.
