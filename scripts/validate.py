#!/usr/bin/env python3
"""Compatibility entry point for repository validation.

The active structural checks live in ``validate_v040.py``. Keeping this small
wrapper avoids leaving an obsolete 0.3-specific validator in the repository for
people who run ``python scripts/validate.py`` manually.
"""

from validate_v040 import main


if __name__ == "__main__":
    main()
