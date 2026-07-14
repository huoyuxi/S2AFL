#!/usr/bin/env python3
"""Compatibility entrypoint that forwards to ``S2AFL.cli.main``."""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from S2AFL.cli.main import main


if __name__ == "__main__":
    main()
