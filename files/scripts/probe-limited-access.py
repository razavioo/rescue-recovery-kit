#!/usr/bin/env python3
"""Run selective Google/Cloudflare/GitHub HTTPS evidence without changing routes."""
from pathlib import Path
import sys

source = Path(__file__).resolve().parents[1] / 'connectivity'
sys.path.insert(0, str(source if (source / 'limited_access_probe.py').is_file()
                       else Path('/opt/connectivity-tools/rescue')))
from limited_access_probe import main


if __name__ == '__main__':
    raise SystemExit(main())
