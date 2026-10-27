#!/usr/bin/env python3
"""Receive a pinned recovery kit; never execute or install retrieved files."""
import argparse
import json
from pathlib import Path
import sys

source = Path(__file__).resolve().parents[1] / 'connectivity'
sys.path.insert(0, str(source if (source / 'recovery_bundle.py').is_file()
                       else Path('/opt/connectivity-tools/rescue')))
from recovery_bundle import MAX_MANIFEST, RecoveryError, document, recover, validate_sources


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    origin = parser.add_mutually_exclusive_group(required=True)
    origin.add_argument('--sources', type=Path, help='private configured mirror list')
    origin.add_argument('--offline-dir', type=Path, help='local kit, without network access')
    parser.add_argument('--manifest-sha256', required=True, help='trust anchor received independently')
    parser.add_argument('--output', type=Path, required=True, help='new directory; existing kits are preserved')
    parser.add_argument('--timeout', type=int, default=15, help='deadline per artifact/source, 1..55 seconds')
    parser.add_argument('--total-timeout', type=int, default=180, help='total recovery budget, 1..1800 seconds')
    args = parser.parse_args(argv)
    try:
        if args.sources:
            if args.sources.stat().st_size > MAX_MANIFEST:
                raise RecoveryError('source configuration exceeds size limit')
            sources = validate_sources(document(args.sources.read_bytes()))
        else:
            sources = [{'id': 'offline', 'type': 'directory', 'directory': str(args.offline_dir.resolve())}]
        result = recover(sources, args.manifest_sha256, args.output, timeout=args.timeout,
                         total_timeout=args.total_timeout)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        # OS and parser exceptions may contain private paths, URLs, or tokens.
        reason = str(exc) if isinstance(exc, RecoveryError) else 'local configuration or filesystem failure'
        parser.exit(1, 'Recovery failed: ' + reason + '\n')
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
