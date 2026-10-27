#!/usr/bin/env python3
"""Derive a network-specific PattNG link from a working CDN/Worker VLESS link.

Read credentials from a file, not command-line arguments. Output is private.
The existing domain must already route to the origin or Worker.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import tempfile

MODULE = Path(__file__).resolve().parents[1] / 'server-bundle/opt/proxy-resilience/cloudflare_profiles.py'
if not MODULE.exists():
    MODULE = Path(__file__).resolve().parents[1] / 'opt/proxy-resilience/cloudflare_profiles.py'
spec = importlib.util.spec_from_file_location('cloudflare_profiles', MODULE)
profiles = importlib.util.module_from_spec(spec)
spec.loader.exec_module(profiles)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True, help='file containing one working VLESS link')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--method', choices=profiles.METHODS, required=True)
    parser.add_argument('--address', required=True, help='edge IP tested on the actual network')
    parser.add_argument('--server-name', help='origin/Worker hostname, preserved separately from edge IP')
    parser.add_argument('--ech-config', help='explicit ECH config/resolver expression; only for --method ech')
    args = parser.parse_args()
    os.umask(0o077)
    try:
        link = profiles.recipe(args.input.read_text(), args.method, args.address,
                               server_name=args.server_name, ech_config=args.ech_config)
        fd, pending = tempfile.mkstemp(prefix='.cf-profile-', dir=args.output.parent)
        try:
            with os.fdopen(fd, 'w') as handle:
                handle.write(link + '\n')
            os.replace(pending, args.output)
        finally:
            Path(pending).unlink(missing_ok=True)
    except (OSError, ValueError) as exc:
        # Do not print credential-bearing input or exception text from URL parsers.
        parser.exit(1, f'Cannot build profile ({type(exc).__name__}); check input, recipe and edge IP\n')
    print('Saved private profile to ' + str(args.output))


if __name__ == '__main__':
    main()
