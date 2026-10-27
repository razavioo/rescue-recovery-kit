#!/usr/bin/env python3
"""Prepare a pinned Aether binary for offline installation; never run a download.

The digest is checked against the reviewed repository manifest, not a checksum
fetched alongside an arbitrary binary. Only the regular `aether` file is copied
from the archive; no archive paths, links or scripts are extracted.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def prepare(directory, machine, archive=None):
    release = json.loads((ROOT / 'connectivity/aether-release.json').read_text())
    asset = release['assets'][machine]
    directory.mkdir(parents=True, exist_ok=True)
    offline = archive is not None
    archive = Path(archive) if offline else directory / asset['name']
    if not archive.exists():
        if offline:
            raise ValueError('specified offline archive is missing')
        url = f'https://github.com/{release["repository"]}/releases/download/{release["version"]}/{asset["name"]}'
        fd, pending = tempfile.mkstemp(prefix='.download-', dir=directory)
        try:
            with os.fdopen(fd, 'wb') as handle, urllib.request.urlopen(url, timeout=45) as response:
                total = 0
                while chunk := response.read(1024 * 1024):
                    total += len(chunk)
                    if total > 128 * 1024 * 1024:
                        raise ValueError('release archive exceeds size limit')
                    handle.write(chunk)
            if hashlib.sha256(Path(pending).read_bytes()).hexdigest() != asset['sha256']:
                raise ValueError('release archive digest mismatch')
            os.replace(pending, archive)
        finally:
            Path(pending).unlink(missing_ok=True)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != asset['sha256']:
        raise ValueError('release archive digest mismatch')
    with tarfile.open(archive, 'r:gz') as bundle:
        members = [m for m in bundle.getmembers() if Path(m.name).name == 'aether']
        if len(members) != 1 or not members[0].isfile() or members[0].size > 128 * 1024 * 1024:
            raise ValueError('archive must contain one regular aether binary')
        data = bundle.extractfile(members[0]).read()
    target = directory / 'aether'
    fd, pending = tempfile.mkstemp(prefix='.binary-', dir=directory)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)
        os.chmod(pending, 0o755)
        os.replace(pending, target)
    finally:
        Path(pending).unlink(missing_ok=True)
    digest = hashlib.sha256(data).hexdigest()
    (directory / 'aether.sha256').write_text(digest + '  aether\n')
    (directory / 'manifest.json').write_text(json.dumps({**release, 'machine': machine,
        'archive': asset, 'binary_sha256': digest}, indent=2) + '\n')
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=ROOT / 'offline-toolkit/aether-v2.4.0')
    parser.add_argument('--machine', choices=('x86_64', 'aarch64', 'armv7l'), default=platform.machine())
    parser.add_argument('--archive', type=Path, help='use this local archive without downloading')
    args = parser.parse_args()
    try:
        binary = prepare(args.directory, args.machine, args.archive)
    except (OSError, ValueError, KeyError, tarfile.TarError) as exc:
        parser.exit(1, f'Preparation failed: {type(exc).__name__}: {exc}\n')
    print('Verified offline binary: ' + str(binary))


if __name__ == '__main__':
    main()
