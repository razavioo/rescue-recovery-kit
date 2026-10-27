#!/usr/bin/env python3
"""Build a public, pinned recovery kit and static Google/Cloudflare mirrors.

Only the explicit public allowlist below is packaged. No live configuration,
credentials, local accounts, or private/offline-toolkit overlays are read.
An optional, explicitly supplied private JSON map can redact exact text before
hashing; that map is never bundled.
Publishing the generated mirrors remains an explicit operator action.
"""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'connectivity'))
from recovery_bundle import MAX_FILE, RecoveryError, commit_directory, document, safe_name, validate_manifest

MAX_REDACTION_MAP = 64 * 1024
MAX_REDACTION_TEXT = 4096

PUBLIC_FILES = (
    'connectivity/connectivityctl',
    'connectivity/aether_runner.py',
    'connectivity/transport_health.py',
    'connectivity/recovery_bundle.py',
    'connectivity/recovery-sources.example.json',
    'connectivity/limited_access_probe.py',
    'connectivity/google-relay-release.json',
    'connectivity/google-relay.example.json',
    'connectivity/aether-release.json',
    'connectivity/aether-profiles.example.json',
    'scripts/rescue-bootstrap.py',
    'scripts/probe-limited-access.py',
    'scripts/install-limited-access-tools.sh',
    'scripts/build-limited-access-kit.py',
    'scripts/prepare-google-relay.py',
    'scripts/prepare-aether.py',
    'scripts/prepare-tor-bridges.py',
    'scripts/build-cloudflare-profile.py',
    'server-bundle/opt/proxy-resilience/cloudflare_profiles.py',
    'docs/LIMITED-ACCESS-RECOVERY-2026-10-27-fa.md',
    'docs/SHUTDOWN-GOOGLE-GITHUB-RESEARCH-2026-10-27-fa.md',
    'docs/SHUTDOWN-CLOUDFLARE-TRANSPORTS-2026-10-27-fa.md',
    'docs/evidence/google-relay-preparation-2026-10-27.json',
    'docs/evidence/google-relay-source-review-2026-10-27.json',
    'docs/evidence/limited-access-local-2026-10-27.json',
    'docs/evidence/limited-access-office-2026-10-27.json',
    'docs/evidence/limited-access-tools-office-2026-10-27.json',
    'docs/evidence/recovery-github-api-2026-10-27.json',
)
# The staged deployment already uses the contents of server-bundle as its root.
STAGED_SOURCES = {
    'server-bundle/opt/proxy-resilience/cloudflare_profiles.py':
        'opt/proxy-resilience/cloudflare_profiles.py',
}


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2).encode('utf-8') + b'\n'


def _load_redactions(path):
    """Read only the explicit bounded regular file; diagnostics disclose no input."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as handle:
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_REDACTION_MAP:
                raise ValueError
            data = handle.read(MAX_REDACTION_MAP + 1)
        if len(data) > MAX_REDACTION_MAP:
            raise ValueError
        mapping = document(data)
        if not isinstance(mapping, dict) or not 1 <= len(mapping) <= 64:
            raise ValueError
        replacements = {}
        for original, replacement in mapping.items():
            if not isinstance(original, str) or not isinstance(replacement, str):
                raise ValueError
            original, replacement = original.encode('utf-8'), replacement.encode('utf-8')
            if not (1 <= len(original) <= MAX_REDACTION_TEXT
                    and 1 <= len(replacement) <= MAX_REDACTION_TEXT):
                raise ValueError
            replacements[original] = replacement
        pattern = re.compile(b'|'.join(re.escape(item) for item in sorted(replacements, key=len, reverse=True)))
        return pattern, replacements
    except (OSError, ValueError, TypeError):
        raise RecoveryError('invalid private redaction map') from None


def _redact(data, pattern, replacements):
    # One pass prevents replacement text from becoming another redaction input.
    # Bound output incrementally so a tiny match cannot cause a huge allocation.
    result, previous, count = bytearray(), 0, 0
    for match in pattern.finditer(data):
        replacement = replacements[match.group()]
        if len(result) + match.start() - previous + len(replacement) > MAX_FILE:
            raise RecoveryError('redacted public source exceeds the kit file size limit')
        result.extend(data[previous:match.start()])
        result.extend(replacement)
        previous, count = match.end(), count + 1
    if len(result) + len(data) - previous > MAX_FILE:
        raise RecoveryError('redacted public source exceeds the kit file size limit')
    result.extend(data[previous:])
    return bytes(result), count


def build(output, bundle_id='rescue-2026-10-27', *, root=ROOT, redactions=None):
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise RecoveryError('output already exists; previous kit retained')
    redaction_rules = _load_redactions(redactions) if redactions is not None else None
    records = {}
    for name in PUBLIC_FILES:
        safe_name(name)
        path = root / name
        if not path.exists() and not path.is_symlink() and name in STAGED_SOURCES:
            path = root / STAGED_SOURCES[name]
        if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()) or not path.is_file():
            raise RecoveryError('a public allowlisted source is missing or is a symlink')
        if path.stat().st_size > MAX_FILE:
            raise RecoveryError('a public source exceeds the kit file size limit')
        records[name] = path.read_bytes()
    records['READ-ME-FIRST.txt'] = (
        'This kit contains public tools and preparation templates, not a working subscription.\n'
        'Verify manifest.json against the SHA-256 you retained independently.\n'
        'No received file should be run before reviewing it. No tunnel has been qualified by downloading this kit.\n'
        'Begin with docs/LIMITED-ACCESS-RECOVERY-2026-10-27-fa.md.\n'
    ).encode()
    redactions_applied = 0
    if redaction_rules is not None:
        for name, data in records.items():
            records[name], count = _redact(data, *redaction_rules)
            redactions_applied += count
    manifest = {'schema_version': 1, 'bundle_id': bundle_id,
                'created_at': datetime.now(timezone.utc).isoformat(),
                'files': [{'name': name, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                          for name, data in sorted(records.items())]}
    manifest_data = _json(manifest)
    validate_manifest(manifest_data)
    records['manifest.json'] = manifest_data
    digest = hashlib.sha256(manifest_data).hexdigest()
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix='.limited-access-kit-', dir=output.parent))
    try:
        for name, data in records.items():
            target = stage / 'files' / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            os.chmod(target, 0o644)
        (stage / 'MANIFEST.sha256').write_text(digest + '  files/manifest.json\n')
        encoded = {name: base64.b64encode(data).decode('ascii') for name, data in records.items()}
        mapping = json.dumps(encoded, sort_keys=True)
        google = stage / 'google-apps-script'
        google.mkdir()
        (google / 'Code.gs').write_text(
            '// Static PUBLIC recovery files only. This is not a proxy or a tunnel.\n'
            '// Deploy as a web app before an outage. Keep the manifest digest separately.\n'
            'const FILES = ' + mapping + ';\n'
            'function doGet(e) {\n'
            '  const name = e && e.parameter && e.parameter.file;\n'
            '  const found = typeof name === "string" && Object.prototype.hasOwnProperty.call(FILES, name);\n'
            '  const result = found ? {encoding: "base64", content: FILES[name]} : {error: "not_found"};\n'
            '  return ContentService.createTextOutput(JSON.stringify(result)).setMimeType(ContentService.MimeType.JSON);\n'
            '}\n', encoding='utf-8')
        cloudflare = stage / 'cloudflare-worker'
        cloudflare.mkdir()
        (cloudflare / 'worker.js').write_text(
            '// Static PUBLIC recovery mirror. No outbound connections, keys, or open proxy.\n'
            'const FILES = ' + mapping + ';\n'
            'export default {async fetch(request) {\n'
            '  if (!["GET", "HEAD"].includes(request.method)) return new Response(null, {status: 405});\n'
            '  let name;\n'
            '  try { name = decodeURIComponent(new URL(request.url).pathname.slice(1)); }\n'
            '  catch { return new Response(null, {status: 400}); }\n'
            '  if (!Object.prototype.hasOwnProperty.call(FILES, name)) return new Response(null, {status: 404});\n'
            '  const bytes = Uint8Array.from(atob(FILES[name]), c => c.charCodeAt(0));\n'
            '  return new Response(request.method === "HEAD" ? null : bytes, {headers: {\n'
            '    "Content-Type": "application/octet-stream", "Cache-Control": "public, max-age=300",\n'
            '    "X-Content-Type-Options": "nosniff", "Content-Length": String(bytes.length)}});\n'
            '}};\n', encoding='utf-8')
        (cloudflare / 'wrangler.jsonc').write_bytes(_json({
            'name': 'rescue-recovery-static', 'main': 'worker.js', 'compatibility_date': '2026-10-27'}))
        report = {'schema_version': 1, 'bundle_id': bundle_id, 'manifest_sha256': digest,
                  'artifact_count': len(manifest['files']), 'total_bytes': sum(i['size'] for i in manifest['files']),
                  'public_allowlist_only': True, 'published': False, 'services_started': False}
        if redaction_rules is not None:
            report['redactions_applied'] = redactions_applied
        (stage / 'build-report.json').write_bytes(_json(report))
        if output.exists() or output.is_symlink():
            raise RecoveryError('output appeared during preparation; retained')
        commit_directory(stage, output)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'offline-toolkit/limited-access-kit-2026-10-27')
    parser.add_argument('--bundle-id', default='rescue-2026-10-27')
    parser.add_argument('--redactions', type=Path, help='Explicit private JSON map of exact text replacements; never bundled')
    args = parser.parse_args(argv)
    try:
        result = build(args.output, args.bundle_id, redactions=args.redactions)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        reason = str(exc) if isinstance(exc, RecoveryError) else 'local public-kit preparation failure'
        parser.exit(1, 'Preparation failed: ' + reason + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
