"""Receive a pinned recovery kit over HTTPS, GitHub APIs, or an offline copy.

The trust anchor is a manifest SHA-256 supplied independently of its mirror.
Nothing downloaded is executed, installed, imported, or made executable.
"""
import base64
import ctypes
import errno
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import quote, urlencode, urljoin, urlsplit

MAX_FILE = 512 * 1024
MAX_TOTAL = 4 * 1024 * 1024
MAX_MANIFEST = 64 * 1024
MAX_SOURCES = 8
HEX256 = re.compile(r'[0-9a-f]{64}\Z')
COMMIT = re.compile(r'[0-9a-f]{40}\Z')
SEGMENT = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,80}\Z')


class RecoveryError(ValueError):
    """A deliberately non-sensitive diagnostic safe to print."""


def document(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise RecoveryError('duplicate JSON key')
            result[key] = value
        return result
    try:
        result = json.loads(data, object_pairs_hook=pairs)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise RecoveryError('invalid JSON document') from exc
    pending = [(result, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > 64:
            raise RecoveryError('JSON nesting exceeds limit')
        if isinstance(item, dict):
            pending.extend((value, depth + 1) for value in item.values())
        elif isinstance(item, list):
            pending.extend((value, depth + 1) for value in item)
    return result


def safe_name(value):
    if (not isinstance(value, str) or len(value) > 200
            or not value or any(not SEGMENT.fullmatch(p) for p in value.split('/'))):
        raise RecoveryError('invalid relative file name')
    return value


def safe_url(value):
    if not isinstance(value, str) or len(value) > 8192:
        raise RecoveryError('source requires an HTTPS URL without credentials')
    try:
        parts = urlsplit(value)
        valid = (parts.scheme == 'https' and parts.hostname and parts.username is None
                 and parts.password is None and not parts.fragment and parts.port in (None, 443)
                 and all(ord(c) > 32 and ord(c) != 127 for c in value))
    except (TypeError, ValueError):
        valid = False
    if not valid:
        raise RecoveryError('source requires an HTTPS URL without credentials')
    return parts


def _curl_config(value):
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def checked_connect_ip(value):
    try:
        address = ipaddress.ip_address(value)
    except (ValueError, TypeError) as exc:
        raise RecoveryError('connection override requires a public literal IP') from exc
    if not address.is_global:
        raise RecoveryError('connection override requires a public literal IP')
    return str(address)


def _request(url, maximum, timeout, headers=(), connect_ip=None):
    """Bound wall time and bytes even on old curl, without putting URLs in argv."""
    safe_url(url)
    config = 'url = ' + _curl_config(url) + '\n'
    if connect_ip is not None:
        address = checked_connect_ip(connect_ip)
        if ':' in address:
            address = '[' + address + ']'
        config += 'resolve = ' + _curl_config(safe_url(url).hostname + ':443:' + address) + '\n'
    for header in headers:
        if '\r' in header or '\n' in header:
            raise RecoveryError('invalid request header')
        config += 'header = ' + _curl_config(header) + '\n'
    command = ['curl', '--disable', '--silent', '--show-error', '--http1.1', '--globoff', '--retry', '0',
               '--include', '--proto', '=https', '--tlsv1.2', '--max-redirs', '0',
               '--connect-timeout', str(min(timeout, 8)), '--max-time', str(timeout),
               '--noproxy', '*', '--proxy', '', '--config', '-']
    try:
        blocked_env = {'CURL_CA_BUNDLE', 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'SSLKEYLOGFILE',
                       'CURL_SSL_BACKEND', 'CURL_SSL_CIPHER_LIST'}
        environment = {key: value for key, value in os.environ.items()
                       if key.upper() not in blocked_env and not key.lower().endswith('_proxy')}
        child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, env=environment)
    except OSError as exc:
        raise RecoveryError('curl unavailable') from exc
    data = bytearray()
    deadline = time.monotonic() + timeout + 1
    try:
        child.stdin.write(config.encode())
        child.stdin.close()
        with selectors.DefaultSelector() as events:
            events.register(child.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not events.select(remaining):
                    raise RecoveryError('request timed out')
                chunk = os.read(child.stdout.fileno(), min(65536, maximum + 65537 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > maximum + 65536:
                    raise RecoveryError('response exceeded size limit')
        if child.wait(timeout=max(0.01, deadline - time.monotonic())) != 0:
            raise RecoveryError('HTTPS request failed')
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RecoveryError('HTTPS request failed or timed out') from exc
    finally:
        if child.poll() is None:
            child.kill()
        child.wait()
        child.stdout.close()
        child.stdin.close()
    pending, header_bytes = bytes(data), 0
    for _ in range(6):
        head, separator, body = pending.partition(b'\r\n\r\n')
        header_bytes += len(head) + 4
        if not separator or header_bytes > 65536:
            raise RecoveryError('invalid or oversized HTTP response')
        lines = head.split(b'\r\n')
        try:
            status = int(lines[0].split()[1])
            response_headers = {}
            for line in lines[1:]:
                key, colon, value = line.partition(b':')
                if colon:
                    response_headers[key.decode('ascii').lower()] = value.strip().decode('latin1')
        except (ValueError, IndexError, UnicodeError) as exc:
            raise RecoveryError('invalid HTTP response headers') from exc
        if 100 <= status < 200 and status != 101:
            pending = body
            continue
        if len(body) > maximum:
            raise RecoveryError('response exceeded size limit')
        return status, response_headers, body
    raise RecoveryError('too many informational HTTP responses')


def fetch_https(url, maximum, timeout, *, redirect_hosts=(), headers=(), connect_ip=None):
    original = safe_url(url).hostname
    allowed = {original, *redirect_hosts}
    deadline = time.monotonic() + timeout
    for _ in range(3):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RecoveryError('request timed out')
        status, response_headers, body = _request(url, maximum, remaining, headers, connect_ip)
        if status == 200:
            return body
        if status not in (301, 302, 303, 307, 308) or 'location' not in response_headers:
            raise RecoveryError('source returned an unsuccessful HTTP status')
        candidate = urljoin(url, response_headers['location'])
        parts = safe_url(candidate)
        # Credentials may only be sent to the original API host. GitHub API
        # file reads do not need raw.githubusercontent.com or asset redirects.
        if parts.hostname not in allowed or headers:
            raise RecoveryError('source attempted an unapproved redirect')
        url = candidate
    raise RecoveryError('too many redirects')


def _token(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
            raise RecoveryError('GitHub token file must be private and regular')
        value = os.read(descriptor, 4097).strip()
    finally:
        os.close(descriptor)
    if not re.fullmatch(rb'[A-Za-z0-9_]{20,255}', value):
        raise RecoveryError('invalid GitHub token file')
    return value.decode('ascii')


def validate_sources(config):
    if not isinstance(config, dict) or config.get('schema_version') != 1:
        raise RecoveryError('unsupported source configuration')
    sources = config.get('sources')
    if not isinstance(sources, list) or not 1 <= len(sources) <= MAX_SOURCES:
        raise RecoveryError('expected one to eight configured sources')
    active, ids = [], set()
    for item in sources:
        if not isinstance(item, dict) or not isinstance(item.get('enabled', True), bool):
            raise RecoveryError('invalid source entry')
        identity = item.get('id')
        if not isinstance(identity, str) or not SEGMENT.fullmatch(identity) or identity in ids:
            raise RecoveryError('invalid or duplicate source identifier')
        ids.add(identity)
        if not item.get('enabled', True):
            continue
        kind = item.get('type')
        if item.get('connect_ip') is not None:
            if kind == 'directory':
                raise RecoveryError('offline source cannot have a connection override')
            checked_connect_ip(item['connect_ip'])
        if kind == 'directory':
            if not isinstance(item.get('directory'), str) or not Path(item['directory']).is_absolute():
                raise RecoveryError('offline directory must be absolute')
        elif kind == 'github-contents':
            repo = item.get('repository', '')
            if not isinstance(repo, str) or len(repo.split('/')) != 2:
                raise RecoveryError('invalid GitHub repository')
            safe_name(repo)
            if not COMMIT.fullmatch(item.get('ref', '')):
                raise RecoveryError('GitHub source requires a complete immutable commit')
            if item.get('prefix'):
                safe_name(item['prefix'])
        elif kind == 'github-gist':
            if not re.fullmatch(r'[0-9a-f]{20,40}', item.get('gist_id', '')):
                raise RecoveryError('invalid gist identifier')
            if not COMMIT.fullmatch(item.get('revision', '')):
                raise RecoveryError('gist requires a complete immutable revision')
        elif kind in ('https', 'apps-script'):
            parts = safe_url(item.get('base_url' if kind == 'https' else 'deployment_url', ''))
            if kind == 'https' and (parts.query or not parts.path.endswith('/')):
                raise RecoveryError('HTTPS mirror base must end in / and have no query')
            if kind == 'apps-script' and (parts.hostname != 'script.google.com' or parts.query
                    or not re.fullmatch(r'/macros/s/[A-Za-z0-9_-]+/exec', parts.path)):
                raise RecoveryError('invalid Apps Script deployment URL')
        else:
            raise RecoveryError('unsupported source type')
        active.append(dict(item))
    if not active:
        raise RecoveryError('no sources enabled')
    return active


def read_source(source, name, maximum, timeout, *, fetch=fetch_https, cache=None):
    safe_name(name)
    kind = source['type']
    if kind == 'directory':
        root = Path(source['directory']).resolve(strict=True)
        path = root
        for part in PurePosixPath(name).parts:
            path = path / part
            if path.is_symlink():
                raise RecoveryError('symlinks are not recovery artifacts')
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
                raise RecoveryError('invalid or oversized offline artifact')
            data = os.read(descriptor, maximum + 1)
        finally:
            os.close(descriptor)
    elif kind in ('github-contents', 'github-gist'):
        headers = ['Accept: application/vnd.github+json', 'X-GitHub-Api-Version: 2022-11-28']
        if source.get('token_file'):
            headers.append('Authorization: Bearer ' + _token(source['token_file']))
        if kind == 'github-contents':
            location = '/'.join(filter(None, (source.get('prefix', ''), name)))
            url = ('https://api.github.com/repos/' + source['repository'] + '/contents/'
                   + quote(location, safe='/') + '?ref=' + source['ref'])
        else:
            url = 'https://api.github.com/gists/' + source['gist_id'] + '/' + source['revision']
        cache_key = (source['id'], url)
        record = cache.get(cache_key) if kind == 'github-gist' and cache is not None else None
        if record is None:
            options = {'headers': headers}
            if source.get('connect_ip') is not None:
                options['connect_ip'] = source['connect_ip']
            wire_limit = 2 * MAX_TOTAL if kind == 'github-gist' else maximum * 2 + 65536
            record = document(fetch(url, wire_limit, timeout, **options))
            if kind == 'github-gist' and cache is not None:
                cache[cache_key] = record
        if not isinstance(record, dict):
            raise RecoveryError('invalid GitHub response')
        if kind == 'github-contents':
            if record.get('type') != 'file' or record.get('encoding') != 'base64':
                raise RecoveryError('GitHub file not available inline')
            if not isinstance(record.get('content'), str):
                raise RecoveryError('GitHub file has no inline text content')
            try:
                data = base64.b64decode(''.join(record['content'].split()), validate=True)
            except (ValueError, KeyError, TypeError) as exc:
                raise RecoveryError('invalid GitHub base64 content') from exc
            if record.get('size') != len(data):
                raise RecoveryError('GitHub file size mismatch')
        else:
            files = record.get('files')
            if not isinstance(files, dict):
                raise RecoveryError('gist has no inline file map')
            file = files.get(name)
            if record.get('truncated') or not isinstance(file, dict) or file.get('truncated'):
                raise RecoveryError('gist content missing or truncated; raw redirect refused')
            if not isinstance(file.get('content'), str):
                raise RecoveryError('gist has no inline text content')
            data = file['content'].encode('utf-8')
    elif kind == 'apps-script':
        url = source['deployment_url'] + '?' + urlencode({'file': name})
        options = {'redirect_hosts': ('script.googleusercontent.com',)}
        if source.get('connect_ip') is not None:
            options['connect_ip'] = source['connect_ip']
        record = document(fetch(url, maximum * 2 + 1024, timeout, **options))
        if not isinstance(record, dict) or record.get('encoding') != 'base64':
            raise RecoveryError('Apps Script mirror returned no inline artifact')
        try:
            data = base64.b64decode(record['content'], validate=True)
        except (ValueError, KeyError, TypeError) as exc:
            raise RecoveryError('invalid Apps Script mirror content') from exc
    else:
        options = {'connect_ip': source['connect_ip']} if source.get('connect_ip') is not None else {}
        data = fetch(source['base_url'] + quote(name, safe='/'), maximum, timeout, **options)
    if len(data) > maximum:
        raise RecoveryError('artifact exceeds size limit')
    return data


def validate_manifest(data):
    if len(data) > MAX_MANIFEST:
        raise RecoveryError('manifest exceeds size limit')
    manifest = document(data)
    if not isinstance(manifest, dict) or manifest.get('schema_version') != 1:
        raise RecoveryError('unsupported recovery manifest')
    if not isinstance(manifest.get('bundle_id'), str) or not SEGMENT.fullmatch(manifest['bundle_id']):
        raise RecoveryError('invalid bundle identifier')
    files = manifest.get('files')
    if not isinstance(files, list) or not 1 <= len(files) <= 64:
        raise RecoveryError('manifest must contain one to 64 artifacts')
    seen, total = set(), 0
    for item in files:
        if not isinstance(item, dict):
            raise RecoveryError('invalid manifest artifact')
        name = safe_name(item.get('name'))
        key = name.casefold()
        if key in seen or key == 'manifest.json':
            raise RecoveryError('duplicate or reserved artifact name')
        seen.add(key)
        if (isinstance(item.get('size'), bool) or not isinstance(item.get('size'), int)
                or not 0 <= item['size'] <= MAX_FILE
                or not isinstance(item.get('sha256'), str) or not HEX256.fullmatch(item['sha256'])):
            raise RecoveryError('invalid artifact size or digest')
        total += item['size']
    if total > MAX_TOTAL:
        raise RecoveryError('kit exceeds total size limit')
    return manifest


def commit_directory(stage, destination):
    """Atomically commit a directory without replacing even an empty old one."""
    if sys.platform == 'win32':
        os.rename(stage, destination)  # Windows rename refuses an existing target.
        return
    if sys.platform.startswith('linux'):
        library = ctypes.CDLL(None, use_errno=True)
        rename = getattr(library, 'renameat2', None)
        if rename is not None:
            rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
            rename.restype = ctypes.c_int
            if rename(-100, os.fsencode(stage), -100, os.fsencode(destination), 1) == 0:
                return
            code = ctypes.get_errno()
            if code in (errno.EEXIST, errno.ENOTEMPTY):
                raise RecoveryError('destination already exists; previous kit retained')
            if code not in (errno.ENOSYS, errno.EINVAL):
                raise OSError(code, os.strerror(code))
    raise RecoveryError('atomic directory commit requires Linux renameat2 or Windows rename')


def recover(sources, manifest_sha256, destination, *, timeout=15, total_timeout=180, read=None):
    if not isinstance(manifest_sha256, str) or not HEX256.fullmatch(manifest_sha256):
        raise RecoveryError('independently supplied manifest SHA-256 is required')
    if not 1 <= timeout <= 55:
        raise RecoveryError('timeout must be between one and 55 seconds')
    if not 1 <= total_timeout <= 1800:
        raise RecoveryError('total recovery budget must be between one and 1800 seconds')
    deadline = time.monotonic() + total_timeout
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        raise RecoveryError('destination already exists; previous kit retained')
    sources = validate_sources({'schema_version': 1, 'sources': sources})
    failures, provenance = [], []
    if read is None:
        cache = {}
        def read(source, name, maximum, request_timeout):
            return read_source(source, name, maximum, request_timeout, cache=cache)

    def verified(name, maximum, digest, exact_size=None):
        for source in sources:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RecoveryError('total recovery deadline exceeded')
            try:
                data = read(source, name, maximum, min(timeout, remaining))
                if hashlib.sha256(data).hexdigest() != digest or (exact_size is not None and len(data) != exact_size):
                    raise RecoveryError('artifact digest or size mismatch')
                provenance.append({'file': name, 'source': source['id']})
                return data
            except (OSError, ValueError, KeyError, TypeError):
                failures.append({'file': name, 'source': source['id'], 'result': 'unavailable_or_unverified'})
        raise RecoveryError('no source provided the pinned artifact')

    manifest_data = verified('manifest.json', MAX_MANIFEST, manifest_sha256)
    manifest = validate_manifest(manifest_data)
    destination.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix='.recovery-', dir=destination.parent))
    try:
        (stage / 'manifest.json').write_bytes(manifest_data)
        for item in manifest['files']:
            data = verified(item['name'], item['size'], item['sha256'], item['size'])
            target = stage / item['name']
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'wb') as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
        os.chmod(stage / 'manifest.json', 0o600)
        if destination.exists() or destination.is_symlink():
            raise RecoveryError('destination appeared during recovery; retained')
        commit_directory(stage, destination)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    return {'schema_version': 1, 'bundle_id': manifest['bundle_id'],
            'manifest_sha256': manifest_sha256, 'verified_files': len(manifest['files']),
            'executed': False, 'sources_used': provenance, 'source_failures': failures}
