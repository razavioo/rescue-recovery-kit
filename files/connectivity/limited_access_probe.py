"""Read-only evidence for selective HTTPS access, not proof of a working tunnel.

Each check has a body limit and a wall-clock deadline. curl is used so DNS,
connect, TLS and body transfer are all covered by a killable process deadline.
No response bodies, client IPs, custom URLs or proxy URLs enter the report.
"""
from __future__ import annotations

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import select
import struct
import subprocess
import tempfile
import time
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Check:
    name: str
    provider: str
    capability: str
    url: str
    validator: str
    statuses: tuple[int, ...] = (200,)
    max_bytes: int = 32768
    built_in: bool = True


@dataclass(frozen=True)
class Response:
    status: int | None = None
    body: bytes = b''
    content_type: str = ''
    tls_verified: bool = False
    error: str | None = None


DNS_NAME = 'example.com'
DNS_QUERY = (struct.pack('!6H', 0, 0x0100, 1, 0, 0, 0)
             + b'\x07example\x03com\x00\x00\x01\x00\x01')
DNS_PARAMETER = base64.urlsafe_b64encode(DNS_QUERY).rstrip(b'=').decode('ascii')

DEFAULT_CHECKS = (
    Check('google-web', 'google', 'https_web', 'https://www.gstatic.com/generate_204',
          'empty', (204,), 1024),
    Check('google-api', 'google', 'public_api',
          'https://www.googleapis.com/discovery/v1/apis?name=drive&preferred=true',
          'google-discovery'),
    Check('google-doh', 'google', 'dns_over_https',
          'https://dns.google/dns-query?dns=' + DNS_PARAMETER, 'dns-wire', max_bytes=4096),
    Check('cloudflare-web', 'cloudflare', 'https_web',
          'https://www.cloudflare.com/cdn-cgi/trace', 'cloudflare-trace', max_bytes=8192),
    Check('cloudflare-doh', 'cloudflare', 'dns_over_https',
          'https://cloudflare-dns.com/dns-query?dns=' + DNS_PARAMETER,
          'dns-wire', max_bytes=4096),
    Check('github-api-root', 'github', 'public_api', 'https://api.github.com/', 'github-root'),
    Check('github-api-meta', 'github', 'public_api', 'https://api.github.com/meta',
          'github-meta', max_bytes=262144),
    Check('github-web', 'github', 'https_web', 'https://github.com/robots.txt',
          'robots', max_bytes=65536),
    Check('github-raw', 'github', 'raw_file_download',
          'https://raw.githubusercontent.com/github/gitignore/main/Python.gitignore', 'gitignore'),
    Check('general-control', 'control', 'general_https_control',
          'https://web.mit.edu/robots.txt', 'robots'),
    Check('iran-facing-control', 'control', 'iran_facing_https_control',
          'https://www.aparat.com/robots.txt', 'robots', max_bytes=65536),
)

LIMITATIONS = (
    'A successful check proves only the named endpoint, response and selected route at this time.',
    'HTTPS, API, raw-file and DoH access do not establish a proxy, VPN, domain-fronting or tunnel capability.',
    'DoH success is a checked A answer for example.com, not arbitrary DNS, DNSSEC or DNS-tunnel proof.',
    'Failed checks may reflect local DNS, IPv6, rate limits or endpoint policy; they do not establish censorship.',
    'The Iran-facing control is a service comparison; its physical hosting and domestic routing are not verified.',
    'IPv4/IPv6 selects the connection to the proxy when a proxy is explicit; target-family choice may be remote.',
    'Results apply to the machine and network that ran the command, not all Iranian operators or the office.',
)

ERROR_CODES = frozenset(('timeout', 'dns_failed', 'connect_failed', 'tls_failed',
                         'response_too_large', 'curl_unavailable', 'transport_failed'))


def _timestamp():
    return datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


def _validate_url(value, *, proxy=False):
    """Reject userinfo/query secrets; never repeat supplied values in exceptions."""
    try:
        if not isinstance(value, str) or not value or len(value) > 2048:
            raise ValueError
        if any(ord(char) <= 32 or ord(char) == 127 for char in value) or '\\' in value:
            raise ValueError
        parsed = urlsplit(value)
        allowed = ('http', 'https', 'socks5', 'socks5h') if proxy else ('https',)
        if parsed.scheme not in allowed or not parsed.hostname:
            raise ValueError
        if parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
            raise ValueError
        host = parsed.hostname
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not re.fullmatch(r'[A-Za-z0-9.-]+', host):
                raise ValueError
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError
        if proxy and parsed.path not in ('', '/'):
            raise ValueError
    except (ValueError, TypeError):
        noun = 'proxy' if proxy else 'custom endpoint'
        raise ValueError(f'{noun} must be a valid credential-free URL without query or fragment') from None
    return value


def _dns_name(packet, offset):
    """Read a bounded DNS name, detecting malformed labels/compression loops."""
    labels, seen, end = [], set(), None
    for _ in range(128):
        if offset in seen or offset >= len(packet):
            raise ValueError
        seen.add(offset)
        length = packet[offset]
        if length & 0xc0 == 0xc0:
            if offset + 1 >= len(packet):
                raise ValueError
            if end is None:
                end = offset + 2
            offset = ((length & 0x3f) << 8) | packet[offset + 1]
            continue
        if length & 0xc0 or length > 63 or offset + 1 + length > len(packet):
            raise ValueError
        offset += 1
        if length == 0:
            if sum(len(label) + 1 for label in labels) > 255:
                raise ValueError
            return '.'.join(labels).lower(), end if end is not None else offset
        labels.append(packet[offset:offset + length].decode('ascii'))
        offset += length
    raise ValueError


def validate_dns_wire(packet):
    """Validate a matching, complete DNS answer, with no client/answer IP output."""
    try:
        if len(packet) < 12:
            raise ValueError
        ident, flags, qd, an, ns, ar = struct.unpack_from('!6H', packet)
        if ident != 0 or not flags & 0x8000 or flags & 0x7a0f or qd != 1 or an == 0:
            raise ValueError
        # 0x7a0f excludes non-query opcode, truncation and DNS failure rcodes.
        if an + ns + ar > 128:
            raise ValueError
        name, offset = _dns_name(packet, 12)
        if name != DNS_NAME or packet[offset:offset + 4] != b'\x00\x01\x00\x01':
            raise ValueError
        offset += 4
        addresses, aliases = [], []
        for number in range(an + ns + ar):
            owner, offset = _dns_name(packet, offset)
            kind, record_class, _, size = struct.unpack_from('!HHIH', packet, offset)
            offset += 10
            end = offset + size
            if end > len(packet):
                raise ValueError
            if number < an and record_class == 1:
                if kind == 1:
                    if size != 4:
                        raise ValueError
                    address = ipaddress.IPv4Address(packet[offset:end])
                    if not address.is_global:
                        raise ValueError
                    addresses.append((owner, address))
                elif kind == 5:
                    alias, alias_end = _dns_name(packet, offset)
                    if alias_end != end:
                        raise ValueError
                    aliases.append((owner, alias))
            offset = end
        if offset != len(packet):
            raise ValueError
        reachable = {DNS_NAME}
        for _ in range(len(aliases)):
            reachable.update(target for owner, target in aliases if owner in reachable)
        count = sum(owner in reachable for owner, _ in addresses)
        if not count:
            raise ValueError
        return {'dns_rcode': 0, 'matching_public_a_answers': count}
    except (ValueError, UnicodeError, struct.error, IndexError):
        raise ValueError('dns_response_invalid') from None


def _body_evidence(check, response):
    body = response.body
    kind = check.validator
    if kind == 'dns-wire':
        if response.content_type.split(';', 1)[0].strip().lower() != 'application/dns-message':
            raise ValueError
        return validate_dns_wire(body)
    if kind == 'empty':
        valid = not body
    elif kind in ('google-discovery', 'github-root', 'github-meta'):
        document = json.loads(body)
        if not isinstance(document, dict):
            raise ValueError
        if kind == 'google-discovery':
            items = document.get('items')
            valid = document.get('kind') == 'discovery#directoryList' and isinstance(items, list)
            valid = valid and any(isinstance(item, dict) and item.get('name') == 'drive'
                                  and item.get('version') == 'v3' for item in items)
        elif kind == 'github-root':
            valid = document.get('current_user_url') == 'https://api.github.com/user'
            valid = valid and isinstance(document.get('repository_url'), str)
        else:
            valid = isinstance(document.get('verifiable_password_authentication'), bool)
            valid = valid and isinstance(document.get('ssh_keys'), list) and bool(document['ssh_keys'])
            valid = valid and isinstance(document.get('git'), list) and bool(document['git'])
    elif kind == 'cloudflare-trace':
        fields = dict(line.split('=', 1) for line in body.decode('ascii').splitlines() if '=' in line)
        ipaddress.ip_address(fields.get('ip', ''))
        valid = fields.get('h') == 'www.cloudflare.com' and fields.get('tls', '').startswith('TLSv')
    elif kind == 'robots':
        valid = b'user-agent:' in body.lower() and b'disallow:' in body.lower()
    elif kind == 'gitignore':
        valid = b'__pycache__/' in body and b'*.py[codz]' in body
    elif kind == 'status-only':
        return {'response_validation': 'status_only_custom_endpoint'}
    else:
        raise ValueError
    if not valid:
        raise ValueError
    return {'response_validation': 'expected_body'}


def _curl_error(code):
    if code in (5, 6):
        return 'dns_failed'
    if code == 7:
        return 'connect_failed'
    if code == 28:
        return 'timeout'
    if code in (35, 51, 58, 60, 77, 80, 82, 83, 90, 91):
        return 'tls_failed'
    if code == 63:
        return 'response_too_large'
    return 'transport_failed' if code else None


def curl_transport(check, *, timeout, family='auto', proxy=None):
    """Perform one HTTPS GET, without redirects, retries or inherited proxies."""
    deadline = time.monotonic() + timeout
    accept = 'application/dns-message' if check.validator == 'dns-wire' else '*/*'
    command = ['curl', '--disable', '--silent', '--globoff', '--proto', '=https',
               '--proto-redir', '=https', '--tlsv1.2', '--retry', '0',
               '--connect-timeout', str(min(timeout, 5)), '--max-time', str(timeout),
               '--max-filesize', str(check.max_bytes), '--user-agent', 'IranRebate-access-probe/1',
               '--header', 'Accept: ' + accept,
               '--write-out', '%{stderr}%{http_code}\n%{ssl_verify_result}\n%{content_type}']
    command += ['--proxy', proxy or '', '--noproxy', '' if proxy else '*']
    if family != 'auto':
        command.append('--ipv4' if family == 'ipv4' else '--ipv6')
    command += ['--url', check.url]
    environment = {key: value for key, value in os.environ.items()
                   if key.lower() not in ('http_proxy', 'https_proxy', 'all_proxy', 'no_proxy',
                                          'curl_ca_bundle', 'ssl_cert_file', 'ssl_cert_dir', 'sslkeylogfile')}
    body = bytearray()
    forced_error = None
    with tempfile.TemporaryFile() as metadata:
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=metadata, env=environment)
        except OSError:
            return Response(error='curl_unavailable')
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    forced_error = 'timeout'
                    break
                ready, _, _ = select.select([process.stdout], [], [], remaining)
                if not ready:
                    forced_error = 'timeout'
                    break
                chunk = os.read(process.stdout.fileno(), min(16384, check.max_bytes + 1 - len(body)))
                if not chunk:
                    break
                body.extend(chunk)
                if len(body) > check.max_bytes:
                    forced_error = 'response_too_large'
                    break
            if forced_error:
                process.kill()
            try:
                code = process.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1)
                code, forced_error = -1, forced_error or 'timeout'
        except (OSError, ValueError):
            process.kill()
            process.wait(timeout=1)
            code, forced_error = -1, 'transport_failed'
        finally:
            process.stdout.close()
        metadata.seek(0)
        lines = metadata.read(512).decode('ascii', errors='replace').splitlines()
    status = int(lines[0]) if lines and re.fullmatch(r'[1-5][0-9]{2}', lines[0]) else None
    verified = status is not None and len(lines) > 1 and lines[1] == '0'
    media_type = lines[2] if len(lines) > 2 else ''
    return Response(status, bytes(body[:check.max_bytes]), media_type, verified,
                    forced_error or _curl_error(code))


def _check_result(check, family, timeout, proxy, transport):
    started = time.monotonic()
    result = {'name': check.name, 'provider': check.provider, 'capability': check.capability,
              'family': family, 'started_at': _timestamp(), 'timeout_seconds': round(timeout, 3),
              'endpoint': check.url.split('?', 1)[0] if check.built_in else '[custom endpoint redacted]',
              'observed': False, 'tls_verified': False, 'http_status': None, 'bytes_received': 0}
    try:
        response = transport(check, timeout=timeout, family=family, proxy=proxy)
        result.update(http_status=response.status, tls_verified=bool(response.tls_verified),
                      bytes_received=min(len(response.body), check.max_bytes + 1))
        if response.error:
            result['reason'] = response.error if response.error in ERROR_CODES else 'transport_failed'
        elif len(response.body) > check.max_bytes:
            result['reason'] = 'response_too_large'
        elif not response.tls_verified:
            result['reason'] = 'tls_unverified'
        elif response.status not in check.statuses:
            result['reason'] = 'unexpected_http_status'
        else:
            result['evidence'] = _body_evidence(check, response)
            result['observed'] = True
            result['reason'] = 'expected_response'
    except (ValueError, TypeError, UnicodeError, KeyError, OverflowError, RecursionError):
        result['reason'] = 'invalid_response_body'
    except Exception:
        # Transport exceptions can contain credentials/URLs; no exception text is logged.
        result['reason'] = 'transport_failed'
    result['seconds'] = round(time.monotonic() - started, 3)
    return result


def probe(*, timeout=8, families=('auto',), proxy=None, custom_urls=(), workers=3,
          total_timeout=60, transport=curl_transport):
    """Return a sanitized report; custom endpoints prove status/TLS only."""
    if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0.2 <= timeout <= 60:
        raise ValueError('timeout must be between 0.2 and 60 seconds')
    if not isinstance(total_timeout, (int, float)) or not math.isfinite(total_timeout) or not 0.2 <= total_timeout <= 300:
        raise ValueError('total timeout must be between 0.2 and 300 seconds')
    if type(workers) is not int or not 1 <= workers <= 4:
        raise ValueError('workers must be between 1 and 4')
    families = tuple(families)
    if not families or len(set(families)) != len(families) or any(f not in ('auto', 'ipv4', 'ipv6') for f in families):
        raise ValueError('families must be unique auto, ipv4 or ipv6 values')
    if proxy is not None:
        _validate_url(proxy, proxy=True)
    custom_urls = tuple(custom_urls)
    if len(custom_urls) > 4:
        raise ValueError('at most four custom endpoints are allowed')
    checks = list(DEFAULT_CHECKS)
    for number, url in enumerate(custom_urls, 1):
        checks.append(Check(f'custom-{number}', 'custom', 'custom_https_status',
                            _validate_url(url), 'status-only', built_in=False))
    started = time.monotonic()
    report = {'schema_version': 1, 'kind': 'limited_access_evidence', 'started_at': _timestamp(),
              'route': 'explicit_proxy' if proxy else 'direct', 'inherited_proxies': False,
              'family_scope': 'proxy_connection' if proxy else 'endpoint_connection',
              'timeout_seconds': timeout, 'total_timeout_seconds': total_timeout,
              'max_parallel_checks': workers, 'limitations': list(LIMITATIONS)}

    def run(item):
        check, family = item
        remaining = total_timeout - (time.monotonic() - started)
        if remaining <= 0:
            return {'name': check.name, 'provider': check.provider, 'capability': check.capability,
                    'family': family, 'observed': False, 'reason': 'total_deadline_not_attempted',
                    'tls_verified': False, 'http_status': None, 'bytes_received': 0, 'seconds': 0}
        return _check_result(check, family, min(timeout, remaining), proxy, transport)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        results = list(executor.map(run, ((check, family) for check in checks for family in families)))
    report['checks'] = results
    report['capabilities'] = {}
    for provider in ('google', 'cloudflare', 'github', 'control', 'custom'):
        rows = [row for row in results if row['provider'] == provider]
        if rows:
            report['capabilities'][provider] = {
                'observed': sorted({row['capability'] for row in rows if row['observed']}),
                'unconfirmed': sorted({row['capability'] for row in rows if not row['observed']}),
                'tunnel_validated': False}
    report.update(finished_at=_timestamp(), seconds=round(time.monotonic() - started, 3))
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.add_argument('--timeout', type=float, default=8, help='per-check seconds, 0.2–60 (default: 8)')
    parser.add_argument('--total-timeout', type=float, default=60, help='whole-run seconds, 0.2–300')
    parser.add_argument('--families', default='auto', help='comma-separated auto,ipv4,ipv6; default auto')
    parser.add_argument('--workers', type=int, default=3, help='parallel checks, 1–4 (default: 3)')
    parser.add_argument('--proxy', help='explicit credential-free HTTP(S)/SOCKS5(H) proxy; environment ignored')
    parser.add_argument('--custom-url', action='append', default=[], help='up to four credential-free HTTPS controls')
    parser.add_argument('--output', type=Path, help='save JSON report (stdout otherwise)')
    args = parser.parse_args(argv)
    try:
        report = probe(timeout=args.timeout, total_timeout=args.total_timeout,
                       families=tuple(args.families.split(',')), proxy=args.proxy,
                       custom_urls=args.custom_url, workers=args.workers)
    except ValueError as exc:
        parser.error(str(exc))
    encoded = json.dumps(report, ensure_ascii=False, indent=2) + '\n'
    if args.output:
        try:
            args.output.write_text(encoded, encoding='utf-8')
        except OSError:
            parser.exit(2, 'unable to write report output\n')
    else:
        print(encoded, end='')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
