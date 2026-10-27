"""Bounded HTTPS probes that cannot bypass the selected loopback proxy."""
import ipaddress
import json
import os
import subprocess
import time

from aether_runner import PROFILES

TARGETS = {
    'primary': ('http', 11908, None),
    'lantern': ('http', 12940, 'connectivity-lantern'),
    'snowflake': ('socks5h', 12951, 'connectivity-tor@snowflake'),
    'tor': ('socks5h', 12950, 'connectivity-tor@direct'),
    'obfs4': ('socks5h', 12952, 'connectivity-tor@obfs4'),
    'meek': ('socks5h', 12953, 'connectivity-tor@meek'),
    'warp': ('socks5h', 12960, 'connectivity-warp@plain'),
    'psiphon': ('socks5h', 12961, 'connectivity-warp@psiphon'),
    'gool': ('socks5h', 12962, 'connectivity-warp@gool'),
    'reverse-ssh': ('socks5h', 10857, None),
    'masterdns': ('socks5h', 10856, 'masterdnsvpn-client'),
    'wggre': ('socks5h', 12978, 'connectivity-wggre'),
    'ipsec': ('socks5h', 12981, 'connectivity-ipsec'),
    'dnstt': ('socks5h', 10853, 'dnstt-client'),
}
TARGETS.update({name: ('socks5h', info[3], 'connectivity-aether@' + name) for name, info in PROFILES.items()})


def curl(name, url, timeout, *, stats=False, upload=None, run=subprocess.run):
    scheme, port, _ = TARGETS[name]
    command = ['curl', '--disable', '--silent', '--show-error', '--fail', '--noproxy', '',
               '--proxy', f'{scheme}://127.0.0.1:{port}', '--proto', '=https',
               '--connect-timeout', str(min(timeout, 10)), '--max-time', str(timeout)]
    if stats:
        command += ['--output', os.devnull, '--write-out', '%{json}']
    else:
        command += ['--max-filesize', '16384']
    if upload is not None:
        command += ['--request', 'POST', '--header', 'Content-Type: application/octet-stream', '--data-binary', '@-']
    command.append(url)
    try:
        result = run(command, input=upload, capture_output=True, timeout=timeout + 2)
        text = result.stdout.decode('utf-8', errors='replace')
        return result.returncode, json.loads(text) if stats else text
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return -1, {} if stats else ''


def probe(name, timeout=15, workload=False, *, run=subprocess.run):
    started = time.monotonic()
    code, trace = curl(name, 'https://www.cloudflare.com/cdn-cgi/trace', timeout, run=run)
    fields = dict(line.split('=', 1) for line in trace.splitlines() if '=' in line)
    try:
        exit_ip = str(ipaddress.ip_address(fields.get('ip', '')))
    except ValueError:
        exit_ip = None
    trace_ok = code == 0 and exit_ip is not None
    if name in PROFILES:
        trace_ok = trace_ok and fields.get('warp') in ('on', 'plus')
    web_code, web = curl(name, 'https://www.gstatic.com/generate_204', timeout, stats=True, run=run)
    web_ok = web_code == 0 and web.get('http_code') == 204
    result = {'channel': name, 'healthy': trace_ok and web_ok,
              'available': trace_ok or web_ok, 'trace_ok': trace_ok, 'https_ok': web_ok,
              'exit_ip': exit_ip, 'warp': fields.get('warp'), 'country': fields.get('loc')}
    if workload:
        size = 65536
        down_code, down = curl(name, f'https://speed.cloudflare.com/__down?bytes={size}', timeout, stats=True, run=run)
        up_code, up = curl(name, 'https://speed.cloudflare.com/__up', timeout,
                           stats=True, upload=os.urandom(size), run=run)
        result['download'] = {'healthy': down_code == 0 and down.get('http_code') == 200
                              and down.get('size_download') == size,
                              'bytes': down.get('size_download'), 'bytes_per_second': down.get('speed_download')}
        result['upload'] = {'healthy': up_code == 0 and up.get('http_code') == 200
                            and up.get('size_upload') == size,
                            'bytes': up.get('size_upload'), 'bytes_per_second': up.get('speed_upload')}
        result['healthy'] &= result['download']['healthy'] and result['upload']['healthy']
    result['seconds'] = round(time.monotonic() - started, 3)
    return result
