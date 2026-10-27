#!/usr/bin/env python3
"""Run independent userspace Cloudflare transports with persistent identities."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import urllib.parse

# Ports deliberately differ from the legacy warp-plus listeners 12960..12962.
PROFILES = {
    'warp-ipv6': ('wg', '6', False, 12970),
    'warp-ipv4': ('wg', '4', False, 12971),
    'warp-dual': ('wg', 'dual', False, 12972),
    'masque-h2-ipv4': ('masque', '4', True, 12973),
    'masque-h2-ipv6': ('masque', '6', True, 12974),
    'masque-h3-ipv4': ('masque', '4', False, 12975),
    'masque-h3-ipv6': ('masque', '6', False, 12976),
}
CONFIG = Path('/etc/connectivity-aether/profiles.json')
BINARY = Path('/opt/connectivity-tools/aether/aether')


def profile_environment(name, settings, state_dir):
    protocol, family, h2, port = PROFILES[name]
    if not isinstance(settings, dict):
        raise ValueError('profile must be an object')
    if settings.get('enabled') is not True:
        raise ValueError('profile is disabled')
    # Ignore inherited AETHER_* variables: they could silently disable validation,
    # expose an unauthenticated listener, change identity paths or add a detour.
    env = {k: v for k, v in os.environ.items() if not k.startswith('AETHER_')}
    env.update(TOKIO_WORKER_THREADS='2', AETHER_PROTOCOL=protocol, AETHER_IP=family,
               AETHER_MASQUE_HTTP2='1' if h2 else '0',
               AETHER_SOCKS=f'127.0.0.1:{port}', AETHER_SCAN='balanced',
               AETHER_CONFIG=str(state_dir / 'identity.toml'),
               AETHER_WG_CONFIG=str(state_dir / 'identity.toml'),
               AETHER_MASQUE_CONFIG=str(state_dir / 'identity.toml'),
               AETHER_NOIZE='off' if h2 else 'balanced',
               AETHER_QUICK_RECONNECT='1', AETHER_REPROVISION='0',
               AETHER_API_ADDRESS='127.0.0.1:9',
               AETHER_API_HOST='api.cloudflareclient.com',
               AETHER_API_SNI='api.cloudflareclient.com',
               AETHER_TLS_VERIFY='1', AETHER_MASQUE_SNI='www.cloudflare.com',
               AETHER_LOG_LEVEL='info', AETHER_PERF_PROFILE='low',
               AETHER_MAX_CLIENTS='64', AETHER_TCP_CONNECT_SECS='20',
               AETHER_WG_STALE_SECS='60', AETHER_MASQUE_STARTUP_SECS='60',
               AETHER_MASQUE_H2_KEEPALIVE_SECS='20', AETHER_MASQUE_H2_KEEPALIVE_TIMEOUT_SECS='10')
    # The HTTP CONNECT authority remains cloudflareaccess.com.  The TLS SNI
    # follows Aether 2.4's public-site default; forcing the CONNECT authority
    # here makes otherwise reachable Iranian HTTP/2 gateways stall.
    if 'masque_sni' in settings:
        sni = settings['masque_sni']
        if (protocol != 'masque' or not isinstance(sni, str) or len(sni) > 253 or
                not re.fullmatch(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
                                 r'[a-zA-Z](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?', sni)):
            raise ValueError('masque_sni must be a DNS hostname on a MASQUE profile')
        env['AETHER_MASQUE_SNI'] = sni.lower()
    peer = settings.get('peer')
    if peer:
        if not isinstance(peer, str):
            raise ValueError('peer must be an IP and port')
        host, sep, raw_port = peer.rpartition(':')
        if not sep or not 1 <= int(raw_port) <= 65535:
            raise ValueError('peer needs an IP and port')
        address = ipaddress.ip_address(host.strip('[]'))
        if family != 'dual' and str(address.version) != family:
            raise ValueError('peer IP family does not match profile')
        env['AETHER_PEER'] = f'[{address}]:{raw_port}' if address.version == 6 else f'{address}:{raw_port}'
    if type(settings.get('fragment', False)) is not bool:
        raise ValueError('fragment must be a boolean')
    if settings.get('fragment'):
        if not h2:
            raise ValueError('ClientHello fragmentation requires MASQUE HTTP/2')
        env['AETHER_MASQUE_H2_FRAGMENT'] = '1'
    return env


def bootstrap_environment(env, name, proxy=None):
    """Registration is an explicit preparation step, never normal failover."""
    env = dict(env)
    env['AETHER_REGISTER'] = 'wg' if PROFILES[name][0] == 'wg' else 'masque'
    if proxy:
        address = urllib.parse.urlsplit(proxy)
        if (address.scheme not in ('http', 'socks5', 'socks5h') or
                address.hostname not in ('127.0.0.1', '::1') or not address.port or
                address.username or address.password or address.path not in ('', '/') or
                address.query or address.fragment):
            raise ValueError('bootstrap proxy must be an unauthenticated loopback proxy URL')
        env['AETHER_UPSTREAM'] = proxy
    return env


def ipv6_available():
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
            # connect() on UDP does route selection without sending a packet.
            sock.connect(('2606:4700:4700::1111', 53))
            address = ipaddress.ip_address(sock.getsockname()[0])
            return not (address.is_unspecified or address.is_loopback or address.is_link_local)
    except OSError:
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('profile', choices=PROFILES)
    parser.add_argument('--config', type=Path, default=CONFIG,
                        help='profile settings map (default: %(default)s)')
    parser.add_argument('--state-directory', type=Path,
                        help='persistent identity directory for a dedicated service user')
    parser.add_argument('--provision', action='store_true', help='prepare a persistent identity and exit')
    parser.add_argument('--bootstrap-proxy', help='loopback proxy used only with --provision')
    args = parser.parse_args()
    os.umask(0o077)
    try:
        settings = json.loads(args.config.read_text())[args.profile]
        state_dir = args.state_directory or Path('/var/lib/connectivity-aether-' + args.profile)
        env = profile_environment(args.profile, settings, state_dir)
        expected = BINARY.with_name('aether.sha256').read_text().split()[0]
        if hashlib.sha256(BINARY.read_bytes()).hexdigest() != expected:
            raise ValueError('installed Aether digest mismatch')
        if args.bootstrap_proxy and not args.provision:
            raise ValueError('bootstrap proxy is only valid while provisioning')
        if args.provision:
            env = bootstrap_environment(env, args.profile, args.bootstrap_proxy)
        elif not (state_dir / 'identity.toml').is_file():
            parser.exit(78, 'Prepare a persistent identity with --provision before starting this transport\n')
        if not args.provision and PROFILES[args.profile][1] == '6' and not ipv6_available():
            raise ValueError('no usable local IPv6 route')
        state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chdir(state_dir)
    except (OSError, ValueError, KeyError, TypeError, IndexError):
        parser.exit(78, 'Aether configuration, binary integrity or IPv6 preflight failed\n')
    from aether_provision import block_enrollment, provision
    if args.provision:
        try:
            parser.exit(provision(BINARY, env))
        except (OSError, subprocess.SubprocessError):
            parser.exit(1, 'Verified Aether provisioning failed; identity preserved\n')
    guard = block_enrollment(env)
    os.execve(BINARY, [str(BINARY)], env)


if __name__ == '__main__':
    main()
