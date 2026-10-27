#!/usr/bin/env python3
"""Prepare a private Snowflake client from the installed Tor Browser bridge list.

Writing requires the installed Tor parser to accept the complete candidate first.
This only prepares configuration; it never starts or enables a service.
"""
import argparse
import grp
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


BRIDGES = {
    '192.0.2.3:80': '2B280B23E1107BB62ABFC40DDCC8824814F80A72',
    '192.0.2.4:80': '8838024498816A039FCBBAB14E6F40A0843051FA',
}
BROKER = 'https://1098762253.rsc.cdn77.org/'
DOMAIN = re.compile(r'(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\Z')


def tor_path(path):
    value = str(path)
    if not Path(value).is_absolute() or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('Tor paths must be absolute and contain no control characters')
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def transport_executable(path):
    # ClientTransportPlugin's argv parser retains quote characters in argv[0].
    # Use a single safe absolute token, as the official pt_config template does.
    value = str(path)
    if not Path(value).is_absolute() or not re.fullmatch(r'[A-Za-z0-9_./+\-]+', value):
        raise ValueError('Transport executable path must be an absolute token without spaces or quotes')
    return value


def validate_bridges(document):
    entries = document.get('bridges', {}).get('snowflake', [])
    if not isinstance(entries, list) or len(entries) != len(BRIDGES):
        raise ValueError('Expected the two pinned official Snowflake bridges')
    seen = set()
    for entry in entries:
        if not isinstance(entry, str) or any(ord(c) < 32 or ord(c) == 127 for c in entry):
            raise ValueError('Bridge entry contains control characters')
        fields = entry.split(' ')
        if len(fields) != 8 or fields[0] != 'snowflake' or fields[1] not in BRIDGES:
            raise ValueError('Unexpected Snowflake bridge syntax')
        address, fingerprint = fields[1:3]
        if address in seen or fingerprint != BRIDGES[address]:
            raise ValueError('Duplicate or unpinned Snowflake bridge')
        seen.add(address)
        options = {}
        for field in fields[3:]:
            key, separator, value = field.partition('=')
            if not separator or key in options or not value:
                raise ValueError('Invalid or duplicate bridge option')
            options[key] = value
        if set(options) != {'fingerprint', 'url', 'fronts', 'ice', 'utls-imitate'}:
            raise ValueError('Unexpected Snowflake bridge options')
        if options['fingerprint'] != fingerprint or options['url'] != BROKER:
            raise ValueError('Unpinned bridge identity or broker')
        if options['utls-imitate'] != 'hellorandomizedalpn':
            raise ValueError('Unexpected Snowflake TLS imitation')
        if not all(DOMAIN.fullmatch(host) for host in options['fronts'].split(',')):
            raise ValueError('Invalid front domain')
        for server in options['ice'].split(','):
            parts = server.split(':')
            if len(parts) != 3 or parts[0] != 'stun' or not DOMAIN.fullmatch(parts[1]):
                raise ValueError('Invalid STUN endpoint')
            if not parts[2].isdecimal() or not 1 <= int(parts[2]) <= 65535:
                raise ValueError('Invalid STUN port')
    return entries


def render_config(document, tor_root=Path('/opt/connectivity-tools/tor'),
                  state=Path('/var/lib/connectivity-tor-snowflake'), port=12951,
                  *, transport_binary=None, transport_log=None, dtls_mode=None):
    if isinstance(port, bool) or not isinstance(port, int) or not 1024 <= port <= 65535:
        raise ValueError('SOCKS port must be between 1024 and 65535')
    entries = validate_bridges(document)
    # The bundle version of lyrebird does not identify its embedded Snowflake
    # version. An explicitly reviewed standalone client can be selected without
    # replacing Tor, the other bundled transports, or existing private state.
    executable = transport_binary or tor_root / 'tor/pluggable_transports/lyrebird'
    command = transport_executable(executable)
    if transport_log is not None:
        command += ' -log ' + transport_executable(transport_log)
    if dtls_mode is not None:
        if transport_binary is None or dtls_mode not in {'disable', 'mimic', 'randomize', 'randomizemimic'}:
            raise ValueError('DTLS mode requires an explicit compatible standalone Snowflake client')
        command += ' -covertdtls-config ' + dtls_mode
    return '\n'.join([
        '# Prepared from the installed, pinned Tor Browser Snowflake bridge list.',
        'ClientOnly 1', 'RunAsDaemon 0',
        'DataDirectory ' + tor_path(state),
        f'SocksPort 127.0.0.1:{port} IsolateSOCKSAuth',
        'SafeSocks 1', 'UseBridges 1',
        'ClientTransportPlugin snowflake exec ' + command,
        *('Bridge ' + entry for entry in entries),
        'Log notice stdout', '',
    ])


def write_verified(config, output, tor_binary, library_dir, *, group_id=None,
                   verify_user=None, run=subprocess.run):
    """Keep the previous file intact when Tor rejects a candidate or cannot run."""
    output = Path(output)
    descriptor, candidate = tempfile.mkstemp(prefix='.' + output.name + '.', dir=output.parent)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as handle:
            handle.write(config)
            handle.flush()
            os.fsync(handle.fileno())
        if group_id is not None:
            os.chown(candidate, -1, group_id)
            os.chmod(candidate, 0o640)
        if verify_user and group_id is None:
            raise ValueError('A runtime verification user requires a readable group')
        env = dict(os.environ, LD_LIBRARY_PATH=str(library_dir))
        command = [str(tor_binary), '--verify-config', '-f', candidate]
        if verify_user:
            # PAM may strip LD_LIBRARY_PATH from runuser's environment.
            command = ['runuser', '-u', verify_user, '--', 'env',
                       'LD_LIBRARY_PATH=' + str(library_dir)] + command
        result = run(command,
                     env=env, capture_output=True, text=True, timeout=20)
        if result.returncode:
            raise ValueError('Installed Tor rejected the candidate; previous configuration retained')
        os.chmod(candidate, 0o640)
        os.replace(candidate, output)
        directory = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(candidate):
            os.unlink(candidate)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tor-root', type=Path, default=Path('/opt/connectivity-tools/tor'))
    parser.add_argument('--state', type=Path, default=Path('/var/lib/connectivity-tor-snowflake'))
    parser.add_argument('--port', type=int, default=12951)
    parser.add_argument('--transport-binary', type=Path,
                        help='Explicit reviewed standalone Snowflake client; keeps bundled lyrebird intact')
    parser.add_argument('--transport-log', type=Path,
                        help='Private log path writable by the runtime user')
    parser.add_argument('--dtls-mode', choices=('disable', 'mimic', 'randomize', 'randomizemimic'),
                        help='Standalone client DTLS option; not enabled implicitly')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--group', default='connectivity-tools',
                        help='Group allowed to read the written configuration')
    parser.add_argument('--user', default='connectivity-tools',
                        help='Runtime user whose private state Tor must be able to access')
    args = parser.parse_args()
    try:
        source = args.tor_root / 'tor/pluggable_transports/pt_config.json'
        config = render_config(json.loads(source.read_text()), args.tor_root, args.state, args.port,
                               transport_binary=args.transport_binary,
                               transport_log=args.transport_log, dtls_mode=args.dtls_mode)
        if args.output:
            group_id = grp.getgrnam(args.group).gr_gid if args.group else None
            write_verified(config, args.output, args.tor_root / 'tor/tor',
                           args.tor_root / 'tor', group_id=group_id, verify_user=args.user)
        else:
            print(config, end='')
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f'Cannot prepare Snowflake: {error}\n')


if __name__ == '__main__':
    main()
