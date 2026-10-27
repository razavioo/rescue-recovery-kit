"""Cloudflare recipes, kept separate from clients that cannot express F&F.

Preset values are expanded from PattNG arrays.xml at commit
3135dc5de16394101ddcaa547b16bdb0635f2fcf, rather than passing UI labels
to an Xray core. A recipe is a candidate until tested on the actual network.
"""
import copy
import ipaddress
import json
import re
import urllib.parse
import uuid


FINAL_MASK = {'tcp': [
    {'type': 'fragment', 'settings': {'packets': 'tlshello',
     'lengths': ['0', '104', '1'], 'delays': ['0'], 'maxSplit': '0'}},
    {'type': 'fragment', 'settings': {'packets': '1-1',
     'lengths': ['114', '1'], 'delays': ['1'], 'maxSplit': '11'}}]}
CIPHERS = ':'.join([
    'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
    'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256', 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256'])
METHODS = ('ipv6', 'ff', 'ech')


def dns_name(value):
    if not isinstance(value, str):
        raise ValueError('a DNS hostname is required')
    value = value.rstrip('.').encode('idna').decode('ascii').lower()
    if len(value) > 253 or '.' not in value or any(
            not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
            for part in value.split('.')):
        raise ValueError('a DNS hostname is required for Cloudflare SNI/Host')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError('Cloudflare SNI must be a hostname, not an edge IP')


def recipe(link, method, address, *, server_name=None, ech_config=None, name=None):
    """Transform an existing authenticated VLESS/TLS WS or XHTTP link.

    Keep the origin's UUID, path, Host and XHTTP settings. Remove stale ECH,
    masks and cipher lists before selecting mutually exclusive recipes.
    """
    if method not in METHODS:
        raise ValueError('unknown Cloudflare recipe')
    if len(link.strip().splitlines()) != 1 or any(c.isspace() for c in link.strip()):
        raise ValueError('input must contain one URL-encoded VLESS link')
    parsed = urllib.parse.urlsplit(link.strip())
    if parsed.scheme != 'vless' or parsed.password or not parsed.hostname:
        raise ValueError('an authenticated VLESS link is required')
    identity = str(uuid.UUID(urllib.parse.unquote(parsed.username or '')))
    pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    params = dict(pairs)
    if len(params) != len(pairs):
        raise ValueError('ambiguous duplicate VLESS parameters')
    transport = params.get('type')
    if params.get('security') != 'tls' or transport not in ('ws', 'xhttp'):
        raise ValueError('Cloudflare recipes require TLS with WS or XHTTP')
    edge = ipaddress.ip_address(address)
    if not edge.is_global:
        raise ValueError('a public edge IP is required')
    if method == 'ipv6' and edge.version != 6:
        raise ValueError('the IPv6 recipe requires an IPv6 edge address')
    sni = dns_name(server_name or params.get('sni') or parsed.hostname)
    host = dns_name(params.get('host') or sni)
    for key in ('fm', 'cs', 'ech', 'echOutbound', 'allowInsecure', 'allow_insecure', 'insecure'):
        params.pop(key, None)
    params.update(sni=sni, host=host, fp='chrome',
                  alpn='http/1.1' if transport == 'ws' else 'h2,http/1.1', insecure='0')
    if method == 'ff':
        params.update(fp='unsafe', cs=CIPHERS, fm=json.dumps(FINAL_MASK, separators=(',', ':')))
    elif method == 'ech':
        if not ech_config or not ech_config.strip():
            raise ValueError('ECH needs an explicit config or resolver expression')
        params['ech'] = ech_config.strip()
    port = parsed.port or 443
    target = f'[{edge}]' if edge.version == 6 else str(edge)
    label = name or (urllib.parse.unquote(parsed.fragment) + '-CF-' + method.upper())
    return urllib.parse.urlunsplit(('vless', f'{identity}@{target}:{port}', '',
                                   urllib.parse.urlencode(params), urllib.parse.quote(label, safe='')))


def ingress_nodes(settings, token, *, pattng=False):
    """Opt-in CDN entrances to existing WS rescue channels, per subscriber.

    Publishing requires both enabled and published on each ingress. F&F and
    ECH links are available only in pattng.txt; portable profiles carry DNS
    hostnames and IPv6. DNS entrances work with both CDN and direct records.
    External Worker/XHTTP links can be transformed with the standalone CLI.
    """
    result, names = [], set()
    channels = {c['tag']: c for c in settings['channels'] if c.get('enabled')}
    identity = str(uuid.uuid5(uuid.NAMESPACE_URL, 'iranrebate-rescue:' + token))
    for ingress in settings.get('cloudflare_ingresses', []):
        if not ingress.get('enabled') or not ingress.get('published', False):
            continue
        method = ingress['method']
        if method not in (*METHODS, 'domain'):
            raise ValueError('unknown Cloudflare ingress method')
        if method not in ('ipv6', 'domain') and not pattng:
            continue
        channel = channels[ingress['channel']]
        if channel.get('published', True) is False:
            continue
        name = ingress['name']
        if name in names:
            raise ValueError('duplicate Cloudflare ingress name')
        names.add(name)
        domain = dns_name(ingress['server_name'])
        params = {'security': 'tls', 'type': 'ws', 'path': channel['path'], 'host': domain}
        base = f'vless://{identity}@{domain}:443?' + urllib.parse.urlencode(params)
        if method == 'domain':
            address = domain
            if ingress.get('address'):
                edge = ipaddress.ip_address(ingress['address'])
                if not edge.is_global:
                    raise ValueError('a public ingress IP is required')
                address = str(edge)
            authority = f'[{address}]' if ':' in address else address
            params.update(sni=domain, fp='chrome', alpn='http/1.1', insecure='0')
            link = (f'vless://{identity}@{authority}:443?' + urllib.parse.urlencode(params)
                    + '#' + urllib.parse.quote(name, safe=''))
        else:
            link = recipe(base, method, ingress['address'], server_name=domain,
                          ech_config=ingress.get('ech_config'), name=name)
        node = {'link': link, 'auto': False}
        if method in ('ipv6', 'domain'):
            node['outbound'] = {
                'type': 'vless', 'tag': name,
                'server': address if method == 'domain' else str(ipaddress.ip_address(ingress['address'])),
                'server_port': 443, 'uuid': identity,
                'tls': {'enabled': True, 'server_name': domain, 'alpn': ['http/1.1'],
                        'utls': {'enabled': True, 'fingerprint': 'chrome'}},
                'transport': {'type': 'ws', 'path': channel['path'], 'headers': {'Host': domain}}}
        result.append(copy.deepcopy(node))
    return result
