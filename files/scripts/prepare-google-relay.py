#!/usr/bin/env python3
"""Prepare pinned GooseRelay source and private templates without running it.

Use --archive offline, or explicitly --download (requires API AND codeload).
Private rendering additionally requires --config and --generate-key/--key-file.
No downloaded code is executed, built, installed, published or enabled.
"""
import argparse
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import tarfile
import urllib.parse
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "connectivity/google-relay-release.json"
MAX_ARCHIVE = 16 * 1024 * 1024
MAX_FILE = 4 * 1024 * 1024
MAX_EXPANDED = 32 * 1024 * 1024
DOMAIN = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z")


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()


def validate_download_url(url, hosts):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname not in hosts
            or parsed.username or parsed.password or parsed.port not in (None, 443)):
        raise ValueError("Source download attempted an unexpected host or protocol")


class SourceRedirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, hosts):
        self.hosts = hosts
        super().__init__()

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_download_url(newurl, self.hosts)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download_source(lock):
    hosts = set(lock["download_hosts"])
    validate_download_url(lock["source_url"], hosts)
    opener = urllib.request.build_opener(SourceRedirects(hosts))
    request = urllib.request.Request(lock["source_url"], headers={
        "User-Agent": "IranRebate-offline-preparation/1",
    })
    with opener.open(request, timeout=30) as response:
        validate_download_url(response.url, hosts)
        data = response.read(MAX_ARCHIVE + 1)
    if len(data) > MAX_ARCHIVE:
        raise ValueError("Source archive exceeds size limit")
    return data


def verified_source(data, lock):
    """Validate identity and every member before creating any output files."""
    if len(data) > MAX_ARCHIVE:
        raise ValueError("Source archive exceeds size limit")
    if hashlib.sha256(data).hexdigest() != lock["source_sha256"]:
        raise ValueError("Pinned source SHA-256 mismatch; no archive content accepted")
    files, names, expanded = {}, set(), 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for index, member in enumerate(archive):
            if index >= 4096:
                raise ValueError("Too many archive members")
            raw = member.name.rstrip("/")
            parts = PurePosixPath(raw).parts
            if (not parts or parts[0] != lock["archive_root"]
                    or raw.startswith("/") or "\\" in raw
                    or any(p in {"", ".", ".."} for p in raw.split("/"))
                    or any(ord(c) < 32 or ord(c) == 127 for c in raw)):
                raise ValueError("Unsafe archive path")
            if raw in names:
                raise ValueError("Duplicate archive member")
            names.add(raw)
            if not (member.isdir() or member.isfile()):
                raise ValueError("Links and special archive entries are forbidden")
            if member.isdir():
                continue
            if len(parts) < 2 or not 0 <= member.size <= MAX_FILE:
                raise ValueError("Invalid archive file or size")
            expanded += member.size
            if expanded > MAX_EXPANDED:
                raise ValueError("Expanded source exceeds size limit")
            handle = archive.extractfile(member)
            if handle is None:
                raise ValueError("Cannot read archive file")
            content = handle.read(MAX_FILE + 1)
            if len(content) != member.size:
                raise ValueError("Truncated or oversized archive file")
            files["/".join(parts[1:])] = content
    if not set(lock["required_files"]).issubset(files):
        raise ValueError("Pinned source is missing required files")
    if lock["license_copyright"].encode() not in files[lock["license_path"]]:
        raise ValueError("Unexpected upstream license")
    return files


def checked_public_host(value):
    if not isinstance(value, str) or value != value.strip():
        raise ValueError("Expected a public hostname or IP address")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        if not DOMAIN.fullmatch(value) or value.endswith((".example", ".invalid", ".test", ".localhost", ".example.com")):
            raise ValueError("Expected a real public hostname")
    else:
        if not address.is_global:
            raise ValueError("Private, reserved and local addresses are not allowed")
    return value


def checked_port(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 1024 <= value <= 65535:
        raise ValueError("Listen ports must be integers between 1024 and 65535")
    return value


def render_private(config, key, upstream_script):
    if not isinstance(config, dict):
        raise ValueError("Configuration must be an object")
    allowed = {"google_host", "sni", "socks_port", "script_keys", "exit_relay_url", "exit_listen_port"}
    if set(config) - allowed:
        raise ValueError("Unknown preparation configuration fields")
    if not re.fullmatch(r"[a-fA-F0-9]{64}", key):
        raise ValueError("Tunnel key must contain exactly 64 hexadecimal characters")
    google = checked_public_host(config.get("google_host", "216.239.38.120"))
    snis = config.get("sni", ["google.com", "www.google.com"])
    if not isinstance(snis, list) or not snis or len(snis) > 8:
        raise ValueError("sni must be a list of 1–8 Google domain names")
    for host in snis:
        if not isinstance(host, str) or not DOMAIN.fullmatch(host) or not (host == "google.com" or host.endswith(".google.com")):
            raise ValueError("Only explicitly configured Google SNI domains are supported")
    entries = config.get("script_keys", [])
    if not isinstance(entries, list) or not entries or len(entries) > 8:
        raise ValueError("Provide 1–8 existing Apps Script deployments")
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"id", "account"}:
            raise ValueError("Each script_keys entry needs id and account")
        if not isinstance(entry["id"], str) or not re.fullmatch(r"AKfycb[A-Za-z0-9_-]{44,194}", entry["id"]):
            raise ValueError("Provide a real deployment ID beginning AKfycb, not an editor URL")
        if entry["id"] in seen:
            raise ValueError("Duplicate deployment ID")
        seen.add(entry["id"])
        if not isinstance(entry["account"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", entry["account"]):
            raise ValueError("Use a short account label, not an email address")
    url = config.get("exit_relay_url", "")
    if not isinstance(url, str) or any(ord(c) < 33 or ord(c) == 127 for c in url):
        raise ValueError("Invalid exit relay URL")
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.path != "/tunnel"):
        raise ValueError("Exit relay must be an owned HTTPS /tunnel endpoint without credentials or query")
    checked_public_host(parsed.hostname)
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError("Invalid exit HTTPS port")
    marker = re.compile(r"const RELAY_URLS = \[.*?\];", re.DOTALL)
    if len(marker.findall(upstream_script)) != 1:
        raise ValueError("Pinned Apps Script RELAY_URLS layout changed")
    script = marker.sub(lambda match: "const RELAY_URLS = [\n  " + json.dumps(url) + ",\n];", upstream_script)
    client = {
        "socks_host": "127.0.0.1", "socks_port": checked_port(config.get("socks_port", 12982)),
        "google_host": google, "sni": snis, "script_keys": entries,
        "tunnel_key": key, "idle_slots_per_bucket": 1,
    }
    # The exit stays on localhost behind an operator-configured HTTPS reverse proxy.
    server = {"server_host": "127.0.0.1", "server_port": checked_port(config.get("exit_listen_port", 18443)), "tunnel_key": key}
    return {"client_config.json": json_bytes(client), "server_config.json": json_bytes(server), "Code.gs": script.encode()}


def secure_directory(path):
    path = Path(path).absolute()
    for part in [*reversed(path.parents), path]:
        if part.is_symlink():
            raise ValueError("Output path must not contain symbolic links")
        if part.exists() and not part.is_dir():
            raise ValueError("Output parent is not a directory")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.stat().st_mode & 0o077:
        raise ValueError("Output directory must be private (mode 0700)")
    return path


def write_same_or_new(path, content):
    """Never overwrite manual changes, secrets or symlinks on a repeat run."""
    secure_directory(path.parent)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
            raise ValueError("Existing output is not a private regular file")
        if path.read_bytes() != content:
            raise ValueError("Existing output differs; choose a fresh output directory")
        return
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(content)


def read_key(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
        raise ValueError("Key file must be a private regular file (mode 0600)")
    if path.stat().st_size > 128:
        raise ValueError("Key file is oversized")
    key = path.read_text().strip()
    if not re.fullmatch(r"[a-fA-F0-9]{64}", key):
        raise ValueError("Key file must contain 64 hexadecimal characters")
    return key


def prepare(data, lock, output, *, config=None, key_file=None, generate_key=False):
    files = verified_source(data, lock)
    private = None
    if config is not None:
        if bool(key_file) == bool(generate_key):
            raise ValueError("Private rendering requires exactly one of --key-file or --generate-key")
        existing_key = output / "private/tunnel.key"
        key = read_key(key_file) if key_file else (read_key(existing_key) if existing_key.exists() else secrets.token_hex(32))
        private = render_private(config, key, files["apps_script/Code.gs"].decode())
        # Persist the key before configs so an interrupted render can reuse it.
        private = {"tunnel.key": (key + "\n").encode(), **private}
    elif key_file or generate_key:
        raise ValueError("Key options require --config")
    output = secure_directory(output)
    write_same_or_new(output / "source.tar.gz", data)
    for name, content in files.items():
        write_same_or_new(output / "source" / name, content)
    if private is not None:
        for name, content in private.items():
            write_same_or_new(output / "private" / name, content)
    write_same_or_new(output / "source-lock.json", json_bytes(lock))
    report = {
        "schema": 1, "project": lock["project"], "commit": lock["commit"],
        "archive_sha256": hashlib.sha256(data).hexdigest(), "files_verified": len(files),
        "license": lock["license"], "stage": "source-and-templates-only",
        "binary_built": False, "upstream_code_executed": False, "service_enabled": False,
        "google_deployment_created": False,
    }
    write_same_or_new(output / "prepared.json", json_bytes(report))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--archive", type=Path, help="Previously verified source archive; no network needed")
    source.add_argument("--download", action="store_true", help="Explicitly fetch pinned archive (requires codeload redirect)")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--config", type=Path, help="Private prep configuration using connectivity/google-relay.example.json schema")
    keys = parser.add_mutually_exclusive_group()
    keys.add_argument("--key-file", type=Path, help="Existing mode0600 file; key never appears on stdout or command line")
    keys.add_argument("--generate-key", action="store_true", help="Generate once and preserve output/private/tunnel.key on rerun")
    args = parser.parse_args()
    try:
        lock = json.loads(LOCK.read_text())
        if args.archive and args.archive.stat().st_size > MAX_ARCHIVE:
            raise ValueError("Source archive exceeds size limit")
        data = args.archive.read_bytes() if args.archive else download_source(lock)
        output = args.output or ROOT / "offline-toolkit/google-relay" / lock["commit"]
        config = json.loads(args.config.read_text()) if args.config else None
        report = prepare(data, lock, output, config=config, key_file=args.key_file, generate_key=args.generate_key)
        print(json.dumps(report, ensure_ascii=False))
    except (OSError, ValueError, KeyError, tarfile.TarError) as error:
        # Do not print config values, URLs, upstream bodies or key-bearing exceptions.
        parser.exit(1, "Cannot prepare Google relay (" + type(error).__name__ + "): check local paths, private permissions, pinned checksum and configuration.\n")


if __name__ == "__main__":
    main()
