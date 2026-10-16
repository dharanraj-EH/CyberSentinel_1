"""Explicit local assessment allowlist and exclusion policy."""
import ipaddress
import json
from urllib.parse import urlsplit


class ScopePolicy:
    def __init__(self, root):
        self.path = root / 'scope.json'

    def read(self):
        if self.path.exists():
            return json.loads(self.path.read_text(encoding='utf-8'))
        return {'approved': ['127.0.0.1', 'localhost'], 'excluded': []}

    def save(self, approved, excluded):
        for entry in approved + excluded:
            self.parse(entry)
        self.path.write_text(json.dumps({'approved': approved, 'excluded': excluded}, indent=2), encoding='utf-8')

    @staticmethod
    def parse(value):
        value = value.strip().lower()
        if '://' in value:
            from .web_assessment import origin
            return ('origin', origin(value))
        try:
            network = ipaddress.ip_network(value, strict=False)
            if network.num_addresses > 256:
                raise ValueError('Network scopes are limited to 256 addresses.')
            return ('network', network)
        except ValueError:
            if '/' in value or not value or value.startswith('-') or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789.-' for c in value):
                raise ValueError('Scope must be a hostname, IP, CIDR up to 256 addresses, or HTTP(S) origin.')
            return ('hostname', value)

    def permits(self, target):
        candidate = self.parse(target)
        policy = self.read()
        if candidate[0] == 'network':
            for entry in policy['excluded']:
                kind, denied = self.parse(entry)
                if kind == 'network' and candidate[1].version == denied.version and candidate[1].overlaps(denied):
                    return False
        # An excluded address also excludes approved hostnames resolving to it.
        host = candidate[1][1] if candidate[0] == 'origin' else (candidate[1] if candidate[0] == 'hostname' else None)
        if host:
            import socket
            try:
                addresses = {entry[4][0] for entry in socket.getaddrinfo(host, None)}
            except socket.gaierror:
                addresses = set()
            for entry in policy['excluded']:
                kind, denied = self.parse(entry)
                if kind == 'network' and any(ipaddress.ip_address(address) in denied for address in addresses):
                    return False
        def matches(entry):
            kind, allowed = self.parse(entry)
            current_kind, current = candidate
            if kind == current_kind:
                if kind == 'network':
                    return current.version == allowed.version and current.subnet_of(allowed)
                return current == allowed
            if current_kind == 'origin':
                host = current[1]
                if kind == 'hostname':
                    return host == allowed
                if kind == 'network':
                    try:
                        return ipaddress.ip_address(host) in allowed
                    except ValueError:
                        return False
            return False
        return any(matches(item) for item in policy['approved']) and not any(matches(item) for item in policy['excluded'])
