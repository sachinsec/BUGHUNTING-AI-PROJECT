import ipaddress
import re
import socket
from urllib.parse import urlsplit

from app.models.scope import ScopeRecord

_DOMAIN = re.compile(r"(?=.{1,253}\Z)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\Z")


class ScopeError(ValueError):
    """A target is malformed, unsafe, or outside the registered authorization scope."""


def normalize_domain(value: str) -> str:
    domain = value.strip().rstrip(".").lower()
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ScopeError("Invalid domain name") from exc
    if not _DOMAIN.fullmatch(domain):
        raise ScopeError("Enter a valid public DNS domain name")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        return domain
    raise ScopeError("IP address targets are not supported in this phase")


def validate_public_destination(host: str, resolve: bool = True) -> None:
    """Reject local, private, reserved, and metadata destinations, including DNS answers."""
    if host.lower().rstrip(".") in {"localhost", "metadata.google.internal", "metadata"}:
        raise ScopeError("Local and cloud metadata destinations are blocked")
    try:
        addresses = [ipaddress.ip_address(host)]
    except ValueError:
        if not resolve:
            return
        try:
            addresses = [ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)]
        except (OSError, ValueError) as exc:
            raise ScopeError("Target DNS could not be safely resolved") from exc
    if not addresses or any(not address.is_global for address in addresses):
        raise ScopeError("Private, local, link-local, and reserved IP addresses are blocked")


def validate_domain_in_scope(domain: str, scope: ScopeRecord, resolve: bool = True) -> str:
    normalized = normalize_domain(domain)
    root = normalize_domain(scope.root_domain)
    included_assets = set(getattr(scope, "included_assets", []))
    in_scope = normalized == root or normalized in included_assets or (scope.include_subdomains and normalized.endswith("." + root))
    if not in_scope:
        raise ScopeError("Target is outside the registered scope")
    exclusions = {normalize_domain(item) for item in scope.excluded_subdomains}
    if any(normalized == item or normalized.endswith("." + item) for item in exclusions):
        raise ScopeError("Target matches a program exclusion")
    validate_public_destination(normalized, resolve=resolve)
    return normalized


def validate_url_in_scope(url: str, scope: ScopeRecord, resolve: bool = True) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ScopeError("Only HTTP(S) URLs without embedded credentials are supported")
    if parsed.port not in {None, 80, 443}:
        raise ScopeError("Nonstandard destination ports are blocked")
    validate_domain_in_scope(parsed.hostname, scope, resolve=resolve)
    return url
