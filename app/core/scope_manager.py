import ipaddress
import json
import re
import socket
from urllib.parse import urlsplit

from app.models.scope import ScopeRecord

_DOMAIN = re.compile(r"(?=.{1,253}\Z)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\Z")


class ScopeError(ValueError):
    """A target is malformed, unsafe, or outside the registered authorization scope."""


def normalize_domain(value: str, allow_lab_hosts: bool = False) -> str:
    domain = value.strip().rstrip(".").lower()
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ScopeError("Invalid domain name") from exc
    try:
        address = ipaddress.ip_address(domain)
    except ValueError:
        address = None
    if address is not None:
        if allow_lab_hosts and (address.is_private or address.is_loopback) and not (address.is_link_local or address.is_reserved):
            return str(address)
        raise ScopeError("IP address targets are supported only for explicitly configured local labs")
    if allow_lab_hosts and domain == "localhost":
        return domain
    if not _DOMAIN.fullmatch(domain):
        raise ScopeError("Enter a valid public DNS domain name")
    return domain


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


def validate_lab_destination(host: str, resolve: bool = True) -> None:
    """Allow only localhost or literal loopback destinations; private LANs are not labs."""
    normalized = host.lower().rstrip(".")
    try:
        address = ipaddress.ip_address(normalized)
        addresses = [address]
    except ValueError:
        if normalized != "localhost":
            raise ScopeError("Local Lab mode accepts only localhost or literal loopback addresses")
        if not resolve:
            return
        try:
            addresses = [ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(normalized, None, type=socket.SOCK_STREAM)]
        except (OSError, ValueError) as exc:
            raise ScopeError("Local lab destination could not be resolved") from exc
    if not addresses or any(not item.is_loopback for item in addresses):
        raise ScopeError("Local Lab mode only permits destinations resolving exclusively to loopback")


def validate_domain_in_scope(domain: str, scope: ScopeRecord, resolve: bool = True) -> str:
    is_lab = bool(getattr(scope, "local_lab_mode", False))
    normalized = normalize_domain(domain, allow_lab_hosts=is_lab)
    root = normalize_domain(scope.root_domain, allow_lab_hosts=is_lab)
    included_assets = {normalize_domain(item, allow_lab_hosts=is_lab) for item in getattr(scope, "included_assets", [])}
    in_scope = normalized == root or normalized in included_assets or (scope.include_subdomains and normalized.endswith("." + root))
    if not in_scope:
        raise ScopeError("Target is outside the registered scope")
    exclusions = {normalize_domain(item, allow_lab_hosts=is_lab) for item in scope.excluded_subdomains}
    if any(normalized == item or normalized.endswith("." + item) for item in exclusions):
        raise ScopeError("Target matches a program exclusion")
    if is_lab:
        try:
            root_is_loopback = ipaddress.ip_address(root).is_loopback
        except ValueError:
            root_is_loopback = False
        if root != "localhost" and not root_is_loopback:
            raise ScopeError("Local Lab mode cannot authorize a public or private network domain")
        validate_lab_destination(normalized, resolve=resolve)
    else:
        validate_public_destination(normalized, resolve=resolve)
    return normalized


def validate_url_in_scope(url: str, scope: ScopeRecord, resolve: bool = True) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ScopeError("Only HTTP(S) URLs without embedded credentials are supported")
    if scope.local_lab_mode:
        if parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ScopeError("Local Lab only permits explicit loopback hosts")
        allowed_ports = set(getattr(scope, "local_lab_ports", []))
        if parsed.port is None or parsed.port not in allowed_ports:
            raise ScopeError("Local Lab URL must use an explicitly configured port")
        if parsed.hostname not in {scope.root_domain, *getattr(scope, "included_assets", [])}:
            raise ScopeError("Local Lab URL host is outside its explicitly configured hosts")
        validate_lab_destination(parsed.hostname, resolve=resolve)
        return url
    if parsed.port not in {None, 80, 443}:
        raise ScopeError("Nonstandard destination ports are blocked")
    validate_domain_in_scope(parsed.hostname, scope, resolve=resolve)
    return url


def validate_real_network_access(scope: ScopeRecord, target: str, resolve: bool = True,
                                 allow_local_lab: bool = True) -> str:
    """Gate public traffic on separate review; lab URLs must pin a loopback host and port."""
    from app.core.runtime_settings import get_scan_mode

    if get_scan_mode() == "local_lab" and not scope.local_lab_mode:
        raise ScopeError("LOCAL_LAB execution mode only permits a registered Local Lab scope")
    if not scope.authorization_confirmed:
        raise ScopeError("Explicit authorization confirmation is required")
    if scope.local_lab_mode:
        if not allow_local_lab:
            raise ScopeError("This external reconnaissance source is disabled for local lab scopes")
        if target.startswith(("http://", "https://")):
            return validate_url_in_scope(target, scope, resolve=resolve)
        raise ScopeError("Local Lab network operations must use an explicit loopback URL and configured port")
    # Check syntax, scope membership, and exclusions before reporting review state;
    # resolve DNS only after a matching approval has been found.
    normalized = validate_domain_in_scope(target, scope, resolve=False)
    from datetime import datetime, timezone
    from app.core.database import connect
    with connect() as db:
        reviews = db.execute("SELECT * FROM authorization_reviews WHERE scope_id=? ORDER BY id DESC", (scope.id,)).fetchall()
    if not reviews:
        raise ScopeError("Authorization review is missing; public reconnaissance is blocked")
    now = datetime.now(timezone.utc)
    matching = []
    for review in reviews:
        asset = normalize_domain(review["authorized_asset"])
        if normalized == asset or (review["allow_subdomains"] and normalized.endswith("." + asset)):
            matching.append(review)
    if not matching:
        raise ScopeError("Target is outside the exact asset approved for public reconnaissance")

    latest = matching[0]
    review_exclusions = json.loads(latest["excluded_assets"] or "[]")
    if any(normalized == item or normalized.endswith("." + item) for item in review_exclusions):
        raise ScopeError("Target matches an authorization review exclusion")
    if latest["status"] == "PENDING":
        raise ScopeError("Authorization review is pending; public reconnaissance is blocked")
    if latest["status"] == "REJECTED":
        raise ScopeError("Authorization was rejected; public reconnaissance is blocked")
    latest_expiry = datetime.fromisoformat(latest["expires_at"]) if latest["expires_at"] else None
    if latest_expiry and latest_expiry.tzinfo is None:
        latest_expiry = latest_expiry.replace(tzinfo=timezone.utc)
    if latest["status"] == "EXPIRED" or (latest_expiry and latest_expiry <= now):
        raise ScopeError("Authorization has expired; public reconnaissance is blocked")
    if latest["status"] != "APPROVED":
        raise ScopeError("Authorization review is not approved; public reconnaissance is blocked")
    return validate_domain_in_scope(normalized, scope, resolve=resolve)
