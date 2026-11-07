from app.core.scope_manager import ScopeError, validate_domain_in_scope, validate_url_in_scope
from app.models.scope import ScopeRecord


def scope(**overrides):
    values = dict(id=1, root_domain="example.com", include_subdomains=True, excluded_subdomains=["private.example.com"],
                  authorization_notes="Authorized test", authorization_confirmed=True, created_at="2026-01-01T00:00:00+00:00")
    values.update(overrides)
    return ScopeRecord(**values)


def test_accepts_root_and_authorized_subdomain_without_network_lookup():
    assert validate_domain_in_scope("www.example.com", scope(), resolve=False) == "www.example.com"
    assert validate_domain_in_scope("EXAMPLE.COM", scope(), resolve=False) == "example.com"


def test_rejects_out_of_scope_and_excluded_hosts():
    for host in ("evil-example.com", "other.net", "private.example.com", "x.private.example.com"):
        try:
            validate_domain_in_scope(host, scope(), resolve=False)
        except ScopeError:
            continue
        raise AssertionError(f"accepted out-of-scope host: {host}")


def test_rejects_local_addresses_and_unsafe_urls():
    for host in ("127.0.0.1", "localhost"):
        try:
            validate_domain_in_scope(host, scope(), resolve=False)
        except ScopeError:
            continue
        raise AssertionError(f"accepted local host: {host}")
    try:
        validate_url_in_scope("https://user:pass@example.com/", scope(), resolve=False)
    except ScopeError:
        return
    raise AssertionError("accepted URL with embedded credentials")
