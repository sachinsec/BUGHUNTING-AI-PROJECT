from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from app.core.database import connect


def list_parameters(scope_id: int | None = None) -> dict:
    with connect() as db:
        historical = db.execute("SELECT scope_id, scan_id, url, simulated, discovered_at FROM historical_urls" +
                                (" WHERE scope_id = ?" if scope_id else ""), ((scope_id,) if scope_id else ())).fetchall()
        endpoints = db.execute("SELECT scope_id, scan_id, url, simulated, discovered_at FROM discovered_endpoints" +
                               (" WHERE scope_id = ?" if scope_id else ""), ((scope_id,) if scope_id else ())).fetchall()
    seen: set[tuple[int, str, str, bool]] = set()
    results = []
    for source, rows in (("historical_url", historical), ("crawled_endpoint", endpoints)):
        for row in rows:
            parsed = urlsplit(row["url"])
            query = parse_qsl(parsed.query, keep_blank_values=True)
            if not query:
                continue
            endpoint_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
            for name in sorted({key for key, _ in query if key}):
                simulated = bool(row["simulated"])
                key = (row["scope_id"], endpoint_url, name, simulated)
                if key in seen:
                    continue
                seen.add(key)
                parameterized = [(key_name, "{value}") for key_name, _ in query]
                results.append({"scope_id": row["scope_id"], "scan_id": row["scan_id"],
                                "endpoint_url": endpoint_url, "parameter_name": name,
                                "parameterized_url": urlunsplit((parsed.scheme, parsed.netloc, parsed.path,
                                                                 urlencode(parameterized), "")),
                                "source": source, "simulated": simulated,
                                "discovered_at": row["discovered_at"]})
    results.sort(key=lambda item: (item["endpoint_url"], item["parameter_name"], item["source"]))
    return {"count": len(results), "results": results}
