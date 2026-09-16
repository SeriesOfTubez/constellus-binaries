#!/usr/bin/env python3
"""Normalise published cloud provider IP range feeds into one NDJSON dataset.

Standard library only. See SCHEMA.md for the output format and common.py for
shared fetch/hash/write helpers. Driven entirely by sources.json - adding a
provider means adding a parser branch here and a registry entry there.
"""

from __future__ import annotations

import argparse
import bisect
import csv
import ipaddress
import json
import os
import sys

import common
from common import FeedError

VALID_CLASSES = {"compute", "edge", "storage", "managed", "unknown"}


# ---------------------------------------------------------------------------
# Fetching (network or offline)
# ---------------------------------------------------------------------------


def _ext_for(parser: str) -> str:
    if parser == "plaintext_cidr":
        return ".txt"
    if parser == "geofeed_csv":
        return ".csv"
    return ".json"


def _fetch_source_bytes(source: dict, *, offline_dir: str | None) -> list[bytes]:
    """Return the list of raw bodies for a source (len 1, or 2 for cloudflare)."""
    url = source["url"]
    urls = url if isinstance(url, list) else [url]
    ext = _ext_for(source["parser"])
    sid = source["id"]

    bodies: list[bytes] = []
    if offline_dir is not None:
        for i, u in enumerate(urls):
            if len(urls) > 1:
                path = os.path.join(offline_dir, f"{sid}-{i}{ext}")
            else:
                path = os.path.join(offline_dir, f"{sid}{ext}")
            try:
                with open(path, "rb") as fh:
                    bodies.append(fh.read())
            except OSError as exc:
                raise FeedError(f"{sid}: offline file {path} unreadable: {exc}") from exc
    else:
        for u in urls:
            bodies.append(common.fetch(u))
    return bodies


def _raw_paths(source: dict, out_dir: str) -> list[str]:
    url = source["url"]
    urls = url if isinstance(url, list) else [url]
    ext = _ext_for(source["parser"])
    sid = source["id"]
    raw_dir = os.path.join(out_dir, "raw")
    if len(urls) > 1:
        return [os.path.join(raw_dir, f"{sid}-{i}{ext}") for i in range(len(urls))]
    return [os.path.join(raw_dir, f"{sid}{ext}")]


def _write_raw(source: dict, bodies: list[bytes], out_dir: str) -> None:
    for path, body in zip(_raw_paths(source, out_dir), bodies):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(body)


# ---------------------------------------------------------------------------
# Parsers - each returns a list of raw records:
#   (prefix_str, service_raw, region, class_key)
# class_key is the string used to resolve service_class from `classes`.
# The caller fills in provider/source/ip_version/normalised prefix.
# ---------------------------------------------------------------------------


def _parse_aws(body: bytes, url: str) -> tuple[list[tuple], str]:
    obj = common.read_json(body, url)
    common.require_keys(obj, ["syncToken", "prefixes", "ipv6_prefixes"], url)
    recs = []
    for p in obj["prefixes"]:
        service = p.get("service")
        recs.append((p.get("ip_prefix"), service, p.get("region"), service))
    for p in obj["ipv6_prefixes"]:
        service = p.get("service")
        recs.append((p.get("ipv6_prefix"), service, p.get("region"), service))
    return recs, str(obj["syncToken"])


def _parse_azure(body: bytes, url: str) -> tuple[list[tuple], str]:
    obj = common.read_json(body, url)
    common.require_keys(obj, ["changeNumber", "values"], url)
    recs = []
    for v in obj["values"]:
        props = v.get("properties", {})
        prefixes = props.get("addressPrefixes")
        if not prefixes:
            continue
        name = v.get("name")
        system_service = props.get("systemService", "")
        region = props.get("region") or None
        for prefix in prefixes:
            recs.append((prefix, name, region, system_service))
    return recs, str(obj["changeNumber"])


def _parse_oci(body: bytes, url: str) -> tuple[list[tuple], str]:
    obj = common.read_json(body, url)
    common.require_keys(obj, ["last_updated_timestamp", "regions"], url)
    recs = []
    for r in obj["regions"]:
        region = r.get("region")
        for c in r.get("cidrs", []) or []:
            cidr = c.get("cidr")
            for tag in c.get("tags", []) or []:
                recs.append((cidr, tag, region, tag))
        for c in r.get("ipv6_cidrs", []) or []:
            cidr = c.get("cidr")
            for tag in c.get("tags", []) or []:
                recs.append((cidr, tag, region, tag))
    return recs, obj["last_updated_timestamp"]


def _parse_gcp(body: bytes, url: str) -> tuple[list[tuple], str]:
    obj = common.read_json(body, url)
    common.require_keys(obj, ["syncToken", "prefixes"], url)
    recs = []
    for p in obj["prefixes"]:
        prefix = p.get("ipv4Prefix") or p.get("ipv6Prefix")
        service = p.get("service")
        recs.append((prefix, service, p.get("scope"), service))
    return recs, str(obj["syncToken"])


def _parse_google(body: bytes, url: str) -> tuple[list[tuple], str]:
    obj = common.read_json(body, url)
    common.require_keys(obj, ["syncToken", "prefixes"], url)
    recs = []
    for p in obj["prefixes"]:
        prefix = p.get("ipv4Prefix") or p.get("ipv6Prefix")
        recs.append((prefix, None, None, ""))
    return recs, str(obj["syncToken"])


def _parse_plaintext_cidr(body: bytes, url: str) -> tuple[list[tuple], str]:
    text = body.decode("utf-8")
    recs = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        recs.append((stripped, None, None, ""))
    return recs, None


def _parse_fastly(body: bytes, url: str) -> tuple[list[tuple], str]:
    obj = common.read_json(body, url)
    common.require_keys(obj, ["addresses", "ipv6_addresses"], url)
    recs = []
    for prefix in obj["addresses"]:
        recs.append((prefix, None, None, ""))
    for prefix in obj["ipv6_addresses"]:
        recs.append((prefix, None, None, ""))
    return recs, None


def _parse_geofeed_csv(body: bytes, url: str) -> tuple[list[tuple], str]:
    text = body.decode("utf-8")
    recs = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        row = next(csv.reader([line]))
        if len(row) < 1 or not row[0].strip():
            raise FeedError(f"{url}: malformed geofeed row {row!r}")
        prefix = row[0].strip()
        region = row[2].strip() if len(row) > 2 and row[2].strip() else None
        recs.append((prefix, None, region, ""))
    return recs, None


def _parse_vultr(body: bytes, url: str) -> tuple[list[tuple], str]:
    obj = common.read_json(body, url)
    common.require_keys(obj, ["updated", "subnets"], url)
    recs = []
    for s in obj["subnets"]:
        recs.append((s.get("ip_prefix"), None, s.get("region"), ""))
    return recs, obj["updated"]


PARSERS = {
    "aws": _parse_aws,
    "azure": _parse_azure,
    "oci": _parse_oci,
    "gcp": _parse_gcp,
    "google": _parse_google,
    "plaintext_cidr": _parse_plaintext_cidr,
    "fastly": _parse_fastly,
    "geofeed_csv": _parse_geofeed_csv,
    "vultr": _parse_vultr,
}


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


def _classify(class_key: str | None, classes: dict) -> str:
    key = class_key if class_key is not None else ""
    catch_all = classes.get("catch_all", [])
    class_map = classes.get("map", {})
    if key in catch_all:
        result = "unknown"
    elif key in class_map:
        result = class_map[key]
    else:
        result = classes.get("default")
    if result not in VALID_CLASSES:
        raise FeedError(
            f"service_class {result!r} is not one of {sorted(VALID_CLASSES)} - "
            f"sources.json classes entry is malformed (key {key!r})"
        )
    return result


# ---------------------------------------------------------------------------
# Per-source pipeline
# ---------------------------------------------------------------------------


def _display_url(source: dict):
    return source["url"]


def _process_source(
    source: dict,
    *,
    offline_dir: str | None,
    out_dir: str,
    previous_counts: dict[str, int],
) -> tuple[list[dict], dict]:
    sid = source["id"]
    url = source["url"]
    url_for_errors = url if isinstance(url, str) else ",".join(url)
    parser_name = source["parser"]
    parser = PARSERS.get(parser_name)
    if parser is None:
        raise FeedError(f"{sid}: unknown parser {parser_name!r}")

    try:
        bodies = _fetch_source_bytes(source, offline_dir=offline_dir)
    except FeedError as exc:
        raise FeedError(str(exc) if str(exc).startswith(f"{sid}:") else f"{sid}: {exc}") from exc

    _write_raw(source, bodies, out_dir)

    fetched_at = common.utcnow()

    try:
        if parser_name == "plaintext_cidr":
            raw_recs: list[tuple] = []
            change_token = None
            for body in bodies:
                sub_recs, _ = parser(body, url_for_errors)
                raw_recs.extend(sub_recs)
        else:
            raw_recs, change_token = parser(bodies[0], url_for_errors)
    except FeedError as exc:
        raise FeedError(str(exc) if str(exc).startswith(f"{sid}:") else f"{sid}: {exc}") from exc
    except (KeyError, TypeError, AttributeError) as exc:
        raise FeedError(f"{sid}: unexpected feed shape: {exc}") from exc

    classes = source["classes"]
    provider = source["provider"]

    records: list[dict] = []
    for prefix_raw, service_raw, region, class_key in raw_recs:
        if prefix_raw is None:
            raise FeedError(f"{sid}: record missing a prefix value")
        try:
            prefix, ip_version = common.normalise_cidr(prefix_raw)
        except ValueError as exc:
            raise FeedError(f"{sid}: invalid CIDR {prefix_raw!r}: {exc}") from exc
        region_norm = region if region else None
        service_class = _classify(class_key, classes)
        records.append(
            {
                "prefix": prefix,
                "ip_version": ip_version,
                "provider": provider,
                "service_raw": service_raw,
                "service_class": service_class,
                "region": region_norm,
                "source": sid,
            }
        )

    # Containment filter for discovered geofeeds.
    #
    # A geofeed URL found in RIR whois describes whatever space its publisher
    # chose to describe, which is not necessarily the seed provider's. Live
    # discovery hit exactly this: AS20473 (Vultr) announces 44.33.0.0/16 out of
    # AMPRNet, whose whois points at ARDC's geofeed - a feed covering thousands
    # of prefixes belonging to other organisations entirely. Ingesting that
    # wholesale would attribute all of them to `provider: vultr`.
    #
    # So a discovered feed is trusted only where it overlaps the space the seed
    # ASN actually announces. Attribution we cannot substantiate is dropped
    # rather than flagged - the same posture the product applies to findings.
    contain_within = source.get("contain_within")
    if contain_within is not None:
        kept = [r for r in records if _contained(r["prefix"], contain_within)]
        dropped_n = len(records) - len(kept)
        if dropped_n:
            print(
                f"note: {sid}: dropped {dropped_n} of {len(records)} record(s) "
                f"outside the seed ASN's announced space",
                file=sys.stderr,
            )
        records = kept

    count = len(records)
    min_prefixes = source.get("min_prefixes", 0)
    if count < min_prefixes:
        raise FeedError(
            f"{sid}: record count {count} is below the min_prefixes floor {min_prefixes}"
        )

    # Discovered geofeeds are exempt from the collapse check: they are
    # `unknown`-class, nothing depends on them, and their size moves with the
    # seed ASN's announcements. Failing the daily build over one would be
    # disproportionate - the count is in the manifest to be read instead.
    if sid in previous_counts and source.get("tier") != "B-discovered":
        old = previous_counts[sid]
        if old > 0 and count < old * 0.75:
            raise FeedError(
                f"{sid}: record count dropped more than 25% (old={old}, new={count})"
            )

    if len(bodies) > 1:
        concatenated = b"".join(bodies)
        manifest_entry = {
            "id": sid,
            "url": url,
            "fetched_at": fetched_at,
            "sha256": common.sha256_bytes(concatenated),
            "bytes": len(concatenated),
            "change_token": change_token,
            "record_count": count,
        }
    else:
        manifest_entry = {
            "id": sid,
            "url": url,
            "fetched_at": fetched_at,
            "sha256": common.sha256_bytes(bodies[0]),
            "bytes": len(bodies[0]),
            "change_token": change_token,
            "record_count": count,
        }

    return records, manifest_entry


# ---------------------------------------------------------------------------
# Discovered geofeeds
# ---------------------------------------------------------------------------


def _build_containment(prefixes: list[str], sid: str) -> dict[int, tuple]:
    """Index a seed ASN's announced prefixes for containment tests.

    A seed can announce thousands of prefixes (Vultr: ~1700), and a discovered
    geofeed can carry thousands of records, so a linear scan per record is a
    real cost. Collapsing to a minimal non-overlapping set and bisecting makes
    each lookup O(log n): with no overlaps, at most one announced network can
    possibly contain a given prefix - the last one starting at or below it.
    """
    by_version: dict[int, list] = {4: [], 6: []}
    for p in prefixes:
        try:
            net = ipaddress.ip_network(p, strict=False)
        except ValueError as exc:
            raise FeedError(f"{sid}: invalid announced prefix {p!r}: {exc}") from exc
        by_version[net.version].append(net)

    index: dict[int, tuple] = {}
    for version, nets in by_version.items():
        collapsed = sorted(
            ipaddress.collapse_addresses(nets), key=lambda n: int(n.network_address)
        )
        index[version] = (
            [int(n.network_address) for n in collapsed],
            [int(n.broadcast_address) for n in collapsed],
        )
    return index


def _contained(prefix: str, index: dict[int, tuple]) -> bool:
    net = ipaddress.ip_network(prefix, strict=False)
    starts, ends = index.get(net.version, ([], []))
    if not starts:
        return False
    lo = int(net.network_address)
    i = bisect.bisect_right(starts, lo) - 1
    return i >= 0 and int(net.broadcast_address) <= ends[i]


def _load_discovered(path: str | None, sources: list[dict]) -> list[dict]:
    if path is None or not os.path.exists(path):
        return []
    with open(path, "rb") as fh:
        body = fh.read()
    try:
        obj = json.loads(body)
        common.require_keys(obj, ["generated_at", "geofeeds"], path)

        existing_ids = {s["id"] for s in sources}
        seen_ids: set[str] = set()
        extra_sources: list[dict] = []
        for entry in obj["geofeeds"]:
            provider = entry["provider"]
            fmt = entry["format"]
            sid = "geofeed-" + provider
            if sid in seen_ids or sid in existing_ids:
                continue
            seen_ids.add(sid)
            if fmt == "csv":
                p = "geofeed_csv"
            elif fmt == "json":
                p = "vultr"
            else:
                raise FeedError(f"{path}: geofeed {provider!r} has unknown format {fmt!r}")

            # A discovered feed without a containment set would be ingested
            # unfiltered, which is the misattribution case this guards against.
            announced = entry.get("announced_prefixes")
            if not announced:
                raise FeedError(
                    f"{path}: geofeed {provider!r} has no announced_prefixes - "
                    "refusing to ingest an unbounded discovered feed"
                )

            extra_sources.append(
                {
                    "id": sid,
                    "provider": provider,
                    "tier": "B-discovered",
                    "parser": p,
                    "url": entry["url"],
                    "change_token": None,
                    # Floor of 0: a discovered feed legitimately contributing
                    # nothing after containment must not break the daily build.
                    # Its count is visible in the manifest either way.
                    "min_prefixes": 0,
                    "classes": {"catch_all": [], "map": {}, "default": "unknown"},
                    "contain_within": _build_containment(announced, sid),
                }
            )
        return extra_sources
    except json.JSONDecodeError as exc:
        raise FeedError(f"{path}: malformed discovered geofeeds file: {exc}") from exc
    except (KeyError, TypeError, AttributeError) as exc:
        raise FeedError(f"{path}: malformed discovered geofeeds file: {exc}") from exc


# ---------------------------------------------------------------------------
# Sorting / serialisation
# ---------------------------------------------------------------------------


def _prefix_sort_key(prefix: str):
    net = ipaddress.ip_network(prefix, strict=False)
    return (int(net.network_address), net.prefixlen)


def _sort_key(rec: dict):
    return (
        rec["provider"],
        rec["ip_version"],
        _prefix_sort_key(rec["prefix"]),
        rec["service_raw"] or "",
    )


def _serialise(records: list[dict]) -> tuple[bytes, int, list[dict]]:
    records_sorted = sorted(records, key=_sort_key)

    deduped: list[dict] = []
    seen: set[tuple] = set()
    dropped = 0
    for rec in records_sorted:
        key = (
            rec["prefix"],
            rec["ip_version"],
            rec["provider"],
            rec["service_raw"],
            rec["service_class"],
            rec["region"],
            rec["source"],
        )
        if key in seen:
            dropped += 1
            continue
        seen.add(key)
        deduped.append(rec)

    lines = [
        json.dumps(
            {
                "prefix": rec["prefix"],
                "ip_version": rec["ip_version"],
                "provider": rec["provider"],
                "service_raw": rec["service_raw"],
                "service_class": rec["service_class"],
                "region": rec["region"],
                "source": rec["source"],
            },
            separators=(",", ":"),
        )
        for rec in deduped
    ]
    text = "\n".join(lines) + "\n" if lines else ""
    body = text.encode("utf-8")
    return body, dropped, deduped


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parser.add_argument(
        "--sources", default=os.path.join(script_dir, "sources.json")
    )
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--offline-dir", default=None)
    parser.add_argument("--previous-manifest", default=None)
    parser.add_argument("--discovered", default=None)
    args = parser.parse_args(argv)

    try:
        with open(args.sources, "r", encoding="utf-8") as fh:
            registry = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: could not load sources file {args.sources}: {exc}", file=sys.stderr)
        return 1

    sources = list(registry.get("sources", []))

    previous_manifest = None
    previous_counts: dict[str, int] = {}
    if args.previous_manifest and os.path.exists(args.previous_manifest):
        try:
            with open(args.previous_manifest, "r", encoding="utf-8") as fh:
                previous_manifest = json.load(fh)
            for entry in previous_manifest.get("sources", []):
                previous_counts[entry["id"]] = entry["record_count"]
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: could not load previous manifest: {exc}", file=sys.stderr)
            return 1

    try:
        extra_sources = _load_discovered(args.discovered, sources)
    except FeedError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    all_sources = sources + extra_sources

    all_records: list[dict] = []
    manifest_sources: list[dict] = []

    for source in all_sources:
        sid = source.get("id", "<unknown>")
        try:
            records, manifest_entry = _process_source(
                source,
                offline_dir=args.offline_dir,
                out_dir=args.out_dir,
                previous_counts=previous_counts,
            )
        except FeedError as exc:
            msg = str(exc)
            if sid not in msg:
                msg = f"{sid}: {msg}"
            print(f"error: {msg}", file=sys.stderr)
            return 1
        all_records.extend(records)
        manifest_sources.append(manifest_entry)

    body, dropped, deduped = _serialise(all_records)

    dataset_sha256 = common.sha256_bytes(body)

    ndjson_path = os.path.join(args.out_dir, "cloud-ranges.ndjson.gz")
    common.write_gzip(ndjson_path, body)

    manifest = {
        "schema_version": 1,
        "generated_at": common.utcnow(),
        "dataset_sha256": dataset_sha256,
        "record_count": len(deduped),
        "sources": manifest_sources,
    }
    manifest_path = os.path.join(args.out_dir, "manifest.json")
    common.write_json(manifest_path, manifest)

    changed = True
    if previous_manifest is not None:
        changed = previous_manifest.get("dataset_sha256") != dataset_sha256

    changed_str = "changed=true" if changed else "changed=false"
    print(changed_str)
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as fh:
            fh.write(changed_str + "\n")

    if dropped:
        print(f"note: dropped {dropped} exact-duplicate record(s)", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
