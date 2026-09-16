"""RFC 9092 geofeed discovery for long-tail cloud/hosting providers.

The long tail of hosting providers (IONOS, Hetzner, OVH, Scaleway, ...)
publishes no dedicated cloud-range feed, and hand-maintaining a list of their
geofeed URLs is exactly the kind of thing planning#179 forbids. RFC 9092 says
RIR whois records can carry a `geofeed:` attribute or a `remarks: Geofeed
<url>` line, so this script discovers the URLs from whois (via the RIPEstat
data API) instead of hardcoding them.

Standard library only. See long_tail.json for the seed ASNs and SCHEMA.md for
context on the wider dataset this feeds into.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import common  # noqa: E402  (path must be adjusted before this import)

RIPESTAT_ANNOUNCED_URL = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
RIPESTAT_WHOIS_URL = "https://stat.ripe.net/data/whois/data.json?resource={prefix}"

# Matches a `remarks:`/`Comment` style line such as "Geofeed https://example.com/geo.csv".
# Case-insensitive per RFC 9092 usage in the wild (e.g. "GeoFeed").
GEOFEED_VALUE_RE = re.compile(r"geofeed\s+(https?://\S+)", re.IGNORECASE)


# --------------------------------------------------------------------------
# Offline fixture naming (see spec: naming rule for --offline-dir)
# --------------------------------------------------------------------------


def offline_name_announced(asn: int) -> str:
    return f"announced-AS{asn}.json"


def offline_name_whois(prefix: str) -> str:
    return f"whois-{prefix.replace('/', '_')}.json"


def offline_name_probe(url: str) -> str:
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
    return f"probe-{digest}"


# --------------------------------------------------------------------------
# HTTP / offline fetch, with the "sleep before every call except the first"
# rate-limit discipline. Offline mode never sleeps.
# --------------------------------------------------------------------------


def make_caller(sleep_seconds: float, offline_dir: str | None):
    """Return call(url, offline_relpath) -> bytes.

    Sleeps `sleep_seconds` before every HTTP call after the first one made
    during this run (so there is no sleep before the very first call, and
    none after the very last, no matter where the run ends). In offline
    mode, no sleeping ever happens and the offline fixture is read instead
    of making a real request.
    """
    state = {"count": 0}

    def call(url: str, offline_relpath: str) -> bytes:
        if offline_dir is not None:
            path = os.path.join(offline_dir, offline_relpath)
            if not os.path.isfile(path):
                raise common.FeedError(f"{url}: offline fixture missing: {path}")
            with open(path, "rb") as fh:
                return fh.read()

        if state["count"] > 0:
            time.sleep(sleep_seconds)
        state["count"] += 1
        return common.fetch(url)

    return call


# --------------------------------------------------------------------------
# Step 1: announced prefixes
# --------------------------------------------------------------------------


def get_announced_prefixes(asn: int, caller) -> list[str]:
    url = RIPESTAT_ANNOUNCED_URL.format(asn=asn)
    body = caller(url, offline_name_announced(asn))
    obj = common.read_json(body, url)
    if obj.get("status") != "ok":
        raise common.FeedError(f"{url}: status={obj.get('status')!r}")
    data = obj.get("data")
    if not isinstance(data, dict) or "prefixes" not in data:
        raise common.FeedError(f"{url}: missing data.prefixes")
    prefixes = data["prefixes"]
    if not isinstance(prefixes, list):
        raise common.FeedError(f"{url}: data.prefixes is not a list")
    out = []
    for entry in prefixes:
        if isinstance(entry, dict) and "prefix" in entry:
            out.append(entry["prefix"])
    return out


def sort_ipv4_prefixes(prefix_strings: list[str]) -> list[str]:
    """Keep IPv4 prefixes and sort largest-aggregate-first (no truncation).

    Sort key: prefix length ascending (bigger blocks first), then network
    address ascending. Geofeeds live on the aggregate inetnum, so querying
    the biggest blocks first finds them soonest. This is also the full
    containment set a seed's announced_prefixes records: everything the ASN
    actually announces, not just the slice we queried whois for.
    """
    nets = []
    for p in prefix_strings:
        try:
            net = ipaddress.ip_network(p, strict=False)
        except ValueError:
            continue
        if net.version == 4:
            nets.append(net)
    nets.sort(key=lambda n: (n.prefixlen, int(n.network_address)))
    return [str(n) for n in nets]


def select_ipv4_prefixes(prefix_strings: list[str], max_prefixes: int) -> list[str]:
    """Keep IPv4 prefixes, sort largest-aggregate-first, truncate to max_prefixes."""
    return sort_ipv4_prefixes(prefix_strings)[:max_prefixes]


# --------------------------------------------------------------------------
# Step 2: whois per prefix, geofeed extraction
# --------------------------------------------------------------------------


def get_whois_records(prefix: str, caller) -> list:
    """Return the flat list of [entry, entry, ...] groups from whois + irr_records.

    A missing/malformed response is treated as "no records" rather than a
    hard failure - a single prefix's whois lookup failing should not abort
    the seed, just that prefix.
    """
    url = RIPESTAT_WHOIS_URL.format(prefix=prefix)
    body = caller(url, offline_name_whois(prefix))
    obj = common.read_json(body, url)
    data = obj.get("data")
    if not isinstance(data, dict):
        return []
    groups = list(data.get("records") or [])
    irr = data.get("irr_records")
    if irr:
        groups.extend(irr)
    return groups


def extract_geofeed_url(record_groups: list) -> str | None:
    """Pull a geofeed URL out of whois record groups, per RFC 9092.

    Recognises a `geofeed` key (value is the URL verbatim) and a
    `remarks`/`Comment`-style "Geofeed <url>" value, case-insensitively.
    Only http(s) URLs are accepted; a trailing '.' or ',' is stripped.
    """
    for group in record_groups:
        if not isinstance(group, list):
            continue
        for entry in group:
            if not isinstance(entry, dict):
                continue
            key = entry.get("key")
            value = entry.get("value")
            if value is None:
                continue
            value = str(value)

            candidate = None
            if key is not None and str(key).strip().lower() == "geofeed":
                candidate = value.strip()
            else:
                match = GEOFEED_VALUE_RE.search(value)
                if match:
                    candidate = match.group(1)

            if not candidate:
                continue
            candidate = candidate.rstrip(".,")
            if candidate.lower().startswith("http://") or candidate.lower().startswith("https://"):
                return candidate
    return None


# --------------------------------------------------------------------------
# Step 3: probe the discovered URL
# --------------------------------------------------------------------------


def probe_url_format(url: str, caller) -> tuple[str | None, bool]:
    """Fetch `url` and classify its body as json or csv.

    Returns (format, reachable). format is None when the URL could not be
    fetched at all (offline fixture missing, or a real fetch failure).
    """
    try:
        body = caller(url, offline_name_probe(url))
    except common.FeedError:
        return None, False
    try:
        json.loads(body)
        return "json", True
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        return "csv", True


# --------------------------------------------------------------------------
# Per-seed processing
# --------------------------------------------------------------------------


def process_seed(seed: dict, caller, max_prefixes: int) -> dict:
    provider = seed["provider"]
    asn = seed["asn"]
    detail = {
        "provider": provider,
        "asn": asn,
        "prefixes_queried": 0,
        "announced_prefixes": [],
        "found": None,
        "usable": None,
        "error": None,
    }

    try:
        raw_prefixes = get_announced_prefixes(asn, caller)
    except common.FeedError as exc:
        detail["error"] = str(exc)
        return detail

    announced_prefixes = sort_ipv4_prefixes(raw_prefixes)
    detail["announced_prefixes"] = announced_prefixes
    # usable is about containment, not discovery: a seed with no IPv4 announced
    # prefixes at all has no set to intersect a geofeed against, so nothing it
    # could ever find would be attributable. Set as soon as we know the
    # announced list, independent of whether a geofeed is found below.
    detail["usable"] = bool(announced_prefixes)
    prefixes = announced_prefixes[:max_prefixes]

    found_url = None
    found_prefix = None
    for prefix in prefixes:
        detail["prefixes_queried"] += 1
        try:
            groups = get_whois_records(prefix, caller)
        except common.FeedError as exc:
            print(f"discover_geofeeds: whois lookup failed for {prefix}: {exc}", file=sys.stderr)
            continue
        url = extract_geofeed_url(groups)
        if url:
            found_url = url
            found_prefix = prefix
            break

    if found_url is None:
        return detail

    fmt, reachable = probe_url_format(found_url, caller)
    detail["found"] = {
        "url": found_url,
        "at_prefix": found_prefix,
        "format": fmt,
        "reachable": reachable,
        "at_prefix_announced_by_seed": found_prefix in announced_prefixes,
    }
    return detail


# --------------------------------------------------------------------------
# Seeds file loading
# --------------------------------------------------------------------------


def load_seeds(path: str) -> list[dict]:
    with open(path, "r", encoding="utf-8") as fh:
        obj = json.load(fh)
    seeds = obj["seeds"]
    if not isinstance(seeds, list):
        raise ValueError("'seeds' is not a list")
    for seed in seeds:
        if "provider" not in seed or "asn" not in seed:
            raise ValueError(f"seed entry missing provider/asn: {seed!r}")
        int(seed["asn"])  # validate shape
    return seeds


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def run(seeds: list[dict], caller, max_prefixes: int) -> tuple[list[dict], list[dict], int]:
    """Process every seed. Returns (detail_list, geofeeds_list, seeds_failed)."""
    details = []
    geofeeds = []
    seeds_failed = 0
    for seed in seeds:
        detail = process_seed(seed, caller, max_prefixes)
        details.append(detail)
        if detail["error"] is not None:
            seeds_failed += 1
            print(
                f"discover_geofeeds: seed {detail['provider']} (AS{detail['asn']}) failed: {detail['error']}",
                file=sys.stderr,
            )
        elif detail["found"] is not None and detail["found"]["reachable"] and detail["usable"]:
            geofeeds.append(
                {
                    "provider": detail["provider"],
                    "url": detail["found"]["url"],
                    "format": detail["found"]["format"],
                    "announced_prefixes": detail["announced_prefixes"],
                }
            )
    geofeeds.sort(key=lambda g: g["provider"])
    return details, geofeeds, seeds_failed


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Discover RFC 9092 geofeed URLs for long-tail hosting providers via RIR whois.",
    )
    parser.add_argument("--out", required=True, help="Path to write the discovery result JSON.")
    parser.add_argument(
        "--seeds",
        default=None,
        help="Path to the seed ASN list (default: long_tail.json next to this script).",
    )
    parser.add_argument(
        "--max-prefixes",
        type=int,
        default=25,
        help="Max announced prefixes to query whois for, per seed (default: 25).",
    )
    parser.add_argument(
        "--sleep",
        type=float,
        default=1.0,
        help="Seconds to sleep between RIPEstat calls (default: 1.0). Ignored with --offline-dir.",
    )
    parser.add_argument(
        "--offline-dir",
        default=None,
        help="Read canned RIPEstat/probe responses from this directory instead of the network.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    seeds_path = args.seeds
    if seeds_path is None:
        seeds_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "long_tail.json")

    try:
        seeds = load_seeds(seeds_path)
    except (OSError, json.JSONDecodeError, ValueError, KeyError, TypeError) as exc:
        print(f"discover_geofeeds: cannot load seeds file {seeds_path}: {exc}", file=sys.stderr)
        return 1

    caller = make_caller(args.sleep, args.offline_dir)

    details, geofeeds, seeds_failed = run(seeds, caller, args.max_prefixes)
    seeds_queried = len(seeds)

    if seeds_queried > 0 and seeds_failed == seeds_queried:
        print(
            "discover_geofeeds: every seed failed to query - total outage, "
            "not writing a result that would erase a previous good file",
            file=sys.stderr,
        )
        return 1

    result = {
        "_comment": [
            "announced_prefixes on each entry is a CONTAINMENT filter, not decoration: a",
            "geofeed found at a prefix the seed ASN announces can still describe space it",
            "announces without owning (AS20473/vultr announces 44.33.0.0/16, part of ARDC's",
            "AMPRNet). Consumers MUST intersect a geofeed's prefixes against announced_prefixes before attributing any record to provider.",
        ],
        "generated_at": common.utcnow(),
        "seeds_queried": seeds_queried,
        "seeds_failed": seeds_failed,
        "geofeeds": geofeeds,
        "detail": details,
    }
    common.write_json(args.out, result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
