"""Shared helpers for the cloud range dataset pipeline.

Standard library only, deliberately: this runs in CI against nine third-party
endpoints and is consumed by a safety gate. Adding a dependency here would mean
auditing and pinning it for the sake of code that `urllib` already covers.
"""

from __future__ import annotations

import gzip
import hashlib
import ipaddress
import json
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

USER_AGENT = "constellus-binaries cloud-range mirror (+https://github.com/SeriesOfTubez/constellus-binaries)"

RETRY_STATUS = {429, 500, 502, 503, 504}


class FeedError(RuntimeError):
    """A feed could not be fetched, or did not look like what it should.

    Raised rather than swallowed on purpose. A feed that changed shape must fail
    this build loudly; failing soft here is exactly the ipapi.is failure mode
    this pipeline exists to avoid (planning#178).
    """


def utcnow() -> str:
    """Timestamp in the one format the dataset uses: RFC 3339, UTC, seconds."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def fetch(url: str, *, timeout: int = 60, attempts: int = 3) -> bytes:
    """GET `url`, retrying transient failures with a backoff.

    Returns the raw body. Raises FeedError if every attempt failed.
    """
    last: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status != 200:
                    raise FeedError(f"{url}: HTTP {resp.status}")
                return resp.read()
        except urllib.error.HTTPError as exc:
            last = exc
            if exc.code not in RETRY_STATUS:
                raise FeedError(f"{url}: HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last = exc
        if attempt < attempts:
            time.sleep(2**attempt)
    raise FeedError(f"{url}: failed after {attempts} attempts: {last}")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalise_cidr(value: str) -> tuple[str, int]:
    """Canonicalise a CIDR string.

    Returns `(prefix, ip_version)`. Host bits are cleared and IPv6 is written in
    its canonical compressed form, so two feeds spelling the same range
    differently produce the same record. Raises ValueError on junk, which the
    caller turns into a FeedError.
    """
    net = ipaddress.ip_network(value.strip(), strict=False)
    return str(net), net.version


def read_json(data: bytes, url: str) -> dict:
    try:
        return json.loads(data)
    except json.JSONDecodeError as exc:
        raise FeedError(f"{url}: body is not JSON: {exc}") from exc


def require_keys(obj: dict, keys: list[str], url: str) -> None:
    """Assert a feed still has the keys we parse. A shape change fails here."""
    missing = [k for k in keys if k not in obj]
    if missing:
        raise FeedError(f"{url}: missing expected key(s) {missing} - feed shape changed")


def write_json(path: str, obj) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, indent=2, sort_keys=False)
        fh.write("\n")


def write_gzip(path: str, data: bytes) -> None:
    """Write gzip with mtime=0 so identical input yields an identical file."""
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz:
            gz.write(data)
