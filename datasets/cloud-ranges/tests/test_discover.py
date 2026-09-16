"""Tests for discover_geofeeds.py (RFC 9092 geofeed discovery, planning#179).

Runs entirely offline against the canned RIPEstat responses in
tests/fixtures/ripestat/ - no network access, no sleeping. See that
directory's files for the scenarios each one backs.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PKG_DIR = os.path.dirname(_HERE)  # datasets/cloud-ranges
if _PKG_DIR not in sys.path:
    sys.path.insert(0, _PKG_DIR)

import discover_geofeeds as dg  # noqa: E402
import common  # noqa: E402

FIXTURES_DIR = os.path.join(_HERE, "fixtures", "ripestat")


def write_seeds(tmpdir: str, seeds: list) -> str:
    path = os.path.join(tmpdir, "seeds.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"seeds": seeds}, fh)
    return path


class TestSelectIpv4Prefixes(unittest.TestCase):
    def test_filters_ipv6_and_sorts_largest_aggregate_first(self):
        with open(os.path.join(FIXTURES_DIR, "announced-AS20473.json"), encoding="utf-8") as fh:
            raw = json.load(fh)
        prefix_strings = [p["prefix"] for p in raw["data"]["prefixes"]]

        selected = dg.select_ipv4_prefixes(prefix_strings, max_prefixes=25)

        self.assertNotIn("2001:19f0::/32", selected)
        self.assertEqual(
            selected,
            ["45.32.0.0/16", "108.61.0.0/16", "45.63.0.0/18", "45.32.32.0/24"],
        )

    def test_max_prefixes_truncates(self):
        selected = dg.select_ipv4_prefixes(
            ["5.9.0.0/16", "78.46.0.0/15", "88.99.0.0/16", "136.243.0.0/16", "148.251.0.0/16"],
            max_prefixes=3,
        )
        self.assertEqual(selected, ["78.46.0.0/15", "5.9.0.0/16", "88.99.0.0/16"])

    def test_junk_prefix_strings_skipped(self):
        selected = dg.select_ipv4_prefixes(["not-a-prefix", "10.0.0.0/8"], max_prefixes=25)
        self.assertEqual(selected, ["10.0.0.0/8"])


class TestExtractGeofeedUrl(unittest.TestCase):
    def test_geofeed_key_form(self):
        records = [[{"key": "geofeed", "value": "https://geofeed.example.com/geo.csv", "comment": None}]]
        self.assertEqual(dg.extract_geofeed_url(records), "https://geofeed.example.com/geo.csv")

    def test_remarks_value_form_case_variant_and_trailing_period(self):
        records = [[{"key": "remarks", "value": "GeoFeed https://example.test/geo.csv.", "comment": None}]]
        self.assertEqual(dg.extract_geofeed_url(records), "https://example.test/geo.csv")

    def test_trailing_comma_stripped(self):
        records = [[{"key": "Comment", "value": "Geofeed https://example.test/geo.csv,", "comment": None}]]
        self.assertEqual(dg.extract_geofeed_url(records), "https://example.test/geo.csv")

    def test_non_http_scheme_ignored(self):
        records = [[{"key": "geofeed", "value": "ftp://example.test/geo.csv", "comment": None}]]
        self.assertIsNone(dg.extract_geofeed_url(records))

    def test_no_match_returns_none(self):
        records = [[{"key": "netname", "value": "SOMENET", "comment": None}]]
        self.assertIsNone(dg.extract_geofeed_url(records))

    def test_first_match_wins_across_groups(self):
        records = [
            [{"key": "netname", "value": "SOMENET", "comment": None}],
            [{"key": "geofeed", "value": "https://a.example/geo.csv", "comment": None}],
            [{"key": "geofeed", "value": "https://b.example/geo.csv", "comment": None}],
        ]
        self.assertEqual(dg.extract_geofeed_url(records), "https://a.example/geo.csv")


class TestOfflineNaming(unittest.TestCase):
    def test_announced_name(self):
        self.assertEqual(dg.offline_name_announced(24940), "announced-AS24940.json")

    def test_whois_name_replaces_slash(self):
        self.assertEqual(dg.offline_name_whois("45.15.99.0/24"), "whois-45.15.99.0_24.json")

    def test_probe_name_is_sha256_prefix(self):
        name = dg.offline_name_probe("https://geofeed.constant.com/")
        self.assertEqual(name, "probe-e7147808c0f72436")


class TestProbeUrlFormat(unittest.TestCase):
    def setUp(self):
        self.caller = dg.make_caller(sleep_seconds=0.0, offline_dir=FIXTURES_DIR)

    def test_json_body(self):
        fmt, reachable = dg.probe_url_format("https://geofeed.constant.com/", self.caller)
        self.assertEqual(fmt, "json")
        self.assertTrue(reachable)

    def test_csv_body(self):
        fmt, reachable = dg.probe_url_format("https://example.test/geo.csv", self.caller)
        self.assertEqual(fmt, "csv")
        self.assertTrue(reachable)

    def test_unreachable_missing_fixture(self):
        fmt, reachable = dg.probe_url_format("https://example.test/unreachable-geofeed", self.caller)
        self.assertIsNone(fmt)
        self.assertFalse(reachable)


class TestProcessSeed(unittest.TestCase):
    def setUp(self):
        self.caller = dg.make_caller(sleep_seconds=0.0, offline_dir=FIXTURES_DIR)

    def test_happy_path_vultr(self):
        detail = dg.process_seed({"provider": "vultr", "asn": 20473}, self.caller, max_prefixes=25)
        self.assertIsNone(detail["error"])
        self.assertIsNotNone(detail["found"])
        self.assertEqual(detail["found"]["url"], "https://geofeed.constant.com/")
        self.assertEqual(detail["found"]["at_prefix"], "45.32.0.0/16")
        self.assertEqual(detail["found"]["format"], "json")
        self.assertTrue(detail["found"]["reachable"])
        # Proves largest-aggregate-first: only the /16 whois fixture exists among
        # vultr's IPv4 prefixes, and it's the very first one queried.
        self.assertEqual(detail["prefixes_queried"], 1)
        # Containment fields (follow-up spec change).
        self.assertEqual(
            detail["announced_prefixes"],
            ["45.32.0.0/16", "108.61.0.0/16", "45.63.0.0/18", "45.32.32.0/24"],
        )
        self.assertTrue(detail["usable"])
        self.assertTrue(detail["found"]["at_prefix_announced_by_seed"])

    def test_empty_ipv4_announced_marks_unusable(self):
        # AS33333's announced-prefixes response has only an IPv6 prefix, so the
        # IPv4 containment set is empty: nothing to query whois for, and no
        # discovery could ever be attributed safely even if it happened.
        detail = dg.process_seed({"provider": "ipv6only", "asn": 33333}, self.caller, max_prefixes=25)
        self.assertIsNone(detail["error"])
        self.assertEqual(detail["announced_prefixes"], [])
        self.assertFalse(detail["usable"])
        self.assertIsNone(detail["found"])
        self.assertEqual(detail["prefixes_queried"], 0)

    def test_ordering_proof_isolated_offline_dir(self):
        # Point the offline dir at a fresh directory holding ONLY the announced
        # list and the aggregate's whois fixture - no other prefix's whois file
        # exists at all, so finding it in one query proves the aggregate (the
        # smallest-prefixlen /16) was queried first, not merely first-available.
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(os.path.join(FIXTURES_DIR, "announced-AS20473.json"), tmp)
            shutil.copy(os.path.join(FIXTURES_DIR, "whois-45.32.0.0_16.json"), tmp)
            caller = dg.make_caller(sleep_seconds=0.0, offline_dir=tmp)
            detail = dg.process_seed({"provider": "vultr", "asn": 20473}, caller, max_prefixes=25)
        self.assertIsNone(detail["error"])
        self.assertEqual(detail["prefixes_queried"], 1)
        self.assertEqual(detail["found"]["at_prefix"], "45.32.0.0/16")

    def test_clean_nothing_found_hetzner(self):
        detail = dg.process_seed({"provider": "hetzner", "asn": 24940}, self.caller, max_prefixes=25)
        self.assertIsNone(detail["error"])
        self.assertIsNone(detail["found"])
        self.assertEqual(detail["prefixes_queried"], 5)

    def test_max_prefixes_respected_on_a_miss(self):
        detail = dg.process_seed({"provider": "hetzner", "asn": 24940}, self.caller, max_prefixes=3)
        self.assertIsNone(detail["error"])
        self.assertIsNone(detail["found"])
        self.assertEqual(detail["prefixes_queried"], 3)

    def test_loop_continues_past_a_miss(self):
        detail = dg.process_seed({"provider": "testprovider", "asn": 99999}, self.caller, max_prefixes=25)
        self.assertIsNone(detail["error"])
        self.assertIsNotNone(detail["found"])
        # /24 (larger aggregate) queried first and misses; /28 queried second and hits.
        self.assertEqual(detail["prefixes_queried"], 2)
        self.assertEqual(detail["found"]["at_prefix"], "198.51.100.128/28")
        self.assertEqual(detail["found"]["url"], "https://example.test/geo.csv")
        self.assertEqual(detail["found"]["format"], "csv")

    def test_seed_failure_recorded_not_raised(self):
        detail = dg.process_seed({"provider": "bogus", "asn": 55555}, self.caller, max_prefixes=25)
        self.assertIsNotNone(detail["error"])
        self.assertIsNone(detail["found"])
        self.assertEqual(detail["prefixes_queried"], 0)

    def test_unreachable_geofeed_recorded_but_not_reachable(self):
        detail = dg.process_seed({"provider": "unreachable", "asn": 77777}, self.caller, max_prefixes=25)
        self.assertIsNone(detail["error"])
        self.assertIsNotNone(detail["found"])
        self.assertFalse(detail["found"]["reachable"])
        self.assertIsNone(detail["found"]["format"])


class TestRun(unittest.TestCase):
    def setUp(self):
        self.caller = dg.make_caller(sleep_seconds=0.0, offline_dir=FIXTURES_DIR)

    def test_unreachable_excluded_from_geofeeds_but_present_in_detail(self):
        seeds = [
            {"provider": "vultr", "asn": 20473},
            {"provider": "unreachable", "asn": 77777},
        ]
        details, geofeeds, seeds_failed = dg.run(seeds, self.caller, max_prefixes=25)
        self.assertEqual(seeds_failed, 0)
        self.assertEqual(len(details), 2)
        self.assertEqual([g["provider"] for g in geofeeds], ["vultr"])
        unreachable_detail = next(d for d in details if d["provider"] == "unreachable")
        self.assertIsNotNone(unreachable_detail["found"])
        self.assertFalse(unreachable_detail["found"]["reachable"])

    def test_single_seed_failure_not_fatal_and_counted(self):
        seeds = [
            {"provider": "vultr", "asn": 20473},
            {"provider": "bogus", "asn": 55555},
        ]
        details, geofeeds, seeds_failed = dg.run(seeds, self.caller, max_prefixes=25)
        self.assertEqual(seeds_failed, 1)
        bogus_detail = next(d for d in details if d["provider"] == "bogus")
        self.assertIsNotNone(bogus_detail["error"])
        self.assertEqual([g["provider"] for g in geofeeds], ["vultr"])

    def test_geofeeds_sorted_by_provider(self):
        seeds = [
            {"provider": "vultr", "asn": 20473},
            {"provider": "avultr-earlier", "asn": 20473},
        ]
        _, geofeeds, _ = dg.run(seeds, self.caller, max_prefixes=25)
        self.assertEqual([g["provider"] for g in geofeeds], ["avultr-earlier", "vultr"])

    def test_geofeeds_entries_match_consumer_contract(self):
        seeds = [{"provider": "vultr", "asn": 20473}]
        _, geofeeds, _ = dg.run(seeds, self.caller, max_prefixes=25)
        self.assertEqual(len(geofeeds), 1)
        for entry in geofeeds:
            self.assertEqual(set(entry.keys()), {"provider", "url", "format", "announced_prefixes"})
            self.assertIn(entry["format"], {"csv", "json"})
            self.assertEqual(entry["announced_prefixes"], ["45.32.0.0/16", "108.61.0.0/16", "45.63.0.0/18", "45.32.32.0/24"])

    def test_unusable_seed_excluded_from_geofeeds_but_marked_in_detail(self):
        seeds = [
            {"provider": "vultr", "asn": 20473},
            {"provider": "ipv6only", "asn": 33333},
        ]
        details, geofeeds, seeds_failed = dg.run(seeds, self.caller, max_prefixes=25)
        self.assertEqual(seeds_failed, 0)
        self.assertEqual([g["provider"] for g in geofeeds], ["vultr"])
        ipv6only_detail = next(d for d in details if d["provider"] == "ipv6only")
        self.assertFalse(ipv6only_detail["usable"])
        self.assertIsNone(ipv6only_detail["found"])
        self.assertEqual(ipv6only_detail["announced_prefixes"], [])


class TestMainCli(unittest.TestCase):
    def test_full_run_writes_expected_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            seeds_path = write_seeds(
                tmp,
                [
                    {"provider": "vultr", "asn": 20473},
                    {"provider": "hetzner", "asn": 24940},
                    {"provider": "testprovider", "asn": 99999},
                ],
            )
            out_path = os.path.join(tmp, "out.json")
            rc = dg.main(
                [
                    "--out", out_path,
                    "--seeds", seeds_path,
                    "--offline-dir", FIXTURES_DIR,
                    "--max-prefixes", "25",
                ]
            )
            self.assertEqual(rc, 0)
            with open(out_path, encoding="utf-8") as fh:
                result = json.load(fh)

        self.assertEqual(result["seeds_queried"], 3)
        self.assertEqual(result["seeds_failed"], 0)
        self.assertEqual(
            [g["provider"] for g in result["geofeeds"]],
            sorted(["vultr", "testprovider"]),
        )
        for entry in result["geofeeds"]:
            self.assertEqual(set(entry.keys()), {"provider", "url", "format", "announced_prefixes"})
            self.assertIn(entry["format"], {"csv", "json"})
            self.assertTrue(entry["announced_prefixes"])
        self.assertEqual(len(result["detail"]), 3)
        self.assertEqual(
            [d["provider"] for d in result["detail"]],
            ["vultr", "hetzner", "testprovider"],
        )
        for d in result["detail"]:
            self.assertIn("announced_prefixes", d)
            self.assertIn("usable", d)
        self.assertIn("generated_at", result)
        self.assertIn("_comment", result)
        self.assertIsInstance(result["_comment"], list)
        self.assertGreaterEqual(len(result["_comment"]), 2)
        self.assertLessEqual(len(result["_comment"]), 4)

    def test_all_seeds_failing_exits_nonzero_and_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            seeds_path = write_seeds(
                tmp,
                [
                    {"provider": "nope1", "asn": 11111},
                    {"provider": "nope2", "asn": 22222},
                ],
            )
            out_path = os.path.join(tmp, "out.json")
            sentinel = {"sentinel": "previous good run"}
            common.write_json(out_path, sentinel)

            rc = dg.main(
                [
                    "--out", out_path,
                    "--seeds", seeds_path,
                    "--offline-dir", FIXTURES_DIR,
                ]
            )
            self.assertEqual(rc, 1)
            with open(out_path, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh), sentinel)

    def test_missing_seeds_file_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc = dg.main(
                [
                    "--out", os.path.join(tmp, "out.json"),
                    "--seeds", os.path.join(tmp, "does-not-exist.json"),
                    "--offline-dir", FIXTURES_DIR,
                ]
            )
            self.assertEqual(rc, 1)
            self.assertFalse(os.path.exists(os.path.join(tmp, "out.json")))

    def test_malformed_seeds_file_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as tmp:
            seeds_path = os.path.join(tmp, "seeds.json")
            with open(seeds_path, "w", encoding="utf-8") as fh:
                fh.write("{ this is not valid json")
            rc = dg.main(
                [
                    "--out", os.path.join(tmp, "out.json"),
                    "--seeds", seeds_path,
                    "--offline-dir", FIXTURES_DIR,
                ]
            )
            self.assertEqual(rc, 1)

    def test_offline_mode_never_sleeps_even_with_large_sleep_arg(self):
        with tempfile.TemporaryDirectory() as tmp:
            seeds_path = write_seeds(
                tmp,
                [
                    {"provider": "vultr", "asn": 20473},
                    {"provider": "hetzner", "asn": 24940},
                    {"provider": "testprovider", "asn": 99999},
                    {"provider": "unreachable", "asn": 77777},
                    {"provider": "bogus", "asn": 55555},
                ],
            )
            out_path = os.path.join(tmp, "out.json")
            started = time.monotonic()
            rc = dg.main(
                [
                    "--out", out_path,
                    "--seeds", seeds_path,
                    "--offline-dir", FIXTURES_DIR,
                    "--sleep", "5.0",
                ]
            )
            elapsed = time.monotonic() - started
        self.assertEqual(rc, 0)
        self.assertLess(elapsed, 2.0, "offline mode must not sleep, regardless of --sleep")


if __name__ == "__main__":
    unittest.main()
