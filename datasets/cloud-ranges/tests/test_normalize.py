"""Tests for datasets/cloud-ranges/normalize.py.

Standard library only (unittest). Runs entirely offline against the trimmed
fixtures in tests/fixtures/, using an in-memory copy of the real sources.json
with every min_prefixes floor lowered - the real floors are calibrated for
full feeds and the fixtures are deliberately tiny. The real sources.json is
never modified.

Invoke with:
    python -m unittest discover -s datasets/cloud-ranges/tests -t . -v
from the repo root, or:
    python -m unittest discover -v
from inside datasets/cloud-ranges/tests.
"""

from __future__ import annotations

import contextlib
import copy
import gzip
import io
import ipaddress
import json
import os
import shutil
import sys
import tempfile
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_CLOUD_RANGES_DIR = os.path.dirname(_TESTS_DIR)
if _CLOUD_RANGES_DIR not in sys.path:
    sys.path.insert(0, _CLOUD_RANGES_DIR)

import normalize  # noqa: E402
import common  # noqa: E402

FIXTURES_DIR = os.path.join(_TESTS_DIR, "fixtures")
REAL_SOURCES_PATH = os.path.join(_CLOUD_RANGES_DIR, "sources.json")

EXPECTED_KEYS = [
    "prefix",
    "ip_version",
    "provider",
    "service_raw",
    "service_class",
    "region",
    "source",
]
VALID_CLASSES = {"compute", "edge", "storage", "managed", "unknown"}


def _load_real_registry() -> dict:
    with open(REAL_SOURCES_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _write_registry(registry: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(registry, fh)


def _low_floor_registry(*, only_ids: list[str] | None = None) -> dict:
    """A deep copy of the real sources.json with every min_prefixes set to 1.

    Optionally restricted to a subset of source ids (by 'id').
    """
    registry = copy.deepcopy(_load_real_registry())
    if only_ids is not None:
        registry["sources"] = [s for s in registry["sources"] if s["id"] in only_ids]
    for s in registry["sources"]:
        s["min_prefixes"] = 1
    return registry


def run_normalize(args: list[str]) -> tuple[int, str, str]:
    """Invoke normalize.main() in-process, capturing stdout/stderr."""
    out = io.StringIO()
    err = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = normalize.main(args)
    return code, out.getvalue(), err.getvalue()


def read_ndjson(path: str) -> list[dict]:
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        text = fh.read()
    assert text.endswith("\n"), "ndjson output must end with a trailing newline"
    lines = text[:-1].split("\n") if text else []
    return [json.loads(line) for line in lines]


def read_ndjson_lines_raw(path: str) -> list[str]:
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        text = fh.read()
    lines = text[:-1].split("\n") if text else []
    return lines


class BaseOfflineTest(unittest.TestCase):
    """Sets up a low-floor sources.json (all 10 real sources) once per test."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="cloud_ranges_test_")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.sources_path = os.path.join(self.tmpdir, "sources_low.json")
        _write_registry(_low_floor_registry(), self.sources_path)

    def out_dir(self, name: str = "out") -> str:
        path = os.path.join(self.tmpdir, name)
        os.makedirs(path, exist_ok=True)
        return path


class EndToEndTest(BaseOfflineTest):
    def test_offline_run_all_sources_produces_manifest_and_matching_line_count(self):
        out_dir = self.out_dir()
        code, stdout, stderr = run_normalize(
            [
                "--sources",
                self.sources_path,
                "--out-dir",
                out_dir,
                "--offline-dir",
                FIXTURES_DIR,
            ]
        )
        self.assertEqual(code, 0, msg=f"stderr={stderr!r}")
        self.assertIn("changed=true", stdout)

        manifest_path = os.path.join(out_dir, "manifest.json")
        ndjson_path = os.path.join(out_dir, "cloud-ranges.ndjson.gz")
        self.assertTrue(os.path.exists(manifest_path))
        self.assertTrue(os.path.exists(ndjson_path))

        with open(manifest_path, encoding="utf-8") as fh:
            manifest = json.load(fh)

        self.assertEqual(manifest["schema_version"], 1)
        self.assertIn("dataset_sha256", manifest)
        self.assertEqual(len(manifest["sources"]), 10)

        records = read_ndjson(ndjson_path)
        self.assertEqual(len(records), manifest["record_count"])
        self.assertGreater(len(records), 0)

        # dataset_sha256 must be the sha256 of the uncompressed ndjson bytes
        with gzip.open(ndjson_path, "rb") as fh:
            uncompressed = fh.read()
        self.assertEqual(manifest["dataset_sha256"], common.sha256_bytes(uncompressed))

        # raw files were written, including the split cloudflare pair
        raw_dir = os.path.join(out_dir, "raw")
        for expected in [
            "aws.json",
            "azure.json",
            "oci.json",
            "gcp.json",
            "google.json",
            "cloudflare-0.txt",
            "cloudflare-1.txt",
            "fastly.json",
            "digitalocean.csv",
            "linode.csv",
            "vultr.json",
        ]:
            self.assertTrue(
                os.path.exists(os.path.join(raw_dir, expected)),
                msg=f"missing raw file {expected}",
            )


class SchemaValidationTest(BaseOfflineTest):
    def setUp(self):
        super().setUp()
        out_dir = self.out_dir()
        code, _, stderr = run_normalize(
            [
                "--sources",
                self.sources_path,
                "--out-dir",
                out_dir,
                "--offline-dir",
                FIXTURES_DIR,
            ]
        )
        self.assertEqual(code, 0, msg=f"stderr={stderr!r}")
        self.ndjson_path = os.path.join(out_dir, "cloud-ranges.ndjson.gz")
        self.lines = read_ndjson_lines_raw(self.ndjson_path)
        self.records = [json.loads(l) for l in self.lines]

    def test_every_record_has_exact_key_set_and_order(self):
        for raw_line, rec in zip(self.lines, self.records):
            self.assertEqual(
                list(json.loads(raw_line).keys()),
                EXPECTED_KEYS,
                msg=f"bad key order in {raw_line!r}",
            )
            self.assertEqual(set(rec.keys()), set(EXPECTED_KEYS))

    def test_service_class_in_enum(self):
        for rec in self.records:
            self.assertIn(rec["service_class"], VALID_CLASSES)

    def test_ip_version_matches_prefix(self):
        for rec in self.records:
            net = ipaddress.ip_network(rec["prefix"])
            self.assertEqual(net.version, rec["ip_version"])

    def test_serialised_compactly(self):
        # json.dumps(..., separators=(",", ":")) -> no spaces after , or :
        for raw_line in self.lines:
            self.assertNotIn(", ", raw_line)
            self.assertNotIn(": ", raw_line)

    def test_records_sorted_deterministically(self):
        def sort_key(rec):
            net = ipaddress.ip_network(rec["prefix"], strict=False)
            return (
                rec["provider"],
                rec["ip_version"],
                (int(net.network_address), net.prefixlen),
                rec["service_raw"] or "",
            )

        keys = [sort_key(r) for r in self.records]
        self.assertEqual(keys, sorted(keys))


class AwsClassificationTest(BaseOfflineTest):
    def setUp(self):
        super().setUp()
        out_dir = self.out_dir()
        code, _, stderr = run_normalize(
            [
                "--sources",
                self.sources_path,
                "--out-dir",
                out_dir,
                "--offline-dir",
                FIXTURES_DIR,
            ]
        )
        self.assertEqual(code, 0, msg=f"stderr={stderr!r}")
        records = read_ndjson(os.path.join(out_dir, "cloud-ranges.ndjson.gz"))
        self.aws_records = [r for r in records if r["source"] == "aws"]

    def _classes_for(self, service_raw):
        return {r["service_class"] for r in self.aws_records if r["service_raw"] == service_raw}

    def test_ec2_is_compute(self):
        self.assertEqual(self._classes_for("EC2"), {"compute"})

    def test_cloudfront_is_edge(self):
        self.assertEqual(self._classes_for("CLOUDFRONT"), {"edge"})

    def test_amazon_catchall_is_unknown(self):
        self.assertEqual(self._classes_for("AMAZON"), {"unknown"})

    def test_unmapped_service_is_managed(self):
        # AURORA_DSQL is not in the aws source's classes.map in sources.json
        self.assertEqual(self._classes_for("AURORA_DSQL"), {"managed"})

    def test_overlap_preserved_for_doubly_listed_cidr(self):
        by_prefix: dict[str, set] = {}
        for r in self.aws_records:
            by_prefix.setdefault(r["prefix"], set()).add(r["service_raw"])
        overlaps = {p: s for p, s in by_prefix.items() if len(s) > 1}
        self.assertGreater(len(overlaps), 0, msg="expected at least one overlapping AWS prefix")
        # the 3.5.140.0/22 CIDR is known (from the trimmed fixture) to carry
        # both an AMAZON catch-all record and a specific-service record
        self.assertIn("3.5.140.0/22", overlaps)
        self.assertGreaterEqual(len(overlaps["3.5.140.0/22"]), 2)

    def test_aws_ipv6_present(self):
        self.assertTrue(any(r["ip_version"] == 6 for r in self.aws_records))


class AzureClassificationTest(BaseOfflineTest):
    def setUp(self):
        super().setUp()
        out_dir = self.out_dir()
        code, _, stderr = run_normalize(
            [
                "--sources",
                self.sources_path,
                "--out-dir",
                out_dir,
                "--offline-dir",
                FIXTURES_DIR,
            ]
        )
        self.assertEqual(code, 0, msg=f"stderr={stderr!r}")
        records = read_ndjson(os.path.join(out_dir, "cloud-ranges.ndjson.gz"))
        self.azure_records = [r for r in records if r["source"] == "azure"]

    def test_azurecloud_catchall_uses_systemservice_not_name(self):
        azurecloud_recs = [
            r for r in self.azure_records if r["service_raw"].startswith("AzureCloud.")
        ]
        self.assertGreater(len(azurecloud_recs), 0)
        for r in azurecloud_recs:
            self.assertEqual(r["service_class"], "unknown")
            self.assertTrue(r["service_raw"].startswith("AzureCloud."))

    def test_azure_frontdoor_is_edge(self):
        recs = [r for r in self.azure_records if r["service_raw"].startswith("AzureFrontDoor")]
        self.assertGreater(len(recs), 0)
        for r in recs:
            self.assertEqual(r["service_class"], "edge")

    def test_azure_storage_is_storage(self):
        # The real feed's tag NAME for storage is "Storage"/"Storage.<region>"
        # (not literally prefixed "Azure"); its systemService is "AzureStorage",
        # which is the sources.json map key that actually drives classification.
        recs = [r for r in self.azure_records if r["service_raw"].startswith("Storage")]
        self.assertGreater(len(recs), 0)
        for r in recs:
            self.assertEqual(r["service_class"], "storage")

    def test_azure_mixed_v4_v6_tag_yields_both_ip_versions(self):
        # AutonomousDevelopmentPlatform is the fixture's designated mixed tag
        recs = [
            r for r in self.azure_records if r["service_raw"] == "AutonomousDevelopmentPlatform"
        ]
        versions = {r["ip_version"] for r in recs}
        self.assertEqual(versions, {4, 6})


class OciTest(BaseOfflineTest):
    def setUp(self):
        super().setUp()
        out_dir = self.out_dir()
        code, _, stderr = run_normalize(
            [
                "--sources",
                self.sources_path,
                "--out-dir",
                out_dir,
                "--offline-dir",
                FIXTURES_DIR,
            ]
        )
        self.assertEqual(code, 0, msg=f"stderr={stderr!r}")
        records = read_ndjson(os.path.join(out_dir, "cloud-ranges.ndjson.gz"))
        self.oci_records = [r for r in records if r["source"] == "oci"]

    def test_multi_tag_cidr_yields_one_record_per_tag(self):
        recs = [r for r in self.oci_records if r["prefix"] == "134.70.200.0/23"]
        tags = {r["service_raw"] for r in recs}
        self.assertEqual(tags, {"OSN", "OBJECT_STORAGE"})
        self.assertEqual(len(recs), 2)

    def test_ipv6_cidrs_entry_yields_ipv6_record(self):
        self.assertTrue(any(r["ip_version"] == 6 for r in self.oci_records))


class DeterminismAndChangeSignalTest(BaseOfflineTest):
    def _run(self, out_dir, extra_args=None):
        args = [
            "--sources",
            self.sources_path,
            "--out-dir",
            out_dir,
            "--offline-dir",
            FIXTURES_DIR,
        ]
        if extra_args:
            args += extra_args
        return run_normalize(args)

    def test_two_runs_produce_identical_dataset_sha256(self):
        out1 = self.out_dir("run1")
        out2 = self.out_dir("run2")
        code1, _, err1 = self._run(out1)
        code2, _, err2 = self._run(out2)
        self.assertEqual(code1, 0, msg=err1)
        self.assertEqual(code2, 0, msg=err2)

        with open(os.path.join(out1, "manifest.json"), encoding="utf-8") as fh:
            m1 = json.load(fh)
        with open(os.path.join(out2, "manifest.json"), encoding="utf-8") as fh:
            m2 = json.load(fh)
        self.assertEqual(m1["dataset_sha256"], m2["dataset_sha256"])

        with open(os.path.join(out1, "cloud-ranges.ndjson.gz"), "rb") as fh:
            b1 = fh.read()
        with open(os.path.join(out2, "cloud-ranges.ndjson.gz"), "rb") as fh:
            b2 = fh.read()
        self.assertEqual(b1, b2, msg="gzip output should be byte-stable (mtime=0)")

    def test_changed_false_when_previous_manifest_matches(self):
        out1 = self.out_dir("run1")
        code1, _, err1 = self._run(out1)
        self.assertEqual(code1, 0, msg=err1)
        previous_manifest = os.path.join(out1, "manifest.json")

        out2 = self.out_dir("run2")
        code2, stdout2, err2 = self._run(
            out2, extra_args=["--previous-manifest", previous_manifest]
        )
        self.assertEqual(code2, 0, msg=err2)
        self.assertIn("changed=false", stdout2)
        self.assertNotIn("changed=true", stdout2)

    def test_changed_true_when_previous_manifest_differs(self):
        out1 = self.out_dir("run1")
        code1, _, err1 = self._run(out1)
        self.assertEqual(code1, 0, msg=err1)

        with open(os.path.join(out1, "manifest.json"), encoding="utf-8") as fh:
            manifest = json.load(fh)
        manifest["dataset_sha256"] = "0" * 64
        different_manifest = os.path.join(self.tmpdir, "different_manifest.json")
        with open(different_manifest, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh)

        out2 = self.out_dir("run2")
        code2, stdout2, err2 = self._run(
            out2, extra_args=["--previous-manifest", different_manifest]
        )
        self.assertEqual(code2, 0, msg=err2)
        self.assertIn("changed=true", stdout2)

    def test_github_output_env_var_is_written(self):
        out1 = self.out_dir("run1")
        gh_output_path = os.path.join(self.tmpdir, "gh_output.txt")
        old = os.environ.get("GITHUB_OUTPUT")
        os.environ["GITHUB_OUTPUT"] = gh_output_path
        try:
            code, stdout, err = self._run(out1)
        finally:
            if old is None:
                os.environ.pop("GITHUB_OUTPUT", None)
            else:
                os.environ["GITHUB_OUTPUT"] = old
        self.assertEqual(code, 0, msg=err)
        with open(gh_output_path, encoding="utf-8") as fh:
            content = fh.read()
        self.assertIn("changed=true", content)
        self.assertIn("changed=true", stdout)


class ShapeChangeAndFloorTest(BaseOfflineTest):
    def _offline_dir_with_broken_aws(self) -> str:
        broken_dir = os.path.join(self.tmpdir, "broken_offline")
        shutil.copytree(FIXTURES_DIR, broken_dir)
        aws_path = os.path.join(broken_dir, "aws.json")
        with open(aws_path, encoding="utf-8") as fh:
            aws_obj = json.load(fh)
        del aws_obj["prefixes"]
        with open(aws_path, "w", encoding="utf-8") as fh:
            json.dump(aws_obj, fh)
        return broken_dir

    def test_missing_required_key_fails_build_and_names_source(self):
        broken_dir = self._offline_dir_with_broken_aws()
        out_dir = self.out_dir()
        code, stdout, stderr = run_normalize(
            [
                "--sources",
                self.sources_path,
                "--out-dir",
                out_dir,
                "--offline-dir",
                broken_dir,
            ]
        )
        self.assertNotEqual(code, 0)
        self.assertIn("aws", stderr)

    def test_min_prefixes_floor_failure_names_source_and_counts(self):
        registry = _low_floor_registry()
        for s in registry["sources"]:
            if s["id"] == "aws":
                s["min_prefixes"] = 10_000_000
        sources_path = os.path.join(self.tmpdir, "sources_high_floor.json")
        _write_registry(registry, sources_path)

        out_dir = self.out_dir()
        code, stdout, stderr = run_normalize(
            [
                "--sources",
                sources_path,
                "--out-dir",
                out_dir,
                "--offline-dir",
                FIXTURES_DIR,
            ]
        )
        self.assertNotEqual(code, 0)
        self.assertIn("aws", stderr)
        self.assertIn("10000000", stderr.replace(",", ""))

    def test_record_count_drop_over_25_percent_fails(self):
        # First run to get a baseline manifest with aws at 30 records.
        out1 = self.out_dir("run1")
        code1, _, err1 = run_normalize(
            [
                "--sources",
                self.sources_path,
                "--out-dir",
                out1,
                "--offline-dir",
                FIXTURES_DIR,
            ]
        )
        self.assertEqual(code1, 0, msg=err1)
        previous_manifest = os.path.join(out1, "manifest.json")

        # Build an offline dir where aws has been trimmed to far fewer records
        # than the previous manifest recorded (drop > 25%).
        shrunk_dir = os.path.join(self.tmpdir, "shrunk_offline")
        shutil.copytree(FIXTURES_DIR, shrunk_dir)
        aws_path = os.path.join(shrunk_dir, "aws.json")
        with open(aws_path, encoding="utf-8") as fh:
            aws_obj = json.load(fh)
        aws_obj["prefixes"] = aws_obj["prefixes"][:2]
        aws_obj["ipv6_prefixes"] = []
        with open(aws_path, "w", encoding="utf-8") as fh:
            json.dump(aws_obj, fh)

        out2 = self.out_dir("run2")
        code2, stdout2, stderr2 = run_normalize(
            [
                "--sources",
                self.sources_path,
                "--out-dir",
                out2,
                "--offline-dir",
                shrunk_dir,
                "--previous-manifest",
                previous_manifest,
            ]
        )
        self.assertNotEqual(code2, 0)
        self.assertIn("aws", stderr2)


class PrefixNormalisationTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="cloud_ranges_prefix_test_")
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)

    def test_host_bits_are_cleared(self):
        registry = _low_floor_registry(only_ids=["cloudflare"])
        sources_path = os.path.join(self.tmpdir, "sources_cf_only.json")
        _write_registry(registry, sources_path)

        offline_dir = os.path.join(self.tmpdir, "offline")
        os.makedirs(offline_dir)
        with open(os.path.join(offline_dir, "cloudflare-0.txt"), "w", encoding="utf-8") as fh:
            fh.write("10.0.0.5/24\n")
        with open(os.path.join(offline_dir, "cloudflare-1.txt"), "w", encoding="utf-8") as fh:
            fh.write("2001:db8::5/32\n")

        out_dir = os.path.join(self.tmpdir, "out")
        os.makedirs(out_dir)
        code, stdout, stderr = run_normalize(
            [
                "--sources",
                sources_path,
                "--out-dir",
                out_dir,
                "--offline-dir",
                offline_dir,
            ]
        )
        self.assertEqual(code, 0, msg=stderr)
        records = read_ndjson(os.path.join(out_dir, "cloud-ranges.ndjson.gz"))
        prefixes = {r["prefix"] for r in records}
        self.assertIn("10.0.0.0/24", prefixes)
        self.assertNotIn("10.0.0.5/24", prefixes)
        self.assertIn("2001:db8::/32", prefixes)
        self.assertNotIn("2001:db8::5/32", prefixes)


class DiscoveredGeofeedsTest(BaseOfflineTest):
    def test_discovered_source_added_with_unknown_default(self):
        offline_dir = os.path.join(self.tmpdir, "offline_with_discovered")
        shutil.copytree(FIXTURES_DIR, offline_dir)
        with open(os.path.join(offline_dir, "geofeed-hetzner.csv"), "w", encoding="utf-8") as fh:
            fh.write("# discovered geofeed\n")
            fh.write("5.9.0.0/16,DE,DE-BE,Berlin,10115\n")
            fh.write("88.198.0.0/16,DE,DE-BY,Nuremberg,90402\n")

        discovered_path = os.path.join(self.tmpdir, "discovered.json")
        with open(discovered_path, "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "generated_at": "2026-09-15T00:00:00Z",
                    "geofeeds": [
                        {
                            "provider": "hetzner",
                            "url": "https://example.invalid/hetzner-geo.csv",
                            "format": "csv",
                            "announced_prefixes": ["5.9.0.0/16", "88.198.0.0/16"],
                        }
                    ],
                },
                fh,
            )

        out_dir = self.out_dir()
        code, stdout, stderr = run_normalize(
            [
                "--sources",
                self.sources_path,
                "--out-dir",
                out_dir,
                "--offline-dir",
                offline_dir,
                "--discovered",
                discovered_path,
            ]
        )
        self.assertEqual(code, 0, msg=stderr)

        records = read_ndjson(os.path.join(out_dir, "cloud-ranges.ndjson.gz"))
        discovered_recs = [r for r in records if r["source"] == "geofeed-hetzner"]
        self.assertEqual(len(discovered_recs), 2)
        for r in discovered_recs:
            self.assertEqual(r["service_class"], "unknown")
            self.assertEqual(r["provider"], "hetzner")

        with open(os.path.join(out_dir, "manifest.json"), encoding="utf-8") as fh:
            manifest = json.load(fh)
        manifest_ids = [s["id"] for s in manifest["sources"]]
        self.assertIn("geofeed-hetzner", manifest_ids)
        # discovered sources are appended after the registry's own sources
        self.assertEqual(manifest_ids[-1], "geofeed-hetzner")

    def _run_with_discovered(self, geofeed_lines, announced):
        """Run with one discovered csv geofeed and the given containment set."""
        offline_dir = os.path.join(self.tmpdir, "offline_contain")
        if not os.path.isdir(offline_dir):
            shutil.copytree(FIXTURES_DIR, offline_dir)
        with open(os.path.join(offline_dir, "geofeed-ardc.csv"), "w", encoding="utf-8") as fh:
            fh.write("".join(geofeed_lines))

        discovered_path = os.path.join(self.tmpdir, "discovered_contain.json")
        entry = {
            "provider": "ardc",
            "url": "https://example.invalid/geofeed.csv",
            "format": "csv",
        }
        if announced is not None:
            entry["announced_prefixes"] = announced
        with open(discovered_path, "w", encoding="utf-8") as fh:
            json.dump({"generated_at": "2026-09-15T00:00:00Z", "geofeeds": [entry]}, fh)

        out_dir = self.out_dir()
        code, stdout, stderr = run_normalize(
            [
                "--sources", self.sources_path,
                "--out-dir", out_dir,
                "--offline-dir", offline_dir,
                "--discovered", discovered_path,
            ]
        )
        return code, stderr, out_dir

    def test_discovered_records_outside_announced_space_are_dropped(self):
        """The AMPRNet case: a discovered feed may describe space the seed ASN
        announces but does not own. Only the contained part may be attributed."""
        code, stderr, out_dir = self._run_with_discovered(
            [
                "44.33.1.0/24,US,US-NJ,Piscataway,08854\n",   # inside announced
                "44.0.0.0/16,US,US-CA,San Diego,92101\n",     # ARDC space, NOT announced
                "44.190.0.0/16,US,US-TX,Austin,73301\n",      # ARDC space, NOT announced
            ],
            announced=["44.33.0.0/16"],
        )
        self.assertEqual(code, 0, msg=stderr)

        records = read_ndjson(os.path.join(out_dir, "cloud-ranges.ndjson.gz"))
        got = [r for r in records if r["source"] == "geofeed-ardc"]
        self.assertEqual([r["prefix"] for r in got], ["44.33.1.0/24"])
        self.assertEqual(got[0]["service_class"], "unknown")
        self.assertIn("outside the seed ASN's announced space", stderr)

    def test_discovered_feed_emptied_by_containment_is_not_an_error(self):
        code, stderr, out_dir = self._run_with_discovered(
            ["44.190.0.0/16,US,US-TX,Austin,73301\n"],
            announced=["44.33.0.0/16"],
        )
        self.assertEqual(code, 0, msg=stderr)
        records = read_ndjson(os.path.join(out_dir, "cloud-ranges.ndjson.gz"))
        self.assertEqual([r for r in records if r["source"] == "geofeed-ardc"], [])
        with open(os.path.join(out_dir, "manifest.json"), encoding="utf-8") as fh:
            manifest = json.load(fh)
        entry = next(s for s in manifest["sources"] if s["id"] == "geofeed-ardc")
        self.assertEqual(entry["record_count"], 0)

    def test_discovered_feed_without_announced_prefixes_is_refused(self):
        """An unbounded discovered feed is the misattribution case - refuse it."""
        code, stderr, _ = self._run_with_discovered(
            ["44.33.1.0/24,US,US-NJ,Piscataway,08854\n"], announced=None
        )
        self.assertNotEqual(code, 0)
        self.assertIn("announced_prefixes", stderr)

        code, stderr, _ = self._run_with_discovered(
            ["44.33.1.0/24,US,US-NJ,Piscataway,08854\n"], announced=[]
        )
        self.assertNotEqual(code, 0)

    def test_containment_matches_on_exact_prefix_and_ip_version(self):
        code, stderr, out_dir = self._run_with_discovered(
            [
                "44.33.0.0/16,US,US-NJ,Piscataway,08854\n",       # exact match, kept
                "2001:db8::/48,US,US-NJ,Piscataway,08854\n",      # v6, no v6 announced
            ],
            announced=["44.33.0.0/16"],
        )
        self.assertEqual(code, 0, msg=stderr)
        records = read_ndjson(os.path.join(out_dir, "cloud-ranges.ndjson.gz"))
        got = sorted(r["prefix"] for r in records if r["source"] == "geofeed-ardc")
        self.assertEqual(got, ["44.33.0.0/16"])

    def test_containment_merges_adjacent_announced_prefixes(self):
        """Announcing 0.0/25 and 0.128/25 means announcing the whole /24, so a
        record spanning both is contained. Collapsing is why this works; a naive
        per-prefix subnet_of check would wrongly reject it."""
        code, stderr, out_dir = self._run_with_discovered(
            ["44.33.0.0/24,US,US-NJ,Piscataway,08854\n"],
            announced=["44.33.0.0/25", "44.33.0.128/25"],
        )
        self.assertEqual(code, 0, msg=stderr)
        records = read_ndjson(os.path.join(out_dir, "cloud-ranges.ndjson.gz"))
        got = [r["prefix"] for r in records if r["source"] == "geofeed-ardc"]
        self.assertEqual(got, ["44.33.0.0/24"])

    def test_missing_discovered_file_is_tolerated(self):
        out_dir = self.out_dir()
        missing_path = os.path.join(self.tmpdir, "does_not_exist.json")
        code, stdout, stderr = run_normalize(
            [
                "--sources",
                self.sources_path,
                "--out-dir",
                out_dir,
                "--offline-dir",
                FIXTURES_DIR,
                "--discovered",
                missing_path,
            ]
        )
        self.assertEqual(code, 0, msg=stderr)

    def test_malformed_discovered_file_fails_build(self):
        out_dir = self.out_dir()
        malformed_path = os.path.join(self.tmpdir, "malformed_discovered.json")
        with open(malformed_path, "w", encoding="utf-8") as fh:
            fh.write("{not valid json")

        code, stdout, stderr = run_normalize(
            [
                "--sources",
                self.sources_path,
                "--out-dir",
                out_dir,
                "--offline-dir",
                FIXTURES_DIR,
                "--discovered",
                malformed_path,
            ]
        )
        self.assertNotEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
