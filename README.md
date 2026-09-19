# constellus-binaries

Builds trusted third-party binaries **from pinned source** and publishes them as
minimal, versioned, scanned OCI images to GHCR — so downstream images can vendor
a known-good binary with a real version tag (no `latest`, no opaque upstream image).

## Why
Pulling a prebuilt third-party image (often only tagged `latest`) means trusting
someone else's build and gives you no version pin, no scan, and no provenance.
This repo builds the binary itself, from a checksum-verified source tag, and gates
on a reachability-aware vuln scan before publishing.

## Security posture
For a third-party tool we don't maintain: **verify the supply chain, scan the
dependencies, don't re-audit the source.**

- **Source integrity — trust, verified.** Pinned semver tag; Go module downloads
  are verified against the Go checksum database (sumdb).
- **Dependencies — scanned + gated.** [`govulncheck`](https://go.dev/security/vuln/)
  is reachability-aware: a vuln fails the build only if the built command actually
  calls the vulnerable symbol. That keeps "scan a third-party tool" actionable —
  unreachable CVEs in someone else's dependency tree don't block.
- **Artifact — SBOM + provenance.** CycloneDX SBOM + SLSA build-provenance
  attestation pushed alongside the image.
- A weekly schedule re-runs the gate against published pins, so a newly-disclosed
  reachable vuln fails even without a version bump.

When `govulncheck` flags a *reachable* vuln: bump to a fixed upstream version →
file upstream + temporarily pin → fork+patch (last resort) → or accept with a
documented, time-boxed justification.

### Accepting a finding (`GOVULN_ALLOW`)
That last option is the only one with an escape hatch, so it is deliberately a
narrow one. The gate stays **deny-by-default**: any reachable finding fails the
build unless it is named in the binary's `GOVULN_ALLOW` *and* its review date is
still in the future.

```sh
# binaries/<name>/build.env
GOVULN_ALLOW=GO-2026-5932:2026-10-16     # space-separated ID:YYYY-MM-DD entries
```

- **Reachable means symbol-level** — a trace naming a function the built command
  actually calls. Findings that are merely imported or required never reach the
  gate, which is what keeps it actionable.
- **The date is a review deadline, not a snooze.** Once it passes the build
  fails until someone re-reads the finding. Extending it is a decision with a
  commit message, not an edit.
- **An entry that is no longer reachable warns rather than fails** — upstream
  fixing something must not break the build — and tells you to delete it.
- **Only the named ID is accepted.** A new reachable finding fails even while an
  existing acceptance is live.
- Write the justification as a comment above the entry: why no fix exists, what
  the reachable path actually is, and what has to change for it to be removed.

A binary with no `GOVULN_ALLOW` is gated strictly, which is the normal case.

## Layout
```
binaries/<name>/build.env   # REPO, VERSION (pinned tag), PKG, BIN, GO_VERSION
binaries/<name>/Dockerfile  # golang build stage -> scratch image with just the binary
datasets/<name>/            # a dataset built the same way: fetch -> validate -> publish
.github/workflows/build.yml # verify (gate + build) on every PR; publish on main
```

## Add a binary
Create `binaries/<name>/` with a `build.env` (and the shared Dockerfile pattern),
then add `<name>` to the `matrix.binary` list in **both** jobs of
`.github/workflows/build.yml` — `verify` and `publish`. There is no
auto-discovery; the matrix is the registry of what gets built.

## CI shape
`verify` runs on every pull request, on main, and on the weekly schedule: it runs
the govulncheck reachability gate against the pinned source and builds the image
**without pushing**. `publish` runs only when the event is not a pull request, and
carries the only credentials that can write to GHCR or sign an attestation.

So a pull request proves a binary is fit to ship without being able to ship it —
which is what lets a change to the gate itself be reviewed with CI evidence,
rather than first executing after merge.

## Consume a published binary
```dockerfile
FROM ghcr.io/seriesoftubez/<name>:<version>@sha256:<digest> AS bin
COPY --from=bin /<name> /usr/local/bin/<name>
```
Pin the digest for immutability; the version tag keeps it human-readable (and
satisfies image-tag lint rules like Checkov CKV_DOCKER_7).

## Datasets
The same posture applied to *data* a downstream service depends on: fetch from
the publisher, validate the shape, version the result, attest its provenance.

### `datasets/cloud-ranges`
Mirrors the published cloud provider IP range feeds (AWS, Azure, OCI, GCP,
Google, Cloudflare, Fastly, and the DigitalOcean/Linode/Vultr geofeeds),
normalises nine formats into one schema, and publishes it as a release.
Long-tail providers are found via RFC 9092 geofeed discovery against RIR whois
rather than a hand-maintained URL list.

Constellus reads it as a tenancy signal on the probe-authorisation path, which
sets the bar: **a provider changing its response shape fails this build**,
loudly, instead of quietly altering a safety gate in every deployment.

- Schema, semantics and consumer rules: [`datasets/cloud-ranges/SCHEMA.md`](datasets/cloud-ranges/SCHEMA.md)
- Feed registry and classification maps: [`datasets/cloud-ranges/sources.json`](datasets/cloud-ranges/sources.json)
- Daily build: [`.github/workflows/cloud-ranges.yml`](.github/workflows/cloud-ranges.yml)
- Weekly discovery: [`.github/workflows/geofeed-discovery.yml`](.github/workflows/geofeed-discovery.yml)

Consume it by resolving the moving pointer once, then pinning the digest:
```bash
gh release download cloud-ranges-latest -R SeriesOfTubez/constellus-binaries \
  --pattern 'cloud-ranges.ndjson.gz' --pattern 'manifest.json'
```
`manifest.json` carries `dataset_sha256` (pin this), `generated_at` (staleness —
refreshed even on days nothing changed, so a stale value means a broken job, not
a quiet week), and per-source counts and change tokens.

Standard library Python only, deliberately — this runs against nine third-party
endpoints and feeds a safety gate; a dependency here would be one more thing to
audit for code `urllib` already covers.

## Published
| Artifact | Kind | Source | Version |
|----------|------|--------|---------|
| zgrab2 | image | [zmap/zgrab2](https://github.com/zmap/zgrab2) | `master-e5172a7` |
| cdncheck | image | [projectdiscovery/cdncheck](https://github.com/projectdiscovery/cdncheck) | v1.3.1 |
| cloud-ranges | dataset | 10 provider feeds + RIR-discovered geofeeds | `cloud-ranges-latest` |

Versions here are the published image tag, which is `VERSION` in each
`build.env` — zgrab2 is built from a pinned commit rather than a tag, because
v1.0.0 predates the `rdp` module the scanner-worker needs (planning#67).

**cdncheck consumers must pass `-duc`.** It runs an update check against
ProjectDiscovery on every invocation otherwise. Note also that its CIDR/ASN
dataset is `//go:embed`-ed at build time, so the ranges only move when the pin
is bumped and the image rebuilt — see `binaries/cdncheck/build.env`.
