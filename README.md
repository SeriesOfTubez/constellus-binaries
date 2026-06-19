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

## Layout
```
binaries/<name>/build.env   # REPO, VERSION (pinned tag), PKG, BIN, GO_VERSION
binaries/<name>/Dockerfile  # golang build stage -> scratch image with just the binary
.github/workflows/build.yml # discover binaries/* -> build + gate + scan + publish
```

## Add a binary
Create `binaries/<name>/` with a `build.env` (and the shared Dockerfile pattern).
The workflow auto-discovers it — no per-binary YAML.

## Consume a published binary
```dockerfile
FROM ghcr.io/seriesoftubez/<name>:<version>@sha256:<digest> AS bin
COPY --from=bin /<name> /usr/local/bin/<name>
```
Pin the digest for immutability; the version tag keeps it human-readable (and
satisfies image-tag lint rules like Checkov CKV_DOCKER_7).

## Published
| Binary | Source | Version |
|--------|--------|---------|
| zgrab2 | [zmap/zgrab2](https://github.com/zmap/zgrab2) | v1.0.0 |
