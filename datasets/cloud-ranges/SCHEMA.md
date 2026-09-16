# Cloud range dataset — schema

Normalised output of the published cloud provider IP range feeds listed in
[`sources.json`](sources.json). Produced daily by
[`.github/workflows/cloud-ranges.yml`](../../.github/workflows/cloud-ranges.yml),
published as a release asset, consumed by Constellus (planning#181).

Two files make up a release:

| File | Contents |
|------|----------|
| `cloud-ranges.ndjson.gz` | one JSON object per line, one line per `(prefix, service_raw)` pair |
| `manifest.json` | provenance: what was fetched, when, its digest, and the counts |

`raw-feeds.tar.gz` is attached alongside so any published dataset can be
re-derived from the exact bytes it was built from.

Releases are tagged `cloud-ranges-YYYY.MM.DD` and are immutable.
`cloud-ranges-latest` is a moving pointer giving consumers one stable URL to
resolve; resolve it once, then pin `dataset_sha256`, the way the images in this
repo are pinned by digest rather than by tag.

## Record

```json
{
  "prefix": "3.5.140.0/22",
  "ip_version": 4,
  "provider": "aws",
  "service_raw": "EC2",
  "service_class": "compute",
  "region": "ap-northeast-2",
  "source": "aws"
}
```

| Field | Type | Meaning |
|-------|------|---------|
| `prefix` | string | CIDR, normalised by `ipaddress` (host bits cleared, canonical v6 form) |
| `ip_version` | int | `4` or `6` |
| `provider` | string | lowercase provider key — `aws`, `azure`, `oci`, `gcp`, `google`, `cloudflare`, `fastly`, `digitalocean`, `linode`, `vultr`, or a discovered geofeed's provider |
| `service_raw` | string \| null | the provider's own service token, verbatim (`EC2`, `AzureCloud.eastus`, `OBJECT_STORAGE`). `null` where the feed publishes none |
| `service_class` | string | normalised class — see below |
| `region` | string \| null | the provider's own region/scope string, verbatim |
| `source` | string | the `sources.json` `id` the record came from |

Records are sorted by `(provider, prefix, service_raw)` so the gzipped output is
byte-stable for a given input and the diff between two days is readable.

## `service_class`

An enum, derived from `service_raw` through the per-source `classes` map in
`sources.json`.

| Value | Meaning |
|-------|---------|
| `compute` | addresses the provider assigns to customer-controlled instances |
| `edge` | multi-tenant CDN / anycast / WAF frontend |
| `storage` | object-storage or block/file-storage endpoints |
| `managed` | any other provider-operated service |
| `unknown` | a catch-all aggregate spanning multiple services — tells you who announces the space and nothing more |

**`service_class` is not a tenancy verdict.** It is a normalised restatement of
what the provider published. Deciding "this IP is single-tenant, we may scan it"
belongs to the consumer (planning#181/#182) and must stay composed with a
separate ownership check — EC2 addresses are recycled, so a stale DNS record can
point at a stranger's instance. See the safety note in planning#178.

### What the providers actually give you

Worth knowing before building on this, because it is thinner than it looks:

- **AWS is the only Tier A provider that names customer compute.** `EC2` means
  what it says.
- **Azure publishes no virtual-machine tag at all.** All 98 `systemService`
  values are Microsoft-operated services; customer VM space lives in the
  `AzureCloud.<region>` catch-alls, whose `systemService` is empty. Those
  classify as `unknown`.
- **GCP's `cloud.json` carries one service token, `Google Cloud`,** for every
  prefix. Region scope, no service discriminator. All `unknown`.
- **OCI's plain `OCI` tag spans customer VCN space and Oracle-run services in
  the same CIDRs,** so it is treated as a catch-all rather than compute.
- **Tier B (DigitalOcean, Linode, Vultr) has no service field,** but these are
  pure VPS providers with no multi-tenant edge muddying their ranges, so
  membership alone implies a customer VM. That is a provider-level judgement,
  recorded as the source's `default` in `sources.json` rather than read off the
  feed.

So the dataset's strongest contribution is the **negative**: it says
authoritatively that a given IP is `edge`, `storage` or `managed` — i.e. *not*
a customer VM — across a large share of cloud space. Only AWS `EC2` and Tier B
yield a positive `compute`. Anything landing on `unknown` must escalate to the
next rung of the ladder.

## Discovered geofeeds are contained to the seed ASN's announced space

Long-tail providers are found by RFC 9092 geofeed discovery against RIR whois
(`discover_geofeeds.py`) rather than a hand-maintained URL list. A discovered
feed enters the dataset as `tier: B-discovered` with `service_class: unknown` —
promoting a provider to `compute` is always a reviewed edit to `sources.json`,
never automatic.

**A discovered feed is only trusted where it overlaps the space its seed ASN
actually announces.** Live discovery found why: AS20473 (Vultr) announces
`44.33.0.0/16` out of AMPRNet, and that block's whois points at ARDC's geofeed —
a feed covering thousands of prefixes belonging to unrelated organisations.
Ingested wholesale, every one of them would have been attributed to
`provider: vultr`.

So `discovered_geofeeds.json` carries each seed's announced prefix list, and the
normalizer drops any record not contained within it. Attribution that cannot be
substantiated is dropped rather than flagged — the same posture the product
applies to findings. A discovered feed that survives containment with zero
records is not an error; its count sits in the manifest to be read.

## Overlapping prefixes are expected — do not dedupe

AWS and Azure both publish the *same* CIDR under a catch-all and again under
each specific service. `54.239.x.0/24` appears as both `AMAZON` and
`CLOUDFRONT`; an Azure range appears under `AzureCloud.eastus` and again under
`AzureFrontDoor.eastus`.

The dataset keeps every `(prefix, service_raw)` pair, so a lookup returns
several records. **The consumer resolves them by specificity: prefer the
longest matching prefix, and among equal-length matches prefer any
`service_class` other than `unknown`.** Collapsing to one record per prefix in
this pipeline would throw away the only signal it exists to carry.

## `manifest.json`

```json
{
  "schema_version": 1,
  "generated_at": "2026-09-16T04:12:03Z",
  "dataset_sha256": "…",
  "record_count": 121874,
  "sources": [
    {
      "id": "aws",
      "url": "https://ip-ranges.amazonaws.com/ip-ranges.json",
      "fetched_at": "2026-09-16T04:11:58Z",
      "sha256": "…",
      "bytes": 2702456,
      "change_token": "1789519625",
      "record_count": 17472
    }
  ]
}
```

`generated_at` is the staleness signal, and it means **last verified current**,
not "last time the bytes moved". On a day when no feed changed the dataset is
not republished, but the manifest on `cloud-ranges-latest` is still refreshed —
otherwise a quiet week and a silently broken job would look identical, which is
the failure mode this pipeline exists to prevent. A consumer reading a
`generated_at` older than its tolerance should say so loudly rather than
silently trusting month-old ranges in an authorisation decision.

`dataset_sha256` is what identifies the *content*; it is unchanged across those
refreshes, so "did the ranges change" and "is the mirror alive" stay separate
questions.

`dataset_sha256` is the digest of the uncompressed NDJSON. Pin it the way the
binaries in this repo pin image digests; record it in
`authorisation_decisions.evidence_snapshot` so a past decision stays
reconstructable.

## Failure behaviour

A provider changing its response shape **fails the build**. Every parser
asserts its feed's required keys, and every source declares a `min_prefixes`
floor. A fetch error, a shape change, or a count below the floor aborts the run
with a non-zero exit — one loud, visible build failure instead of a safety gate
quietly changing behaviour in every deployment.
