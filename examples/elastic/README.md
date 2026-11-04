# Captured optional Elastic integration

`result-macos.json` records an actual local Filebeat/Elasticsearch run with the
original synthetic PostgreSQL fixture. It includes all stage counts, document
versions, positive and rejection checks, exact source/export hashes and explicit
limitations. It is a reproducible laboratory observation, not production data or
a general detection/delivery accuracy measurement.

`vendor-artifacts-macos.json` identifies the upstream archives and the SHA-512
checksums verified before executing them. Upstream binary licenses apply; the
binaries and raw runtime logs are not included in this repository.

The input is the same nine records from six local PostgreSQL cases used by the
original scanner. Eight derived rule signals include unknown outcomes and can
represent authorized activity. They are not eight distinct incidents.

See [the integration guide](../../docs/ELASTIC.md) for reproduction. The
[Elastic CI workflow](../../.github/workflows/elastic-lab.yml) runs the same lab
on Linux and publishes its sanitized result as a workflow artifact.

The searchable index is mutable. The create-only collector receives HTTP 409 on
same-ID replays while preserving the document and version; sealed original evidence remains a separate requirement.
The lab deliberately has no TLS/authentication and must stay on a trusted host
with synthetic input. Never publish the work directory's configs, collector logs
or Elasticsearch data directory.
