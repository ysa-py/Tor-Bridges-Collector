# Iran Bridge Status

Total bridge count reflects real, deduplicated availability from all enabled legitimate sources at the time of each run. Growth is expected to plateau once available upstream supply is exhausted — this is correct, intentional behavior consistent with Tor's own anti-enumeration protections, not a defect. The pipeline will never fabricate, farm beyond legitimate rate limits, or count placeholder/non-functional entries toward this total.

## Current root-cause notes

- BridgeDB and MOAT intentionally partition distribution per requester; the collector does not automate around CAPTCHA, per-requester limits, or anti-enumeration protections.
- A large share of current vanilla/obfs4/webtunnel volume is mirrored from public third-party bridge-list publications. Counts therefore track those publishers' cadence and can plateau when their published data is unchanged.
- RFC 5737, RFC 3849, benchmarking, private, loopback, link-local, multicast, and other reserved endpoints are rejected before ingestion and excluded from quality-gate denominators.
- Missing `data/iran_bridges.json` is now a hard precondition failure unless it can be deterministically regenerated from `data/iran_results.json` or `bridge/iran_results.json`.
