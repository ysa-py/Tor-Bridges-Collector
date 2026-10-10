# Directive v1 — Verified Bridge Yield, Probe-Relay Correctness, Full Automation

**Status:** Active engineering directive  
**Priority order:** measurement correctness → genuine verified yield → intelligence → automation → hardening  
**Supersedes no existing contract:** this is additive to `docs/ENGINEERING_PROMPT.md` and the existing Stage 10 publisher contract.

## Mission

Make bridge collection and publication truthful end to end. Improve the number of **genuinely verified** bridges, not the number of rows labelled successful. Preserve every existing collection, transport, publication, and automation capability; add evidence rather than relaxing gates.

A result must never claim more than the observation proves. A TCP socket opening is not a transport handshake, a transport handshake is not a Tor circuit, and an observation from outside Iran is not evidence of reachability inside Iran.

## Non-negotiable invariants

1. **No count inflation.** Distinguish candidates, parsed inputs, probes attempted, observations received, and verified bridges. A fallback, malformed result, generic HTTP response, TCP connect, stale observation, or inconclusive result must not be counted as a working bridge.
2. **Evidence travels with the bridge.** Every bridge record carries its actual highest verification stage and the observing vantage (including country/ASN/location only when observed). Retain timestamp, RTT, typed status, and bounded diagnostic detail. Keep individual observations when multiple vantages exist; do not replace them with a guessed country or a boolean.
3. **Unknown is not failed.** `inconclusive` and infrastructure/configuration `error` are neither success nor bridge failure. They must not lower Rust scores or consume a negative-evidence slot. `refused` and `timeout` are explicit observations, scoped to the target stage and vantage.
4. **No Iran inference from foreign vantage points.** A Cloudflare Worker, GitHub runner, or other non-Iran vantage may establish global reachability or a transport signature, but cannot establish reachability from Iran. Historical OONI data must retain its original measurement time and vantage and must not be presented as a live observation.
5. **Never publish unverified as working.** The existing `iran_likely_working_*` filenames remain unchanged, but their contents must be based only on fresh, positive, stage-appropriate evidence. Candidate/static fallback bridges remain available in candidate inputs; they must not be copied into working projections. Keep the full Stage 10 file contract, manifest, archive, publisher-input validation, and `COUNT_DELTA` checks intact.
6. **Fail closed.** An unset/blank relay or diagnostic secret yields HTTP 503 on protected routes. No workflow may deploy or call a relay in unauthenticated mode. Compare bearer tokens without early-exit content comparison; never print tokens, full relay URLs, credential-bearing paths, raw HTTP errors, or response bodies.
7. **Bound every request.** Validate JSON shape and size, field types and ranges, transport allowlist, target count, CR/LF/control characters, paths/headers, and private/reserved IP literals before network activity. Return structured 4xx/5xx JSON, never an uncaught Worker error 1101. Every timeout, caller cancellation, and failure closes/cancels sockets and releases locks. CORS is disabled or restricted to an explicit origin allowlist; never use wildcard CORS.
8. **Preserve protocol behavior.** Do not regress independent relay TLS SNI and HTTP `Host`, meek/conjure framing and response signatures, the six-connection ceiling, fronted-first admission, deployment-version guard, the version endpoint, existing transport support, bridge filenames, or pipeline capabilities.
9. **Free-tier first.** Use only documented free-tier capacity and existing dependencies. Add no paid service or paid dependency. Keep request, socket, timeout, and workflow cadence inside published limits and record the assumptions.

## Verification stages and outcomes

Use a typed stage and a typed status. Stage is the **highest positive property actually proven**, not the stage merely attempted.

| Stage | Meaning | Example evidence |
|---|---|---|
| **S0 — Candidate** | Descriptor/source record is syntactically valid; no network claim. | Parsed bridge line with source and timestamp. |
| **S1 — TCP connected** | A TCP connection was established from a named vantage. | `socket.opened` resolved, with RTT and vantage. This is reachability only. |
| **S2 — Transport verified** | A transport-specific handshake or protocol signature completed. | WebTunnel HTTP 101 plus valid upgrade signature; meek response signature; conjure registrar's documented validation signature; supported obfs4 handshake; not a generic TLS/HTTP response. |
| **S3 — Tor protocol verified** | Tor OR/link protocol exchange completed beyond the transport wrapper. | Valid Tor `VERSIONS`/`NETINFO` or an equivalent transport-appropriate protocol exchange. |
| **S4 — In-country service verified** | A successful Tor-level service/bootstrap observation came from a verified in-country vantage. | Live successful bootstrap from a named Iran vantage/agent with a measurement reference and timestamp. A foreign vantage never qualifies. |

Required outcome values: `connected`, `refused`, `timeout`, `inconclusive`, and `error`. Each observation includes `stage`, `vantage`, `rtt_ms` (nullable), timestamp, and bounded `detail`/error class. A failed or inconclusive attempt does not advance the highest stage. Missing legacy evidence defaults to S0/unknown; do not infer S2/S3/S4 from a legacy `success` or `tcp_reachable` boolean. A positive S2+ observation from a non-Iran vantage is “protocol verified from that vantage,” not “Iran working.”

## Phase 0 — Read-only evidence audit (before edits)

Inventory the deployed Worker, diagnostic Worker, deployment/auth workflow, client parser, Rust scorers, source adapters, result schemas, and Stage 10/COUNT_DELTA contracts. Verify the hypotheses below from code, real Actions runs/logs, and deployed edge behavior. Label each **confirmed**, **partially confirmed**, **refuted**, or **not yet verifiable**; do not turn a code inspection or mocked test into live-edge evidence.

- **H1 — TCP measurement signal:** raw TCP reachability must await the Cloudflare socket's documented `socket.opened` promise; `reader.closed` is a stream/socket-close signal and cannot prove that a silent server accepted the TCP connection. Demonstrate with a regression test whose socket opens while the readable side remains silent, and with a deployed-edge control.
- **H2 — Authentication:** unset relay/diagnostic secrets must reject with 503; wrong/missing token with 401. Verify every deployment, smoke, production, and diagnostic path; there is no auth-less fallback.
- **H3 — Validation and error containment:** malformed or hostile HTTP bodies/targets must be rejected with structured errors before `connect()`, and no request may cause Worker error 1101. Include body/target caps, types/ranges, CR/LF, private/reserved targets, and exact transport allowlist checks.
- **H4 — Cloudflare egress policy:** establish whether a target is unreachable because it is in a disallowed Cloudflare/private/reserved range, rather than labelling it a dead bridge. Use a public control plus a documented Cloudflare-IP negative control, and report which source/transport records are affected. Never count a policy denial as bridge failure.
- **H5 — Deadline and cancellation semantics:** the configured deadline must cover the entire operation; expiration or caller disconnect closes the live socket and cancels pending reads/writes. No background probe may outlive its result or retain one of the six slots.

## Phase 1 — Probe-relay correctness and regression tests

1. Fix H1 using `socket.opened` for TCP establishment. Preserve TLS `socket.opened` semantics and protocol exchanges.
2. Add a real CI regression test that is red against the old implementation and green after the fix. Test the HTTP handler as well as helper functions: missing secret, invalid token, malformed/oversize body, invalid transport, bad port, CR/LF, private/reserved target, cancellation, timeout, structured response, and response content.
3. Maintain the hard cap of six concurrently open outbound connections. Admit fronted/protocol-sensitive probes first, without changing result order. Clamp or reject invalid runtime configuration rather than allowing `NaN`, zero, or a value over six.
4. Add production-real controls in a main-only CI path: a reachable silent HTTP endpoint (connection must be `connected` without waiting for response bytes), a reachable host/closed port (must be `refused`), and a known-dead public bridge already recorded in repository data (must time out). Assert JSON content, status, stage, vantage and RTT—not only HTTP 200. Include a Cloudflare-IP policy control when it can be run safely.
5. Keep tests deterministic and hermetic in Vitest, but clearly separate mocked unit evidence from deployed-edge E2E evidence.

## Phase 2 — Typed Rust evidence, scoring, and publication

- Add typed Rust representations for stage, status, vantage and timestamped observations; parse old data conservatively. Preserve the existing raw source/result fields needed by consumers.
- Carry relay observations into the Rust-side per-bridge evidence record without merging different vantages into one boolean. Keep the source and measurement reference.
- Update scoring so `inconclusive`/`error` observations are ignored for negative scoring and confidence. They remain visible in reports. Add regression tests proving an inconclusive observation cannot reduce a score or promote/demote a bridge.
- Gate all “working” projections on eligible positive S2+ evidence; gate Iran-specific working claims on an actual, current in-country observation. S1 remains a reachability prefilter, not “working.” Refusal/timeout are evidence only for the observed vantage/time. Candidate fallback lines remain in the candidate/testing input and are never promoted by the fail-safe.
- Preserve every existing bridge filename, Stage 10 manifest/member hash and ZIP check, publisher-input safeguards, archive layout, and COUNT_DELTA notices. Add tests that exercise both empty truthful projections and populated verified projections.

## Phase 3 — Funnel measurement and baseline

For each run, emit a deterministic, machine-readable funnel with per-transport **and per-source** rows:

`source records → fetched → validated → deduplicated/new → parsed → eligible → attempted → responded → status counts → S0/S1/S2/S3/S4 → published`

Include IPv4/IPv6 where meaningful; reconcile totals and retain skipped/error reasons. Use the same bridge identity across stages and deduplicate descriptors that represent the same bridge. Record a before/after count of unique bridges with S2+ evidence, separated by vantage and country. Do not compare unlike samples or call stale data “after.” Mark missing/unavailable stages explicitly; never synthesize results.

## Phase 4 — Legitimate supply improvement

Inspect the live per-source/per-transport funnel before changing collection. Improve only upstream/source selection, pagination/rounds, protocol parsing, deduplication, or bounded retries that are evidenced as yield bottlenecks. Preserve source terms, respect documented rate limits, redact errors/credential-bearing URLs, and keep every attempt attributable to a source. Add an integration fixture or real-source CI observation for every adapter changed. No random generation, placeholder-as-working fallback, or count inflation.

## Phase 5 — Intelligence (only after measurement is correct)

Use only timestamped observations and their verified stage/vantage to rank bridges. Separate `candidate`, `globally reachable`, `transport verified`, `Tor verified`, and `Iran observed` labels. Recompute calibrated weights from empirical per-transport/per-source yield; keep model output advisory unless calibrated and validated on held-out evidence. Retain negative and inconclusive cohorts without treating infrastructure errors as bridge failures. Compare measured outcomes before/after; no mock result may be represented as live verification.

## Phase 6 — Unattended automation and keepalive

- Preserve automatic hourly collect → verify → score → publish on the default branch; deployments and real-edge E2E remain main-only. Check action ordering so report generation/merge completes before Stage 9 publication and Stage 10 validation.
- Add a bounded keepalive/dead-man mechanism. The keepalive must create attributable repository activity without an empty-commit loop, use least-privilege `GITHUB_TOKEN`, plain fast-forward pushes only, and avoid triggering recursive workflows. The dead-man check should fail/alert when the last successful scheduled production run exceeds a documented grace period, and record workflow/run IDs. A schedule cannot prove its own continued execution; explain this limitation and the recovery path.
- Verify current GitHub schedule behavior from official documentation: scheduled workflows run only from the default branch, may be delayed/dropped near the top of an hour, and in public repositories may be auto-disabled after 60 days without repository activity. Do not claim a scheduled run itself prevents deactivation unless an official source establishes that. Run two consecutive unattended scheduled CI runs after the change is on the default branch.
- Verify Cloudflare free-tier limits from official documentation at implementation time; enforce the six-socket ceiling, per-request body/bridge caps, and request budget. Keep deployment credentials in secrets and never use the reserved `CF_ACCOUNT_ID_1`–`CF_ACCOUNT_ID_11` rotation values for Wrangler.

## Required evidence and definition of done

Do not mark this directive complete until all applicable gates are observed green:

- H1–H5 verdict table with evidence and explicit negative results.
- H1 regression test identified in CI, shown failing against the previous implementation and passing with the fix.
- Fail-closed auth, constant-time comparison, strict input validation, body/target caps, and cancellation tests.
- Deployed-edge control tests that assert response content and all three required outcomes.
- Before/after unique S2+ bridge counts by transport/source/vantage, with timestamps and comparable inputs.
- Two consecutive unattended scheduled production CI run IDs, plus a dead-man/keepalive health record.
- Green Rust fmt, all-features Clippy/tests, Vitest, TypeScript, shell/YAML/workflow checks, Stage 9 publication verification, Stage 10 inventory, and COUNT_DELTA output.
- No capability loss; explain how each existing transport, filename, publisher-input guard, secret boundary, version guard, and protocol behavior remains covered.
- A report containing exact commands, observed CI run IDs, short verbatim log excerpts where accessible, mock-vs-live evidence labels, all failures/negative outcomes, and unimplemented work with the exact blocker and next command.

A missing toolchain, missing secret, inaccessible CI log, skipped job, stale artifact, or a run that has not yet occurred is **not** a pass. Keep the code/doc changes and report the blocker; do not ask for a result to be presumed.

## Official references

- Cloudflare Workers limits: <https://developers.cloudflare.com/workers/platform/limits/> (including six simultaneous outgoing connections, 50 Free subrequests per invocation, 100,000 daily Free requests, and body/CPU limits).
- Cloudflare TCP sockets: <https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/> (`socket.opened` resolves on connection establishment; `socket.closed` resolves on close; outbound TCP to Cloudflare IP ranges, localhost, and private network targets is blocked).
- GitHub Actions schedule events: <https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule> (default-branch behavior and scheduling caveats).
- GitHub workflow enable/disable behavior: <https://docs.github.com/en/actions/how-tos/manage-workflow-runs/disable-and-enable-workflows> (public repository schedule auto-disable after 60 days with no repository activity).
