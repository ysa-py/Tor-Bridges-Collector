# Unified OnionHop + VIP Rust Migration

## Purpose

The legacy `OnionHop.py` and `vip.py` entry points have been retired after
their bridge-collection responsibilities were merged into the Rust
**`tor-bridges-collector`** binary. The collector is additive: it does not
remove the broader TorShield pipeline, existing bridge output names, or
established publication checks.

The implementation merges the two scripts' distinct behavior:

- BridgeDB collection for `obfs4`, `webtunnel`, and `vanilla`, for IPv4 and
  IPv6;
- Delta-Kronecker community-list enrichment;
- fixed Snowflake, meek-azure (`meek_lite` token), and Conjure defaults;
- `bridge_history.json` first-seen tracking, a 72-hour fresh window, and
  30-day retention;
- raw-list normalization (including the legacy vanilla `Bridge ` history key);
- protocol-specific testing, README generation, ZIP packaging, and optional
  Telegram delivery;
- adaptive concurrency, persistent health scores, retry jitter, front-domain
  circuit breaking, Prometheus text metrics, and dry-run diffs.

## Layout

```text
src/
├── main.rs                             # default CLI entry point
├── bin/tor-bridges-collector.rs        # explicitly named CLI binary
└── tor_collector/
    ├── cli.rs                          # command-line parsing
    ├── config.rs                       # transport registry and environment config
    ├── fetch.rs                        # BridgeDB/Delta fetch + retry/backoff
    ├── parsing.rs                      # line validation and endpoint extraction
    ├── storage.rs                      # history + rolling health metadata
    ├── tester.rs                       # TCP/TLS/WebSocket/obfs4 verification
    ├── readme.rs                       # README, ZIP, Telegram rendering
    └── service.rs                      # atomic publication and dry-run orchestration
```

The existing `src/nin_cut_tester.rs` was also corrected. It now recognizes the
actual JSON-array input format and probes with a bounded, ordered worker pool.
This addresses the Stage 8k 20-minute timeout shown in
`IMG_20260803_195634.jpg`: the old implementation made 1,584 sequential
three-second connections (up to ~79 minutes); the new default uses at most 64
workers and caps the input at 2,000 candidates.

## Build and run

```bash
# Standard development checks
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo build --release --bin tor-bridges-collector

# Full live collection
./target/release/tor-bridges-collector

# Or use Cargo directly
cargo run --release --bin tor-bridges-collector -- --max-workers 50

# Network/protocol test and diff without changing bridge/, README.md, or ZIP
cargo run --release --bin tor-bridges-collector -- \
  --dry-run --metrics /tmp/tor-bridges.metrics
```

The default `cargo run` entry point also starts the unified collector.

### ARMv7-musl CI note

The repository's `armv7-unknown-linux-musleabihf` job is a no-link Rust
compile sentinel. Hosted runners do not provide the C cross compiler required
by Rustls/ring. For that **CI-only target**, Cargo selects HTTP-only `reqwest`
and builds a small collector stub, so the rest of the Rust workspace is still
type-checked without pretending a TLS collector package was produced. Normal
collector targets—including ARM GNU—retain the complete Rustls/ring,
WebTunnel, and obfs4 implementation.

## Output contract

For pooled transports the collector writes:

```text
bridge/<transport>.txt
bridge/<transport>_72h.txt
bridge/<transport>_tested.txt
bridge/<transport>_ipv6.txt
bridge/<transport>_ipv6_72h.txt
bridge/<transport>_ipv6_tested.txt
```

Fronted transport defaults write their established IPv4-named archive, recent,
and tested files. Existing unrelated publication outputs are not deleted; ZIP
creation includes all existing `bridge/*.txt` files and places them in
`Tor Bridges/Full Archive/`, `Tor Bridges/Recent 72h/`, or
`Tor Bridges/Tested/` just as `vip.py` did.

If a source returns a zero-byte body or errors, the collector treats it as a
failed fetch and never stages an empty replacement for a non-empty archive.
History is only written after it parsed as a JSON object, so malformed history
is also preserved for operator recovery.

## Protocol verification

| Transport | Verification |
| --- | --- |
| Vanilla | Async TCP connect with socket retry/fallback options |
| obfs4 IPv6 | Async TCP connect (CI IPv6 support varies) |
| obfs4 IPv4 | TCP prefilter, then real `obfs4proxy`/`lyrebird` managed-transport SOCKS5 handshake with `cert=` and `iat-mode=` authentication |
| WebTunnel | TLS plus exact `url=` HTTP/1.1 WebSocket Upgrade; only `101` passes |
| Snowflake / meek-azure / Conjure | TLS reachability to `url=`, `fronts=`, or `front=` broker/front host on port 443 |

If no usable obfs4 binary is installed, or fewer than
`OBFS4_VERIFY_MIN_FRACTION` of TCP survivors complete the harness, the
collector retains the TCP-reachable IPv4 obfs4 set. This is the safety fallback
from `OnionHop.py`, not a silent downgrade.

TLS probes use Rustls with the `ring` provider. They rotate cipher-suite/key
share ordering and ALPN profiles per connection, and use `TCP_NODELAY`,
`SO_REUSEADDR`, and TCP keepalive where the operating system permits it.
Rustls does not expose arbitrary TLS extension ordering, so the implementation
does **not** claim byte-for-byte browser/uTLS impersonation; it is a bounded,
standards-compliant fingerprint-rotation layer. Upstream downloads and Telegram
uploads keep normal certificate validation. Reachability probes intentionally
allow self-signed bridge/front certificates so protocol liveness is not
misclassified as a PKI policy failure.

## Environment variables

| Variable | Default | Meaning |
| --- | --- | --- |
| `BRIDGE_DIR` | `bridge` | Output directory |
| `BRIDGE_HISTORY_FILE` | `bridge/bridge_history.json` | History location |
| `README_PATH` | `README.md` | Generated README destination |
| `TOR_BRIDGES_ZIP` | `bridge/tor_bridges.zip` | ZIP destination |
| `BRIDGEDB_BASE_URL` | official BridgeDB URL | Override for controlled tests/mirrors |
| `DELTA_RAW_BASE_URL` | Delta raw bridge directory | Community seed endpoint |
| `RAW_REPO_URL` | ysa-py raw main bridge URL | README link root |
| `CONNECT_TIMEOUT` | `8` | Connect/TLS/WebSocket timeout seconds |
| `OBFS4_HANDSHAKE_TIMEOUT` | `12` | SOCKS harness timeout seconds |
| `MAX_RETRIES` | `2` | Per-probe attempts |
| `FETCH_RETRIES` | `3` | Upstream fetch attempts with jitter |
| `MAX_WORKERS` / `MIN_WORKERS` | `50` / `4` | Adaptive probe concurrency bounds |
| `MAX_TEST_PER_LIST` | `600` | Candidate cap for each list |
| `RECENT_HOURS` | `72` | Fresh-list window |
| `HISTORY_RETENTION_DAYS` | `30` | History retention window |
| `OBFS4_VERIFY_MIN_FRACTION` | `0.2` | Harness safety threshold from 0 to 1 |
| `OBFS4_BIN` | auto-discover | Explicit `obfs4proxy` or `lyrebird` executable |
| `FRONT_FAILURE_THRESHOLD` | `3` | Consecutive failures before front circuit opens |
| `FRONT_COOLDOWN_SECS` | `300` | Front circuit-breaker cooldown |
| `METRICS_OUTPUT` | unset | Prometheus text-file output path |
| `DRY_RUN` | `false` | Environment equivalent of `--dry-run` |
| `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` | unset | Telegram credentials |
| `TELEGRAM_UPLOAD` | `false` | Explicit Telegram upload trigger in GitHub Actions |
| `GITHUB_ACTIONS` | unset | Enables the legacy GitHub/midnight Telegram trigger |
| `NIN_CUT_MAX_WORKERS` | `64` | Stage 8k bounded probe worker count |
| `NIN_CUT_MAX_BRIDGES` | `2000` | Stage 8k input cap |
| `NIN_CUT_TIMEOUT_SECS` | `3` | Stage 8k per-TCP-probe timeout |

CLI options are documented by `tor-bridges-collector --help`: `--dry-run`,
`--bridge-dir`, `--readme`, `--metrics`, `--max-workers`,
`--max-test-per-list`, `--timeout-seconds`, and `--retry-count`.

## GitHub Actions

`.github/workflows/torshield-ir.yml` retains hourly scheduling,
`workflow_dispatch`, and push validation. Its Rust gate now runs formatting,
all-feature Clippy with warnings denied, all-feature tests, and a release
workspace build. The scrape job installs `obfs4proxy` (or `lyrebird` where the
package is available), builds `tor-bridges-collector --release`, and invokes
that binary before the broader source-enrichment pipeline.

Stage 8k has an explicit eight-minute timeout and bounded NIN environment
settings. The stage continues to produce report/export artifacts if individual
hosts time out, but it cannot reproduce the prior serial 20-minute GitHub
Action timeout.
