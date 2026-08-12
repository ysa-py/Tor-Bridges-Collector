# SECURITY_REPORT

## Credentials hygiene (VERIFIED)

- `git grep` across tracked files for `ghp_…`, `sk-…`, and PEM private-key
  headers: **no hardcoded credentials found**.
- Secrets are consumed from GitHub Actions secrets (`TELEGRAM_BOT_TOKEN`,
  `TELEGRAM_CHAT_ID`, `CF_WORKER_*`, `PROBE_RELAY_*`, provider keys) and passed
  via env; the workflow has a secret-presence gate that prints only whether a
  secret is set, never its value.
- `docs/SECRETS_MANIFEST.md` documents the key inventory and per-platform
  mechanisms.
- The Telegram uploader never logs the token (bounded multipart body built in
  memory; the only token use is in the request URL).

## Panic / swallow audit (counted this session, see ARCHITECTURE_GAPS)

- 859 `unwrap()`/`expect()` outside test modules (2 removed this session).
- 242 `let _ = …` result discards.
- 0 empty `catch {}` equivalents; the codebase consistently returns typed
  `Result`/errors at the module boundaries we touched.

## Hardening already present (VERIFIED by inspection)

- **Input validation:** bridge-line parsers (`tester.rs`, `transport_plugin.rs`,
  `endpoint_validator.rs`) reject malformed lines; fingerprint length/hex
  validation in `validate_bridge_line` (tested by `webtunnel_v2_tests`).
- **Rate limiting / abuse prevention:** `retry_engine.rs`, quarantine manager,
  and `source_circuit_breaker.rs` (failure threshold default 3) bound retries
  and back off; `MAX_WORKERS`/`MAX_TEST_PER_LIST` bound probing load.
- **Secret redaction:** per-workflow `validate_secret` helper distinguishes
  UNSET / EMPTY / INVALID without echoing values.
- **Supply chain:** all direct dependencies are pinned to exact versions
  (`=`); `Cargo.lock` committed; `cargo audit` is a CI gate (last run per
  CHANGELOG: 0 vulnerabilities).

## Remaining security debt

1. Panic paths (GAP-1) — a hostile input reaching an unguarded unwrap is the
   main crash vector; the untrusted-input class was reduced by 2 sites this
   session and should be driven to zero.
2. `iran_tester`/`probe_scheduler` binaries are opaque (GAP-5) — their probe
   semantics cannot be audited from source.
3. The Cloudflare relay path authenticates with `PROBE_RELAY_TOKEN`; token
   rotation and the Worker secret sync are owner-managed (Stage 4 deploys and
   syncs it automatically when configured).
4. AI/provider keys (`CEREBRAS_*`, `PORTKEY_*`, `GROQ_*`, `CF_ACCOUNT_ID_1..11`,
   `CF_API_TOKEN_1..11`) are optional; the security gate warns when none are
   set rather than failing, which is intentional but means secrets absence is
   silent in CI logs.
