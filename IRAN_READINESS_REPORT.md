# IRAN_READINESS_REPORT

## Iran-aware capability inventory (VERIFIED by inspection; module list from `src/lib.rs`)

| Module | Purpose |
| --- | --- |
| `iran_detector.rs` | Iran-specific detection heuristics (`smart-detection` feature) |
| `iran_bridge_prioritizer.rs` | Iran-focused bridge prioritization |
| `iran_smart_rotation.rs` | transport/ASN rotation planning with censorship-level escalation |
| `iran_dpi_shaper.rs`, `iran_advanced_dpi_evasion.rs` | DPI-shaping and evasion scoring |
| `iran_quantum_dpi_shield_v2.rs` | post-quantum shielding layer (scoring/design) |
| `iran_smart_anti_filter.rs` / `_v2.rs` | anti-filter scoring state |
| `iran_nin_bypass.rs`, `nin_internet_cut_classifier.rs`, `nin_cut_tester.rs`, `nin_survival_pack.rs`, `nin_selector.rs`, `nin_advanced_bypass.rs` | national-internet-cut (NIN) analysis: multi-anchor blackout detection, survivable pack generation |
| `iran_anti_siam.rs` | SIAM/NGFW anti-AI-DPI evasion analysis (Stage 8r) |
| `smart_iran_scorer.rs` | Iran scoring fusion |

All of these run as CI stages (`pipeline.rs` stage list) against the collected
bridge pool, and produce the advisory artifacts in `bridge/`
(`iran_likely_working_*.txt`, `iran_blocked.txt`, `iran_results.json`) and
`export/` (`iran_pack.txt`, `iran_cut_pack.txt`, `iran_siam_best_bridges.txt`,
…).

## Honest limits (what this system does NOT prove)

1. **No Iranian-side measurement.** Every probe runs from the GitHub runner
   (or, when configured, a Cloudflare relay). The outputs are explicitly
   advisory: "iran_likely_working" means *scored likely* from global evidence,
   not *confirmed reachable from Iran*. The README and manifest say this; the
   session reports must keep saying it.
2. **No full Tor circuit verification.** The pipeline verifies TCP/TLS and
   (when relay-configured) PT handshakes; it does not build a real Tor circuit
   through each bridge from a censored vantage. Nothing in the committed data
   should be read as a circuit-level success.
3. **Per-entry evidence is now explicit.** As of this session every
   `iran_results.json` entry carries `tested_at`, `test_tier`, `test_result`,
   so an Iranian user (or tooling) can see exactly what was observed for each
   line — including the tier at which it was tested.
4. **Single vantage per run.** Regional (EU/NA/ASIA/ME) conclusions require the
   multi-vantage layer (GAP-3), which is not yet in the scheduled pipeline.
5. **NIN packs are advisory sets.** `iran_likely_working_nin.txt` /
   `export/iran_cut_pack.txt` are prioritized candidate sets, not connectivity
   guarantees during an actual national internet cut.

## Score

Iran-readiness of the *advisory intelligence pipeline*: **75/100** — strong
module coverage and honest labeling, capped by the lack of Iranian-side or
multi-vantage measurement and the tier-2 relay dependency.
