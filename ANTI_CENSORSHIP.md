# Anti-Censorship and DPI-Evasion Design Notes

This project contains Rust and Go components for bridge probing, adaptive transport ranking, and cautious traffic-shape recommendations for censorship-circumvention research and operations. It does not claim guaranteed reachability, unlimited bridge growth, or unblockable behavior.

## Threat model

The Iran-focused pipeline models common filtering signals: SNI and hostname blocking, IP/ASN blocklists, active probing, protocol fingerprinting, TLS-in-TLS suspicion, and time-varying throttling. Decisions are based on live probe telemetry, OONI/RIPE-style vantage data when credentials are available, and local scoring modules.

## Safety boundaries

- The collector respects Tor anti-enumeration protections and never farms BridgeDB/MOAT beyond legitimate request patterns.
- Placeholder or reserved endpoints are rejected and never counted as working bridge supply.
- Failsafe data is auditable: use requires an error, bounded retry, alternate acquisition attempt, and a `failsafe_activations.json` record.
- Adaptive DPI logic ranks and selects available pluggable-transport strategies; it does not fabricate bridges or misrepresent reachability.

## Runtime adaptation

The Rust scoring/selection layers consume arbitrary-size candidate pools and rank transports by observed success. Go orchestration dynamically sizes workers from the candidate pool and available CPU rather than fixed historical ceilings. Optional RIPE Atlas and Telegram integrations activate only when their GitHub Actions secrets are present.
