# Orbot-ready bridges (auto-generated every hour)

Paste the content of `orbot_top.txt` (recommended, ~40 lines) into
Orbot -> Connect -> Custom Bridges. Each line is `obfs4 ...` or `webtunnel ...`,
no `Bridge` prefix, upper-case fingerprints, public addresses only.

`orbot_top.txt` is hourly-rotated, ranked (tested tiers first, 443/80 first, reachable first when
probed) and network-diversified: at most 2 bridges per IPv4 /16, IPv6 /32 or webtunnel domain, so
blocking one range cannot take the whole list down.

* `orbot_obfs4.txt` / `orbot_webtunnel.txt` - everything per transport
* `orbot_ipv4.txt` / `orbot_ipv6.txt` - per IP family
* `orbot_all.txt` - union

Snowflake / Meek / Conjure / vanilla lines are not accepted by Orbot's custom-bridge
dialog (use Orbot's built-in Snowflake option instead).
