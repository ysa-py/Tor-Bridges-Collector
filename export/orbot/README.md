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

* `orbot_vanilla.txt` / `orbot_snowflake.txt` / `orbot_meek.txt` / `orbot_extended.txt` - only for
  current Orbot (its validator also lists snowflake, meek_lite and vanilla lines); older Orbot
  releases reject them, so use the lists above if you see "Invalid bridge format".

Conjure is not supported by Orbot and is not published anywhere in this repository.
Never paste comment lines, `Bridge ` prefixes or lines from the torrc exports into Orbot.
