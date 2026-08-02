# eBPF/XDP DPI Bypass Blueprint

Generated: 2026-08-02T20:40:19.123805689+00:00

```json
{
  "actions": [
    "XDP_PASS",
    "XDP_DROP",
    "XDP_TX"
  ],
  "description": "eBPF/XDP program for DPI bypass at line rate",
  "hook_point": "XDP",
  "notes": "Requires kernel 5.4+ with BPF support. See docs/ebpf_xdp_blueprint.md",
  "xdp_program": "iran_dpi_bypass_xdp"
}
```
