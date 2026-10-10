# eBPF/XDP DPI Bypass Blueprint

<<<<<<< Updated upstream
Generated: 2026-10-10T20:18:35.925241049+00:00
=======
Generated: 2026-10-10T20:55:09.155523318+00:00
>>>>>>> Stashed changes

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
