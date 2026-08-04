# Workflow Migration Follow-up

`WORKFLOW_MIGRATION_FOLLOWUP.patch` contains the finalized workflow changes
prepared for this migration:

- install `obfs4proxy`/`lyrebird` and run the release
  `tor-bridges-collector` binary in `torshield-ir.yml`;
- make the TorShield Rust gate enforce all-feature Clippy/tests and a release
  build;
- enforce the bounded NIN Stage 8k settings that fixed the reported
  20-minute timeout; and
- install/configure the ARM C toolchain needed by Rustls/ring in `main-ci.yml`.

The GitHub App credential available to this Arena session can push ordinary
source changes but was rejected by GitHub when it attempted to update files
under `.github/workflows/` because it lacks the required `workflows`
permission. The patch is deliberately checked in so no remediation work is
lost. Once GitHub is reconnected with workflow-file write permission, apply it
from the repository root:

```bash
git apply WORKFLOW_MIGRATION_FOLLOWUP.patch
```

The same changes are also retained as the unpushed workflow commit at the tip
of the Arena working branch.
