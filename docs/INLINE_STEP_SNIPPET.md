# INLINE STEP SNIPPET — AI Ultra-Pro Cleanup v4.0

This file is documentation only. It is intentionally stored outside `.github/workflows/*.yml` so the inline step snippet below is not parsed as an executable GitHub Actions workflow.

Use this step inside an existing workflow job when a full reusable workflow call is not appropriate. Do not paste a second top-level `permissions:` block into a real workflow file unless that block is intended to be the workflow's only top-level permissions declaration.

```yaml
- name: AI Ultra-Pro Cleanup v4.0
  shell: bash
  run: |
    set -euo pipefail
    echo "Starting AI Ultra-Pro cleanup for $GITHUB_REPOSITORY@$GITHUB_SHA"
    find . -type d \( -name '__pycache__' -o -name '.pytest_cache' -o -name '.mypy_cache' -o -name '.ruff_cache' \) -prune -print -exec rm -rf {} +
    find . -type f \( -name '*.pyc' -o -name '*.pyo' \) -print -delete
    find . -type d \( -name '.next' -o -name '.nuxt' -o -name '.turbo' -o -name '.vite' \) -prune -print -exec rm -rf {} +
    echo "AI Ultra-Pro cleanup complete"
```
