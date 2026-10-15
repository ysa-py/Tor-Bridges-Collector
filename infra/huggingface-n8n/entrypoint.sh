#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════════
# Runs once at container boot (and again every time the Space restarts/
# wakes from sleep). It does NOT run the CI jobs themselves — those run
# later, on-demand, as n8n workflow steps (Execute Command node), exactly
# like CircleCI jobs run when a workflow is triggered.
#
# Required Space secrets (Settings → Variables and secrets):
#   GH_PAT    — GitHub Personal Access Token (repo scope; used for git
#               clone/pull/push and for posting commit statuses/releases)
#   GH_OWNER  — your GitHub username/org
#   GH_REPO   — repo name, e.g. torshield-ir
#   + every variable already listed in configs/env_template.sh — these
#     get picked up automatically by scripts/circleci_env_bootstrap.sh,
#     unmodified, because that script already reads live env vars rather
#     than anything CircleCI-specific.
# ════════════════════════════════════════════════════════════════════════
set -euo pipefail

REPO_DIR="/home/user/torshield-ir"

if [ -z "${GH_PAT:-}" ] || [ -z "${GH_OWNER:-}" ] || [ -z "${GH_REPO:-}" ]; then
    echo "⚠️  GH_PAT / GH_OWNER / GH_REPO not set yet."
    echo "    n8n will still start, but Execute Command nodes that need"
    echo "    the repo (build/test/scrape/packaging) will fail until you"
    echo "    set these three Space secrets and restart the Space."
else
    REPO_URL="https://${GH_PAT}@github.com/${GH_OWNER}/${GH_REPO}.git"

    if [ -d "$REPO_DIR/.git" ]; then
        echo "→ Repo already present — pulling latest..."
        git -C "$REPO_DIR" fetch origin
        git -C "$REPO_DIR" reset --hard "origin/${GIT_BRANCH:-main}"
    else
        echo "→ Cloning TorShield-IR (depth 1)..."
        git clone --depth 1 --branch "${GIT_BRANCH:-main}" "$REPO_URL" "$REPO_DIR"
    fi

    git -C "$REPO_DIR" config user.email "n8n-bot@users.noreply.github.com"
    git -C "$REPO_DIR" config user.name  "TorShield-IR n8n Bot"

    # Materialise .env exactly the way CircleCI used to — same script,
    # same template, zero code changes needed.
    if [ -f "$REPO_DIR/scripts/circleci_env_bootstrap.sh" ]; then
        echo "→ Materialising .env from Space secrets..."
        (cd "$REPO_DIR" && bash scripts/circleci_env_bootstrap.sh) || \
            echo "⚠️  env bootstrap failed — check Space secret names match configs/env_template.sh"
    fi

    # Python deps for quality-gate / scrape jobs. Re-installs on every
    # boot since the disk is ephemeral — fine for free-tier traffic
    # volume, just adds ~30-90s to cold start.
    if [ -f "$REPO_DIR/requirements.txt" ]; then
        echo "→ Installing Python dependencies..."
        pip install --no-cache-dir --user -r "$REPO_DIR/requirements.txt" || \
            echo "⚠️  some Python deps failed to install — check logs above"
    fi
fi

echo "→ Starting n8n on port ${N8N_PORT}"
exec n8n start
