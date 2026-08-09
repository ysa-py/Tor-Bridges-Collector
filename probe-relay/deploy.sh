#!/usr/bin/env bash
# ────────────────────────────────────────────────────────────────────
# probe-relay/deploy.sh — Deploy the Cloudflare Worker probe relay
#
# One-time setup (manual — cannot be scripted):
#   1. Create a Cloudflare account at https://dash.cloudflare.com/sign-up
#      (free tier, no credit card required)
#   2. Install wrangler: npm install -g wrangler
#   3. Authenticate:    wrangler login
#   4. Set the secret:  wrangler secret put PROBE_AUTH_TOKEN
#      (generate one with: openssl rand -hex 32)
#   5. Note the deployed Worker URL (e.g. probe-relay.YOUR_SUBDOMAIN.workers.dev)
#      — add it as GitHub Actions secret PROBE_RELAY_URL
#      — add the PROBE_AUTH_TOKEN value as GitHub Actions secret PROBE_RELAY_TOKEN
#
# After initial setup, this script handles redeploys:
#   sh probe-relay/deploy.sh
# ────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "════ Deploying Tor Bridge Probe Relay Worker ════"

# Check prerequisites
if ! command -v npx &>/dev/null; then
  echo "::error::npx not found — install Node.js first"
  exit 1
fi

# Install dependencies if needed
if [ ! -d node_modules ]; then
  echo "Installing wrangler..."
  npm install
fi

# Check wrangler auth
if ! npx wrangler whoami &>/dev/null; then
  echo "::error::Not authenticated with Cloudflare."
  echo "Run: npx wrangler login"
  echo "Then: npx wrangler secret put PROBE_AUTH_TOKEN"
  exit 1
fi

# Check secret is set
if ! npx wrangler secret list 2>/dev/null | grep -q PROBE_AUTH_TOKEN; then
  echo "::warning::PROBE_AUTH_TOKEN secret not set."
  echo "Generate one:  openssl rand -hex 32"
  echo "Set it:         npx wrangler secret put PROBE_AUTH_TOKEN"
fi

# Deploy
echo "Deploying..."
npx wrangler deploy

echo ""
echo "✅ Deploy complete."
echo ""
echo "Add these as GitHub Actions repository secrets:"
echo "  PROBE_RELAY_URL   = <the .workers.dev URL shown above>"
echo "  PROBE_RELAY_TOKEN = <your PROBE_AUTH_TOKEN value>"
echo ""
echo "Test the relay with:"
echo "  curl -X POST https://<YOUR_WORKER>.workers.dev/probe \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -H 'X-Probe-Token: YOUR_TOKEN' \\"
echo "    -d '[{\"id\":\"test\",\"transport\":\"vanilla\",\"host\":\"1.1.1.1\",\"port\":443}]'"
