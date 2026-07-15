# ════════════════════════════════════════════════════════════════════════
# TorShield-IR — n8n CI/CD Runner for Hugging Face Spaces (Docker SDK)
#
# Single-container design: n8n (orchestrator) + Python 3.12 + Go 1.22 +
# Rust 1.80 + git, all in ONE image. No SSH between services needed —
# n8n's "Execute Command" node runs every CI step directly in this same
# container, exactly like a CircleCI job does inside its executor.
#
# Free tier on Hugging Face: 2 vCPU / 16 GB RAM / 50 GB (ephemeral) disk.
# No credit card required for a private Space.
# ════════════════════════════════════════════════════════════════════════
FROM python:3.12-slim-bookworm

# ── System deps + Node.js 22 (n8n requires Node >=22.22) ────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl git ca-certificates gnupg build-essential pkg-config \
        libssl-dev jq tar gzip xz-utils \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# Python 3.12 removed the stdlib `distutils` module, which node-gyp still
# imports when it has to compile a native addon from source (e.g. n8n's
# isolated-vm dependency). setuptools ships a compatibility shim that
# restores `import distutils` for any tool running under this Python —
# without it, `npm install -g n8n` fails with
# "ModuleNotFoundError: No module named 'distutils'".
RUN pip install --no-cache-dir --upgrade setuptools

# ── n8n ───────────────────────────────────────────────────────────────
RUN npm install -g n8n@latest

# ── Go 1.22 (matches go.mod: "go 1.22") — official binary, exact pin ──
RUN curl -fsSL https://go.dev/dl/go1.22.10.linux-amd64.tar.gz -o /tmp/go.tar.gz \
    && tar -C /usr/local -xzf /tmp/go.tar.gz \
    && rm /tmp/go.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"

# ── Rust 1.80 (matches .circleci rust-180 executor) ────────────────────
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
        sh -s -- -y --default-toolchain 1.80.0 --profile minimal
ENV PATH="/usr/local/cargo/bin:${PATH}"

# ── Hugging Face Spaces requires the container to run as UID 1000 ─────
RUN useradd -m -u 1000 user
ENV HOME=/home/user
WORKDIR /home/user

# n8n's own data (workflows/credentials) — only used as a LOCAL fallback
# before you wire up the Supabase Postgres connection. Once Postgres env
# vars (DB_TYPE=postgresdb, DB_POSTGRESDB_*) are set as Space secrets,
# n8n uses Supabase automatically and this folder no longer matters for
# durability (it's wiped on every Space restart anyway).
ENV N8N_USER_FOLDER=/home/user/.n8n

COPY --chown=user:user entrypoint.sh /home/user/entrypoint.sh
RUN chmod +x /home/user/entrypoint.sh
USER user

# Hugging Face Docker Spaces route public traffic to this port.
# Must match `app_port:` in the Space's README.md metadata.
EXPOSE 7860
ENV N8N_PORT=7860
ENV N8N_PROTOCOL=https
ENV N8N_HOST=0.0.0.0
# n8n production-mode sets X-Frame-Options that breaks the HF iframe
# preview — harmless, just open the Space URL directly in a new tab
# instead of relying on the embedded preview pane.

ENTRYPOINT ["/home/user/entrypoint.sh"]
