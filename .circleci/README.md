# `.circleci/` — TorShield-IR on CircleCI

This directory holds the **CircleCI** configuration for TorShield-IR. It runs
**alongside** the existing GitHub Actions (`.github/workflows/`) and GitLab CI
(`.gitlab-ci.yml`) — nothing has been removed.

The reason we add CircleCI is the project requirement of running a
**scheduled OONI poller** on a CI provider whose **free tier does not require
a credit card** (Northflank, despite its claims, still asks for one — same
problem as GitLab). CircleCI's free performance plan needs no card and offers
**Scheduled Pipelines** on the free tier.

---

## 1. What lives here

| File | Purpose |
|------|---------|
| `config.yml` | The full pipeline definition — jobs, workflows, parameters. |
| `README.md` | This file. |

Supporting scripts live in `../scripts/`:

| Script | Purpose |
|--------|---------|
| `scripts/circleci_env_bootstrap.sh` | Writes the runtime `.env` from the `torshield-ir-secrets` CircleCI Context at job start. **This is how `.env` is migrated to CircleCI without losing any variables.** |
| `scripts/circleci_ooni_poller.py`   | Scheduled OONI Iran snapshot poller. Replaces Northflank. |
| `scripts/circleci_packaging.sh`     | Builds `dist/ultra-main-vip-zero-error-quantum-ultra.tar.gz`. |

---

## 2. One-time setup (≈ 5 minutes)

### 2.1 Sign up & connect the repo
1. Go to <https://circleci.com/signup> → "Sign up with GitHub".
2. Allow CircleCI to access the `TorShield-IR` repo.
3. From the CircleCI dashboard → **Set Up Project** → pick the `main` branch.
   CircleCI will detect `.circleci/config.yml` automatically.

### 2.2 Create the secrets Context
1. CircleCI sidebar → **Organization Settings → Contexts → Create Context**.
2. Name it **`torshield-ir-secrets`**.
3. Add every variable listed in [`configs/env_template.sh`](../configs/env_template.sh).
   Even the optional ones — `circleci_env_bootstrap.sh` reads them by name and
   writes empty assignments for any that are missing, so downstream Python
   code that calls `load_dotenv()` keeps working.

   Key ones (the rest follow the same pattern):

   | Name | Required? | Notes |
   |------|-----------|-------|
   | `CEREBRAS_API_KEY` | recommended | AI provider |
   | `CF_ACCOUNT_ID_1` … `CF_ACCOUNT_ID_11` | optional | Cloudflare slots |
   | `CF_API_TOKEN_1` … `CF_API_TOKEN_11` | optional | Cloudflare slots |
   | `CF_AI_GATEWAY_URL_1` … `CF_AI_GATEWAY_URL_11` | optional | CF AI Gateway |
   | `GROQ_API_KEY` | optional | AI provider |
   | `PORTKEY_API_KEY` | optional | AI meta-router |
   | `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | optional | Notification |
   | `GH_PAT_AUTOFIX`, `GH_REPO_OWNER`, `GH_REPO_NAME` | optional | Auto-fix PRs |
   | `SLACK_WEBHOOK`, `SLACK_CHANNEL` | optional | Slack alerts |
   | `DOCKERHUB_USERNAME`, `DOCKERHUB_PASSWORD` | optional | Avoid rate limits |

4. Restrict the Context to the `TorShield-IR` project (Context → *Restrict*).

### 2.3 Attach the Context to every workflow job
All jobs in `config.yml` already reference the Context via `executor` env vars
and the `materialise-env` command. To enforce it at the project level, go to
**Project Settings → Advanced → Default Context** and select
`torshield-ir-secrets`. Done.

---

## 3. Create the schedules (the Northflank replacement)

CircleCI schedules are **configured in the web UI**, not in `config.yml`
(design choice by CircleCI — the config only declares the parameters the
schedules pass in). Create **two** schedules:

### 3.1 Every-6-hour shallow OONI poll
1. **Project Settings → Triggers → Schedules → Add Schedule**.
2. Fill in:

   | Field | Value |
   |-------|-------|
   | Name | `ooni-shallow-6h` |
   | Description | `Shallow OONI IR snapshot every 6 h` |
   | Branch | `main` |
   | Cron | `0 0,6,12,18 * * *` (UTC) — every 6 h on the hour |
   | Pipeline parameters | `schedule-source` = `6h` &nbsp;·&nbsp; `run-ooni-poll` = `true` |

3. **Save.** First run happens at the next cron slot.

### 3.2 Every-12-hour deep OONI poll + health + self-heal
1. Repeat the steps above with:

   | Field | Value |
   |-------|-------|
   | Name | `ooni-deep-12h` |
   | Description | `Deep OONI IR snapshot + AI gateway health + self-heal` |
   | Cron | `0 3,15 * * *` (UTC) — every 12 h, offset by 3 h to avoid the 6 h |
   | Pipeline parameters | `schedule-source` = `12h` &nbsp;·&nbsp; `run-ooni-poll-deep` = `true` |

2. **Save.**

### 3.3 (Optional) Daily packaging
If you want a fresh `ultra-main-vip-zero-error-quantum-ultra.tar.gz`
artifact every day:

   | Field | Value |
   |-------|-------|
   | Name | `daily-packaging` |
   | Cron | `30 4 * * *` |
   | Pipeline parameters | `schedule-source` = `daily` |

### 3.4 (Optional) Hourly gateway health
   | Field | Value |
   |-------|-------|
   | Name | `hourly-health` |
   | Cron | `0 * * * *` |
   | Pipeline parameters | `schedule-source` = `hourly` |

> All schedules are **free-tier** (no credit-card required, no VPS, no
> Northflank, no personal machine). Only GitHub Actions and CircleCI free
> tier are used.

---

## 4. Workflow overview

`config.yml` defines **six workflows** gated on pipeline parameters:

| Workflow | Triggered by | Runs jobs |
|----------|--------------|-----------|
| `ci-push` | every push (default) | env-bootstrap → quality-gate → go-quality-gate → build-rust → build-go → scrape → ai-rerank → packaging |
| `schedule-ooni-6h` | `schedule-source=6h` or `run-ooni-poll=true` | env-bootstrap → ooni-poll (shallow) |
| `schedule-oomi-12h` | `schedule-source=12h` or `run-ooni-poll-deep=true` | env-bootstrap → ooni-poll (deep), ai-gateway-health, self-heal |
| `schedule-hourly-health` | `schedule-source=hourly` | env-bootstrap → ai-gateway-health |
| `schedule-daily-packaging` | `schedule-source=daily` | env-bootstrap → quality-gate → scrape → ai-rerank → packaging |
| `on-failure-self-heal` | `run-self-heal=true` (manual) | env-bootstrap → self-heal |

Every existing GitHub workflow has a 1:1 mirror here; **nothing is removed**.

---

## 5. How the OONI scheduled poll commits back

The `ooni-poll` job:
1. Checks out the repo (full history).
2. Materialises `.env` from the Context.
3. Runs `scripts/circleci_ooni_poller.py --depth {shallow|deep}` which writes:
   - `data/ooni_iran_snapshot.json` (full snapshot)
   - `data/dashboard.json` (updated summary)
   - `data/telemetry_state.json` (poll counter + last summary)
   - `data/censorship_state.json` (blocked-IP list for the anti-filter)
4. If `git diff` is non-empty, commits and pushes with the **CI bot identity**
   (`TorShield-IR CircleCI Bot <circleci-bot@users.noreply.github.com>`).
5. The push uses `--rebase` to gracefully handle races with the other schedule.

**No external VPS, no Northflank, no laptop needed.** The OONI endpoint
`https://api.ooni.io/api/v1/measurements` is public, requires no key, and
was verified active in March 2026.

---

## 6. Local validation

```bash
# Validate the YAML is well-formed.
python -c "import yaml; yaml.safe_load(open('.circleci/config.yml'))"

# Try the env bootstrap locally (will use whatever env vars are already set).
bash scripts/circleci_env_bootstrap.sh /tmp/test.env && cat /tmp/test.env | head

# Try the OONI poller locally (shallow, no bridges file → empty snapshot).
python scripts/circleci_ooni_poller.py --depth shallow \
    --out /tmp/snap.json --dashboard /tmp/dash.json \
    --telemetry /tmp/tel.json --censorship-state /tmp/cen.json
cat /tmp/snap.json
```

---

## 7. Troubleshooting

| Symptom | Fix |
|---------|-----|
| `FATAL: .env missing` in a job | The `env-bootstrap` job didn't run first, or the workspace wasn't attached. Make sure the job has `requires: [ env-bootstrap ]` and uses the `attach-env` command. |
| OONI poll finds no bridges | `data/iran_bridges.json` was not produced by a recent `scrape` job. Either trigger a `daily` schedule or run `python main.py --mode collect` locally and commit the file. |
| `git push` rejected | Another schedule won the race. The script already does `git pull --rebase`; if that fails, the next scheduled run will succeed. |
| Slack notifications silent | `SLACK_WEBHOOK` Context var is not set. Slack orb is no-op without it. |
| `Context not found` | The Context name in `config.yml` doesn't match. Default name is `torshield-ir-secrets` — create it in Org Settings → Contexts. |
