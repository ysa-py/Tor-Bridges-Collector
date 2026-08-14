-- tbc-store schema v1.
--
-- Bridges carry a full serialized payload (the source of truth for the typed
-- model) plus denormalized columns for indexed filtering. Timestamps are
-- stored twice: as RFC 3339 text (exact round-trip) and as unix-seconds
-- integers (cheap range queries). Provenance is relational so the set of
-- sources that ever reported a bridge is preserved for the lifetime of the
-- row.

CREATE TABLE bridges (
    canonical_key    TEXT PRIMARY KEY NOT NULL,
    transport        TEXT NOT NULL,
    host             TEXT NOT NULL,
    port             INTEGER NOT NULL,
    fingerprint      TEXT,
    data             TEXT NOT NULL,
    first_seen       TEXT NOT NULL,
    last_seen        TEXT NOT NULL,
    first_seen_epoch INTEGER NOT NULL,
    last_seen_epoch  INTEGER NOT NULL
);

CREATE INDEX bridges_transport_idx ON bridges (transport);
CREATE INDEX bridges_last_seen_idx ON bridges (last_seen_epoch);

CREATE TABLE bridge_sources (
    canonical_key TEXT NOT NULL REFERENCES bridges (canonical_key) ON DELETE CASCADE,
    source        TEXT NOT NULL,
    PRIMARY KEY (canonical_key, source)
);

CREATE INDEX bridge_sources_key_idx ON bridge_sources (canonical_key);

CREATE TABLE observations (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    bridge_key        TEXT NOT NULL,
    vantage_kind      TEXT NOT NULL,
    country           TEXT,
    asn               INTEGER,
    as_name           TEXT,
    is_mobile         INTEGER NOT NULL DEFAULT 0,
    probe_kind        TEXT NOT NULL,
    evasion_profile   TEXT NOT NULL,
    verdict           TEXT NOT NULL,
    rtt_ms            INTEGER,
    bootstrap_pct     INTEGER,
    error_class       TEXT,
    raw_evidence      TEXT,
    measured_at       TEXT NOT NULL,
    measured_at_epoch INTEGER NOT NULL,
    measurement_ref   TEXT
);

CREATE INDEX observations_bridge_idx ON observations (bridge_key);
CREATE INDEX observations_epoch_idx ON observations (measured_at_epoch);
CREATE UNIQUE INDEX observations_ref_uniq ON observations (bridge_key, measurement_ref)
    WHERE measurement_ref IS NOT NULL;

CREATE TABLE scores (
    bridge_key                  TEXT PRIMARY KEY NOT NULL,
    global_score                REAL NOT NULL,
    per_asn                     TEXT NOT NULL,
    tier                        TEXT NOT NULL,
    k                           INTEGER NOT NULL,
    n                           INTEGER NOT NULL,
    first_confirmed_working_at  TEXT,
    first_blocked_at            TEXT,
    burn_seconds                INTEGER,
    median_lifetime_seconds     INTEGER,
    freshness_age_seconds       INTEGER NOT NULL,
    data                        TEXT NOT NULL
);
