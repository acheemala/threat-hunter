-- ============================================================
-- migrations/001_initial.sql
-- Phase 1 schema: hunts + findings
-- Applied automatically by sqlx::migrate!() on first run
-- ============================================================

CREATE TABLE IF NOT EXISTS campaigns (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    goal       TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'active',   -- active | paused | completed
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hunts (
    id              TEXT PRIMARY KEY,
    campaign_id     TEXT REFERENCES campaigns(id),
    target          TEXT NOT NULL,
    started_at      TEXT NOT NULL,
    completed_at    TEXT,
    status          TEXT NOT NULL,               -- running | completed | failed
    risk_level      TEXT,                        -- CLEAN | LOW | MEDIUM | HIGH | CRITICAL
    risk_score      INTEGER,
    finding_count   INTEGER DEFAULT 0,
    report_markdown TEXT                         -- final agent report text
);

CREATE TABLE IF NOT EXISTS findings (
    id            TEXT PRIMARY KEY,
    hunt_id       TEXT NOT NULL REFERENCES hunts(id),
    campaign_id   TEXT REFERENCES campaigns(id),
    discovered_at TEXT NOT NULL,
    severity      TEXT NOT NULL,   -- CRITICAL | HIGH | MEDIUM | LOW | INFO
    category      TEXT NOT NULL,   -- filesystem | process | network | log
    agent_type    TEXT NOT NULL DEFAULT 'agent',
    description   TEXT NOT NULL,
    detail        TEXT NOT NULL,
    mitre_id      TEXT,
    mitre_name    TEXT,
    suppressed    INTEGER NOT NULL DEFAULT 0,
    notes         TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_hunt     ON findings(hunt_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity, discovered_at);
CREATE INDEX IF NOT EXISTS idx_findings_campaign ON findings(campaign_id, discovered_at);
