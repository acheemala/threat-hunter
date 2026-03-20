// ============================================================
// src/db/mod.rs
//
// Persistence layer — SQLite via sqlx.
//
// The database lives at ~/.config/threathunter/db.sqlite
// Migrations in ./migrations/ are embedded and applied automatically.
//
// Uses runtime query builders (sqlx::query / query_as) rather than
// the compile-time sqlx::query! macros so no DATABASE_URL is needed
// at build time — the binary works out-of-the-box on any machine.
// ============================================================

use anyhow::{Context, Result};
use chrono::Utc;
use sqlx::{sqlite::SqlitePoolOptions, Row, SqlitePool};
use std::path::PathBuf;
use uuid::Uuid;

use crate::report::Finding;

// ── DB path ───────────────────────────────────────────────────────────────────

pub fn db_path() -> Result<PathBuf> {
    let config_dir = dirs::config_dir()
        .context("Could not resolve config directory (~/.config)")?
        .join("threathunter");

    std::fs::create_dir_all(&config_dir)
        .with_context(|| format!("Could not create {}", config_dir.display()))?;

    Ok(config_dir.join("db.sqlite"))
}

// ── Pool init ─────────────────────────────────────────────────────────────────

pub async fn init() -> Result<SqlitePool> {
    let path = db_path()?;
    let url  = format!("sqlite://{}?mode=rwc", path.display());

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .with_context(|| format!("Could not open database at {}", path.display()))?;

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .context("Database migration failed")?;

    Ok(pool)
}

// ── Hunt record ───────────────────────────────────────────────────────────────

pub struct HuntRecord {
    pub id:              String,
    pub campaign_id:     Option<String>,
    pub target:          String,
    pub started_at:      String,
    pub completed_at:    String,
    pub risk_level:      String,
    pub risk_score:      i64,
    pub finding_count:   i64,
    pub report_markdown: String,
}

impl HuntRecord {
    pub fn new(
        target:          &str,
        campaign_id:     Option<String>,
        risk_level:      &str,
        risk_score:      i64,
        finding_count:   i64,
        started_at:      String,
        report_markdown: String,
    ) -> Self {
        Self {
            id:              Uuid::new_v4().to_string(),
            campaign_id,
            target:          target.to_string(),
            started_at,
            completed_at:    Utc::now().to_rfc3339(),
            risk_level:      risk_level.to_string(),
            risk_score,
            finding_count,
            report_markdown,
        }
    }
}

pub async fn save_hunt(pool: &SqlitePool, hunt: &HuntRecord) -> Result<()> {
    sqlx::query(
        "INSERT INTO hunts
             (id, campaign_id, target, started_at, completed_at, status,
              risk_level, risk_score, finding_count, report_markdown)
         VALUES (?, ?, ?, ?, ?, 'completed', ?, ?, ?, ?)"
    )
    .bind(&hunt.id)
    .bind(&hunt.campaign_id)
    .bind(&hunt.target)
    .bind(&hunt.started_at)
    .bind(&hunt.completed_at)
    .bind(&hunt.risk_level)
    .bind(hunt.risk_score)
    .bind(hunt.finding_count)
    .bind(&hunt.report_markdown)
    .execute(pool)
    .await
    .context("Failed to save hunt")?;

    Ok(())
}

// ── Findings ─────────────────────────────────────────────────────────────────

pub async fn save_findings(
    pool:        &SqlitePool,
    hunt_id:     &str,
    campaign_id: Option<&str>,
    findings:    &[Finding],
) -> Result<()> {
    let now = Utc::now().to_rfc3339();

    for f in findings {
        let id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO findings
                 (id, hunt_id, campaign_id, discovered_at, severity, category,
                  agent_type, description, detail, mitre_id, mitre_name)
             VALUES (?, ?, ?, ?, ?, ?, 'agent', ?, ?, ?, ?)"
        )
        .bind(&id)
        .bind(hunt_id)
        .bind(campaign_id)
        .bind(&now)
        .bind(&f.severity)
        .bind(&f.category)
        .bind(&f.description)
        .bind(&f.detail)
        .bind(&f.mitre_id)
        .bind(&f.mitre_name)
        .execute(pool)
        .await
        .context("Failed to save finding")?;
    }

    Ok(())
}

// ── Query ─────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct FindingRow {
    pub id:            String,
    pub hunt_id:       String,
    pub discovered_at: String,
    pub severity:      String,
    pub category:      String,
    pub description:   String,
    pub detail:        String,
    pub mitre_id:      Option<String>,
    pub mitre_name:    Option<String>,
}

pub struct FindingFilter {
    pub min_severity: Option<String>,
    pub hunt_id:      Option<String>,
    pub since:        Option<String>,
    pub limit:        i64,
}

impl Default for FindingFilter {
    fn default() -> Self {
        Self { min_severity: None, hunt_id: None, since: None, limit: 200 }
    }
}

pub async fn list_findings(
    pool:   &SqlitePool,
    filter: &FindingFilter,
) -> Result<Vec<FindingRow>> {
    let severity_floor: i64 = match filter.min_severity.as_deref().unwrap_or("LOW") {
        "CRITICAL" => 4,
        "HIGH"     => 3,
        "MEDIUM"   => 2,
        _          => 1,
    };

    let since = filter.since.clone().unwrap_or_else(|| "1970-01-01".to_string());

    let mut q = String::from(
        "SELECT id, hunt_id, discovered_at, severity, category,
                description, detail, mitre_id, mitre_name
         FROM findings
         WHERE suppressed = 0
           AND discovered_at >= ?
           AND CASE severity
                 WHEN 'CRITICAL' THEN 4
                 WHEN 'HIGH'     THEN 3
                 WHEN 'MEDIUM'   THEN 2
                 WHEN 'LOW'      THEN 1
                 ELSE 0
               END >= ?"
    );

    if filter.hunt_id.is_some() {
        q.push_str(" AND hunt_id = ?");
    }

    q.push_str(" ORDER BY discovered_at DESC LIMIT ?");

    let mut query = sqlx::query(&q)
        .bind(&since)
        .bind(severity_floor);

    if let Some(ref hid) = filter.hunt_id {
        query = query.bind(hid);
    }

    query = query.bind(filter.limit);

    let rows = query
        .fetch_all(pool)
        .await
        .context("Failed to query findings")?;

    Ok(rows.iter().map(|r| FindingRow {
        id:            r.get("id"),
        hunt_id:       r.get("hunt_id"),
        discovered_at: r.get("discovered_at"),
        severity:      r.get("severity"),
        category:      r.get("category"),
        description:   r.get("description"),
        detail:        r.get("detail"),
        mitre_id:      r.get("mitre_id"),
        mitre_name:    r.get("mitre_name"),
    }).collect())
}

#[derive(Debug)]
pub struct HuntSummary {
    pub id:            String,
    pub target:        String,
    pub started_at:    String,
    pub completed_at:  Option<String>,
    pub risk_level:    Option<String>,
    pub risk_score:    Option<i64>,
    pub finding_count: Option<i64>,
}

pub async fn list_hunts(pool: &SqlitePool, limit: i64) -> Result<Vec<HuntSummary>> {
    let rows = sqlx::query(
        "SELECT id, target, started_at, completed_at, risk_level, risk_score, finding_count
         FROM hunts
         WHERE status = 'completed'
         ORDER BY completed_at DESC
         LIMIT ?"
    )
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("Failed to query hunts")?;

    Ok(rows.iter().map(|r| HuntSummary {
        id:            r.get("id"),
        target:        r.get("target"),
        started_at:    r.get("started_at"),
        completed_at:  r.get("completed_at"),
        risk_level:    r.get("risk_level"),
        risk_score:    r.get("risk_score"),
        finding_count: r.get("finding_count"),
    }).collect())
}
