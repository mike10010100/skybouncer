//! Persistence layer for detected dogpile storms (`dogpile_events` table).

use super::*;
use crate::dogpile::{
    CatalystInfo, StormEvent, StormMetrics, StormSeverity, StormStanceVerdict, StormStatus,
};

const STORM_COLUMNS: &str = "id, target_did, target_handle, focal_post_uri, focal_post_snippet, \
    status, severity, started_at_us, updated_at_us, resolved_at_us, metrics_json, \
    catalyst_json, catalyst_qt_uris_json, stance_json, bounces_during_storm, \
    threadgate_applied, postgate_detaches_applied";

fn map_storm_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<StormEvent> {
    let status_str: String = row.get(5)?;
    let severity_str: String = row.get(6)?;
    let metrics_json: String = row.get(10)?;
    let catalyst_json: Option<String> = row.get(11)?;
    let qt_uris_json: String = row.get(12)?;
    let stance_json: Option<String> = row.get(13)?;
    let bounces_raw: i64 = row.get(14)?;
    let threadgate_raw: i64 = row.get(15)?;
    let detaches_raw: i64 = row.get(16)?;

    let status = status_str
        .parse::<StormStatus>()
        .unwrap_or(StormStatus::Active);
    let severity = severity_str
        .parse::<StormSeverity>()
        .unwrap_or(StormSeverity::Elevated);
    let metrics = serde_json::from_str::<StormMetrics>(&metrics_json).unwrap_or_default();
    let top_catalyst = catalyst_json.and_then(|s| serde_json::from_str::<CatalystInfo>(&s).ok());
    let catalyst_qt_uris = serde_json::from_str::<Vec<String>>(&qt_uris_json).unwrap_or_default();
    let stance = stance_json.and_then(|s| serde_json::from_str::<StormStanceVerdict>(&s).ok());

    Ok(StormEvent {
        id: row.get(0)?,
        target_did: row.get(1)?,
        target_handle: row.get(2)?,
        focal_post_uri: row.get(3)?,
        focal_post_snippet: row.get(4)?,
        status,
        severity,
        started_at_us: i64_to_us(row.get(7)?),
        updated_at_us: i64_to_us(row.get(8)?),
        resolved_at_us: row.get::<_, Option<i64>>(9)?.map(i64_to_us),
        metrics,
        top_catalyst,
        catalyst_qt_uris,
        stance,
        bounces_during_storm: u64::try_from(bounces_raw.max(0)).unwrap_or(0),
        threadgate_applied: threadgate_raw != 0,
        postgate_detaches_applied: u64::try_from(detaches_raw.max(0)).unwrap_or(0),
    })
}

impl DeduplicationCache {
    /// Inserts a new active storm or updates the existing active storm for `(target_did, focal_post_uri)`.
    ///
    /// Returns the persisted row `id`.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite insertion/update fails.
    pub fn upsert_active_storm(&self, event: &StormEvent) -> Result<i64, SkybouncerError> {
        let metrics_json = serde_json::to_string(&event.metrics)?;
        let catalyst_json = event
            .top_catalyst
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let qt_uris_json = serde_json::to_string(&event.catalyst_qt_uris)?;
        let stance_json = event
            .stance
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;

        let mut conn = self.conn.lock();
        let tx = conn.transaction().map_err(|e| {
            SkybouncerError::Database(format!("Failed to start storm upsert tx: {e}"))
        })?;

        let existing_id: Option<i64> = {
            let mut stmt = tx.prepare_cached(
                "SELECT id FROM dogpile_events
                 WHERE target_did = ?1 AND focal_post_uri = ?2 AND status = 'active'
                 ORDER BY updated_at_us DESC LIMIT 1;",
            )?;
            stmt.query_row(params![event.target_did, event.focal_post_uri], |r| {
                r.get(0)
            })
            .optional()?
        };

        let storm_id = if let Some(id) = existing_id {
            let mut upd = tx.prepare_cached(
                "UPDATE dogpile_events SET
                    target_handle = COALESCE(?2, target_handle),
                    focal_post_snippet = CASE WHEN ?3 != '' THEN ?3 ELSE focal_post_snippet END,
                    severity = ?4,
                    updated_at_us = ?5,
                    metrics_json = ?6,
                    catalyst_json = ?7,
                    catalyst_qt_uris_json = ?8,
                    stance_json = ?9
                 WHERE id = ?1;",
            )?;
            upd.execute(params![
                id,
                event.target_handle,
                event.focal_post_snippet,
                event.severity.as_str(),
                us_to_i64(event.updated_at_us),
                metrics_json,
                catalyst_json,
                qt_uris_json,
                stance_json,
            ])?;
            id
        } else {
            let mut ins = tx.prepare_cached(
                "INSERT INTO dogpile_events (
                    target_did, target_handle, focal_post_uri, focal_post_snippet,
                    status, severity, started_at_us, updated_at_us, resolved_at_us,
                    metrics_json, catalyst_json, catalyst_qt_uris_json, stance_json,
                    bounces_during_storm, threadgate_applied, postgate_detaches_applied
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16);",
            )?;
            ins.execute(params![
                event.target_did,
                event.target_handle,
                event.focal_post_uri,
                event.focal_post_snippet,
                event.status.as_str(),
                event.severity.as_str(),
                us_to_i64(event.started_at_us),
                us_to_i64(event.updated_at_us),
                event.resolved_at_us.map(us_to_i64),
                metrics_json,
                catalyst_json,
                qt_uris_json,
                stance_json,
                i64::try_from(event.bounces_during_storm).unwrap_or(i64::MAX),
                i64::from(event.threadgate_applied),
                i64::try_from(event.postgate_detaches_applied).unwrap_or(i64::MAX),
            ])?;
            tx.last_insert_rowid()
        };

        tx.commit().map_err(|e| {
            SkybouncerError::Database(format!("Failed to commit storm upsert tx: {e}"))
        })?;

        Ok(storm_id)
    }

    /// Retrieves a single [`StormEvent`] by its primary key ID.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the query fails.
    pub fn get_storm(&self, storm_id: i64) -> Result<Option<StormEvent>, SkybouncerError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(&format!(
            "SELECT {STORM_COLUMNS} FROM dogpile_events WHERE id = ?1 LIMIT 1;"
        ))?;
        Ok(stmt
            .query_row(params![storm_id], map_storm_event)
            .optional()?)
    }

    /// Retrieves the most recently updated active storm for `target_did`.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the query fails.
    pub fn get_latest_active_storm_for(
        &self,
        target_did: &str,
    ) -> Result<Option<StormEvent>, SkybouncerError> {
        let target_did = crate::util::require_non_empty_did(target_did, "target_did")?;
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(&format!(
            "SELECT {STORM_COLUMNS} FROM dogpile_events
             WHERE target_did = ?1 AND status = 'active'
             ORDER BY updated_at_us DESC, id DESC LIMIT 1;"
        ))?;
        Ok(stmt
            .query_row(params![target_did], map_storm_event)
            .optional()?)
    }

    /// Retrieves an active storm for a specific `(target_did, focal_post_uri)` pair.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Config`] if `target_did` is empty/whitespace,
    /// or [`SkybouncerError::Database`] if the query fails.
    pub fn get_active_storm_by_focal_uri(
        &self,
        target_did: &str,
        focal_post_uri: &str,
    ) -> Result<Option<StormEvent>, SkybouncerError> {
        let target_did = crate::util::require_non_empty_did(target_did, "target_did")?;
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(&format!(
            "SELECT {STORM_COLUMNS} FROM dogpile_events
             WHERE target_did = ?1 AND focal_post_uri = ?2 AND status = 'active'
             ORDER BY updated_at_us DESC, id DESC LIMIT 1;"
        ))?;
        Ok(stmt
            .query_row(params![target_did, focal_post_uri], map_storm_event)
            .optional()?)
    }

    /// Lists dogpile storm events optionally scoped to `target_did` and/or `active_only`,
    /// ordered by most recent activity descending.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Config`] if `target_did` is `Some("")`/`Some("   ")`,
    /// or [`SkybouncerError::Database`] if the query fails.
    pub fn list_storms(
        &self,
        target_did: Option<&str>,
        active_only: bool,
        limit: usize,
    ) -> Result<Vec<StormEvent>, SkybouncerError> {
        let scoped_target = match target_did {
            Some(raw) => Some(crate::util::require_non_empty_did(raw, "target_did")?),
            None => None,
        };
        let capped_limit = i64::try_from(limit.clamp(1, 200)).unwrap_or(50);
        let conn = self.conn.lock();

        let sql = match (scoped_target, active_only) {
            (Some(_), true) => format!(
                "SELECT {STORM_COLUMNS} FROM dogpile_events
                 WHERE target_did = ?1 AND status = 'active'
                 ORDER BY updated_at_us DESC, id DESC LIMIT ?2;"
            ),
            (Some(_), false) => format!(
                "SELECT {STORM_COLUMNS} FROM dogpile_events
                 WHERE target_did = ?1
                 ORDER BY updated_at_us DESC, id DESC LIMIT ?2;"
            ),
            (None, true) => format!(
                "SELECT {STORM_COLUMNS} FROM dogpile_events
                 WHERE status = 'active'
                 ORDER BY updated_at_us DESC, id DESC LIMIT ?1;"
            ),
            (None, false) => format!(
                "SELECT {STORM_COLUMNS} FROM dogpile_events
                 ORDER BY updated_at_us DESC, id DESC LIMIT ?1;"
            ),
        };

        let mut stmt = conn.prepare_cached(&sql)?;
        let mut out = Vec::new();
        if let Some(did) = scoped_target {
            let rows = stmt.query_map(params![did, capped_limit], map_storm_event)?;
            for r in rows {
                out.push(r?);
            }
        } else {
            let rows = stmt.query_map(params![capped_limit], map_storm_event)?;
            for r in rows {
                out.push(r?);
            }
        }
        Ok(out)
    }

    /// Increments `bounces_during_storm` for an active storm matching `target_did`
    /// (and `focal_post_uri` if supplied, else the latest active storm for `target_did`).
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Config`] if `target_did` is empty/whitespace,
    /// or [`SkybouncerError::Database`] if the SQLite update fails.
    pub fn increment_storm_bounces(
        &self,
        target_did: &str,
        focal_post_uri: Option<&str>,
        delta: u64,
    ) -> Result<(), SkybouncerError> {
        let target_did = crate::util::require_non_empty_did(target_did, "target_did")?;
        let delta_i64 = i64::try_from(delta).unwrap_or(1);
        let conn = self.conn.lock();
        if let Some(focal) = focal_post_uri.filter(|s| !s.trim().is_empty()) {
            let mut stmt = conn.prepare_cached(
                "UPDATE dogpile_events
                 SET bounces_during_storm = bounces_during_storm + ?3
                 WHERE target_did = ?1 AND focal_post_uri = ?2 AND status = 'active';",
            )?;
            let updated = stmt.execute(params![target_did, focal, delta_i64])?;
            if updated > 0 {
                return Ok(());
            }
        }
        let mut fallback = conn.prepare_cached(
            "UPDATE dogpile_events
             SET bounces_during_storm = bounces_during_storm + ?2
             WHERE id = (
                 SELECT id FROM dogpile_events
                 WHERE target_did = ?1 AND status = 'active'
                 ORDER BY updated_at_us DESC LIMIT 1
             );",
        )?;
        let _ = fallback.execute(params![target_did, delta_i64])?;
        Ok(())
    }

    /// Marks `threadgate_applied` for storms targeting `(target_did, focal_post_uri)`.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Config`] if `target_did` is empty/whitespace,
    /// or [`SkybouncerError::Database`] if the SQLite update fails.
    pub fn mark_storm_threadgate_applied(
        &self,
        target_did: &str,
        focal_post_uri: &str,
        applied: bool,
    ) -> Result<(), SkybouncerError> {
        let target_did = crate::util::require_non_empty_did(target_did, "target_did")?;
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "UPDATE dogpile_events
             SET threadgate_applied = ?3
             WHERE target_did = ?1 AND focal_post_uri = ?2;",
        )?;
        let _ = stmt.execute(params![target_did, focal_post_uri, i64::from(applied)])?;
        Ok(())
    }

    /// Increments `postgate_detaches_applied` for storms targeting `(target_did, focal_post_uri)`.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Config`] if `target_did` is empty/whitespace,
    /// or [`SkybouncerError::Database`] if the SQLite update fails.
    pub fn increment_storm_postgate_detaches(
        &self,
        target_did: &str,
        focal_post_uri: &str,
        count: u64,
    ) -> Result<(), SkybouncerError> {
        let target_did = crate::util::require_non_empty_did(target_did, "target_did")?;
        let count_i64 = i64::try_from(count).unwrap_or(1);
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "UPDATE dogpile_events
             SET postgate_detaches_applied = postgate_detaches_applied + ?3
             WHERE target_did = ?1 AND focal_post_uri = ?2;",
        )?;
        let _ = stmt.execute(params![target_did, focal_post_uri, count_i64])?;
        Ok(())
    }

    /// Updates a storm's lifecycle `status` and `resolved_at_us`, optionally scoped by `target_did`.
    ///
    /// Returns `true` if a matching row was updated.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Config`] if `target_did` is `Some("")`/`Some("   ")`,
    /// or [`SkybouncerError::Database`] if the SQLite update fails.
    pub fn update_storm_status(
        &self,
        target_did: Option<&str>,
        storm_id: i64,
        status: StormStatus,
        resolved_at_us: Option<u64>,
    ) -> Result<bool, SkybouncerError> {
        let scoped_target = match target_did {
            Some(raw) => Some(crate::util::require_non_empty_did(raw, "target_did")?),
            None => None,
        };
        let conn = self.conn.lock();
        let updated = match scoped_target {
            Some(did) => {
                let mut stmt = conn.prepare_cached(
                    "UPDATE dogpile_events
                     SET status = ?3, resolved_at_us = ?4
                     WHERE id = ?1 AND target_did = ?2;",
                )?;
                stmt.execute(params![
                    storm_id,
                    did,
                    status.as_str(),
                    resolved_at_us.map(us_to_i64)
                ])?
            }
            None => {
                let mut stmt = conn.prepare_cached(
                    "UPDATE dogpile_events
                     SET status = ?2, resolved_at_us = ?3
                     WHERE id = ?1;",
                )?;
                stmt.execute(params![
                    storm_id,
                    status.as_str(),
                    resolved_at_us.map(us_to_i64)
                ])?
            }
        };
        Ok(updated > 0)
    }
}
