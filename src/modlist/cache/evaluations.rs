use super::*;

impl DeduplicationCache {
    /// Retrieves a cached evaluation verdict for the given cache key.
    ///
    /// If the evaluation has expired, it is deleted from the cache and `Ok(None)` is returned.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] or [`SkybouncerError::Serialization`] on error.
    pub fn get_evaluation(&self, cache_key: &str) -> Result<Option<Verdict>, SkybouncerError> {
        let now_us = current_time_us();
        let conn = self.conn.lock();

        let mut stmt = conn.prepare_cached(
            "SELECT verdict_json, expires_at
                 FROM evaluation_cache
                 WHERE cache_key = ?1;",
        )?;

        let row: Option<(String, i64)> = stmt
            .query_row(params![cache_key], |r| Ok((r.get(0)?, r.get(1)?)))
            .optional()?;

        match row {
            Some((verdict_json, expires_at_i64)) => {
                let expires_at_u64 = i64_to_us(expires_at_i64);

                if now_us >= expires_at_u64 {
                    let mut del_stmt =
                        conn.prepare_cached("DELETE FROM evaluation_cache WHERE cache_key = ?1;")?;
                    let _ = del_stmt.execute(params![cache_key]);
                    Ok(None)
                } else {
                    let verdict: Verdict = serde_json::from_str(&verdict_json)?;
                    Ok(Some(verdict))
                }
            }
            None => Ok(None),
        }
    }

    /// Stores a classifier verdict in the evaluation cache with the specified TTL.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] or [`SkybouncerError::Serialization`] on error.
    pub fn set_evaluation(
        &self,
        cache_key: &str,
        author_did: &str,
        verdict: &Verdict,
        ttl: Duration,
    ) -> Result<(), SkybouncerError> {
        let verdict_json = serde_json::to_string(verdict)?;
        let now_us = current_time_us();
        let ttl_us = u64::try_from(ttl.as_micros()).unwrap_or(u64::MAX);
        let expires_us = now_us.saturating_add(ttl_us);

        let evaluated_at_i64 = us_to_i64(now_us);
        let expires_at_i64 = us_to_i64(expires_us);

        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "INSERT INTO evaluation_cache (
                    cache_key, author_did, verdict_json, evaluated_at, expires_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(cache_key) DO UPDATE SET
                     author_did = excluded.author_did,
                     verdict_json = excluded.verdict_json,
                     evaluated_at = excluded.evaluated_at,
                     expires_at = excluded.expires_at;",
        )?;

        stmt.execute(params![
            cache_key,
            author_did,
            verdict_json,
            evaluated_at_i64,
            expires_at_i64,
        ])?;

        Ok(())
    }

    /// Purges all expired evaluation records from the cache, returning the count of deleted rows.
    ///
    /// Also prunes `evaluation_log` per `target_did` to retain at most 5,000 recent evaluations
    /// per protected user, guarded by a fast `GROUP BY target_did HAVING COUNT(*) > 5000` check.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the delete query fails.
    pub fn prune_expired_evaluations(&self) -> Result<usize, SkybouncerError> {
        const MAX_EVAL_LOGS_PER_TARGET: i64 = 5_000;
        let now_us = current_time_us();
        let now_i64 = us_to_i64(now_us);

        let conn = self.conn.lock();
        let mut stmt =
            conn.prepare_cached("DELETE FROM evaluation_cache WHERE expires_at <= ?1;")?;
        let deleted = stmt.execute(params![now_i64])?;

        // Fast index-covered check: only prune targets that actually exceed 5,000 rows.
        let over_cap_targets: Vec<String> = {
            let mut count_stmt = conn.prepare_cached(
                "SELECT target_did FROM evaluation_log GROUP BY target_did HAVING COUNT(*) > ?1;",
            )?;
            let rows = count_stmt.query_map(params![MAX_EVAL_LOGS_PER_TARGET], |row| row.get(0))?;
            let mut targets = Vec::new();
            for row in rows {
                targets.push(row?);
            }
            targets
        };

        if !over_cap_targets.is_empty() {
            let mut prune_target_stmt = conn.prepare_cached(
                "DELETE FROM evaluation_log
                 WHERE target_did = ?1
                   AND id NOT IN (
                       SELECT id FROM evaluation_log
                       WHERE target_did = ?1
                       ORDER BY timestamp_us DESC, id DESC
                       LIMIT ?2
                   );",
            )?;
            for target_did in over_cap_targets {
                let _ = prune_target_stmt.execute(params![target_did, MAX_EVAL_LOGS_PER_TARGET]);
            }
        }

        Ok(deleted)
    }

    /// Counts the total number of evaluation cache entries (including unexpired ones).
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if the query fails.
    pub fn count_evaluations(&self) -> Result<usize, SkybouncerError> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached("SELECT COUNT(*) FROM evaluation_cache;")?;
        let count: i64 = stmt.query_row([], |row| row.get(0))?;
        Ok(usize::try_from(count.max(0)).unwrap_or(0))
    }

    /// Records a comprehensive AI evaluation log entry (Tier 1 & Tier 2 breakdown).
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite insertion fails.
    pub fn record_evaluation_log(&self, entry: &NewEvaluationLog) -> Result<i64, SkybouncerError> {
        let timestamp_i64 = us_to_i64(entry.timestamp_us);
        let has_images_i64 = if entry.has_images { 1 } else { 0 };
        let escalated_i64 = if entry.escalated { 1 } else { 0 };
        let primary_conf_f64 = entry.primary_confidence;
        let fallback_conf_f64 = entry.fallback_confidence;
        let final_conf_f64 = entry.final_confidence;

        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "INSERT INTO evaluation_log (
                timestamp_us, source, post_uri, post_text,
                author_did, author_handle, target_did, target_handle,
                has_images, primary_model, primary_action, primary_confidence,
                primary_category, primary_reason, escalated, escalation_reason,
                fallback_model, fallback_action, fallback_confidence,
                fallback_category, fallback_reason, final_action, final_confidence,
                outcome
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24
             );",
        )?;

        stmt.execute(params![
            timestamp_i64,
            entry.source,
            entry.post_uri,
            entry.post_text,
            entry.author_did,
            entry.author_handle,
            entry.target_did,
            entry.target_handle,
            has_images_i64,
            entry.primary_model,
            entry.primary_action,
            primary_conf_f64,
            entry.primary_category,
            entry.primary_reason,
            escalated_i64,
            entry.escalation_reason,
            entry.fallback_model,
            entry.fallback_action,
            fallback_conf_f64,
            entry.fallback_category,
            entry.fallback_reason,
            entry.final_action,
            final_conf_f64,
            entry.outcome,
        ])?;

        Ok(conn.last_insert_rowid())
    }

    /// Lists evaluation log entries ordered by timestamp descending, with optional filtering.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite query fails.
    pub fn list_evaluation_logs(
        &self,
        target_did: Option<&str>,
        source: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<EvaluationLogEntry>, SkybouncerError> {
        let limit_i64 = i64::try_from(limit.clamp(1, 200)).unwrap_or(50);
        let offset_i64 = i64::try_from(offset).unwrap_or(0);
        let clean_target = match target_did {
            Some(raw) => Some(crate::util::require_non_empty_did(raw, "target_did")?),
            None => None,
        };
        let clean_source = source.filter(|s| !s.trim().is_empty() && *s != "all");
        let conn = self.conn.lock();

        let map_row = |row: &rusqlite::Row<'_>| -> rusqlite::Result<EvaluationLogEntry> {
            let id: i64 = row.get(0)?;
            let ts_i64: i64 = row.get(1)?;
            let timestamp_us = i64_to_us(ts_i64);
            let source: String = row.get(2)?;
            let post_uri: String = row.get(3)?;
            let post_text: String = row.get(4)?;
            let author_did: String = row.get(5)?;
            let author_handle: String = row.get(6)?;
            let target_did: String = row.get(7)?;
            let target_handle: String = row.get(8)?;
            let has_images: bool = row.get::<_, i64>(9)? != 0;
            let primary_model: String = row.get(10)?;
            let primary_action: String = row.get(11)?;
            let primary_confidence: f64 = row.get(12)?;
            let primary_category: String = row.get(13)?;
            let primary_reason: String = row.get(14)?;
            let escalated: bool = row.get::<_, i64>(15)? != 0;
            let escalation_reason: Option<String> = row.get(16)?;
            let fallback_model: Option<String> = row.get(17)?;
            let fallback_action: Option<String> = row.get(18)?;
            let fallback_confidence: Option<f64> = row.get(19)?;
            let fallback_category: Option<String> = row.get(20)?;
            let fallback_reason: Option<String> = row.get(21)?;
            let final_action: String = row.get(22)?;
            let final_confidence: f64 = row.get(23)?;
            let outcome: String = row.get(24)?;

            Ok(EvaluationLogEntry {
                id,
                timestamp_us,
                source,
                post_uri,
                post_text,
                author_did,
                author_handle,
                target_did,
                target_handle,
                has_images,
                primary_model,
                primary_action,
                primary_confidence,
                primary_category,
                primary_reason,
                escalated,
                escalation_reason,
                fallback_model,
                fallback_action,
                fallback_confidence,
                fallback_category,
                fallback_reason,
                final_action,
                final_confidence,
                outcome,
            })
        };

        let mut list = Vec::new();
        match (clean_target, clean_source) {
            (Some(t), Some(s)) => {
                let mut stmt = conn.prepare_cached(
                    "SELECT id, timestamp_us, source, post_uri, post_text,
                            author_did, author_handle, target_did, target_handle,
                            has_images, primary_model, primary_action, primary_confidence,
                            primary_category, primary_reason, escalated, escalation_reason,
                            fallback_model, fallback_action, fallback_confidence,
                            fallback_category, fallback_reason, final_action, final_confidence,
                            outcome
                     FROM evaluation_log
                     WHERE target_did = ?1 AND source = ?2
                     ORDER BY timestamp_us DESC, id DESC LIMIT ?3 OFFSET ?4;",
                )?;
                let rows = stmt.query_map(params![t, s, limit_i64, offset_i64], map_row)?;
                for r in rows {
                    list.push(r?);
                }
            }
            (Some(t), None) => {
                let mut stmt = conn.prepare_cached(
                    "SELECT id, timestamp_us, source, post_uri, post_text,
                            author_did, author_handle, target_did, target_handle,
                            has_images, primary_model, primary_action, primary_confidence,
                            primary_category, primary_reason, escalated, escalation_reason,
                            fallback_model, fallback_action, fallback_confidence,
                            fallback_category, fallback_reason, final_action, final_confidence,
                            outcome
                     FROM evaluation_log
                     WHERE target_did = ?1
                     ORDER BY timestamp_us DESC, id DESC LIMIT ?2 OFFSET ?3;",
                )?;
                let rows = stmt.query_map(params![t, limit_i64, offset_i64], map_row)?;
                for r in rows {
                    list.push(r?);
                }
            }
            (None, Some(s)) => {
                let mut stmt = conn.prepare_cached(
                    "SELECT id, timestamp_us, source, post_uri, post_text,
                            author_did, author_handle, target_did, target_handle,
                            has_images, primary_model, primary_action, primary_confidence,
                            primary_category, primary_reason, escalated, escalation_reason,
                            fallback_model, fallback_action, fallback_confidence,
                            fallback_category, fallback_reason, final_action, final_confidence,
                            outcome
                     FROM evaluation_log
                     WHERE source = ?1
                     ORDER BY timestamp_us DESC, id DESC LIMIT ?2 OFFSET ?3;",
                )?;
                let rows = stmt.query_map(params![s, limit_i64, offset_i64], map_row)?;
                for r in rows {
                    list.push(r?);
                }
            }
            (None, None) => {
                let mut stmt = conn.prepare_cached(
                    "SELECT id, timestamp_us, source, post_uri, post_text,
                            author_did, author_handle, target_did, target_handle,
                            has_images, primary_model, primary_action, primary_confidence,
                            primary_category, primary_reason, escalated, escalation_reason,
                            fallback_model, fallback_action, fallback_confidence,
                            fallback_category, fallback_reason, final_action, final_confidence,
                            outcome
                     FROM evaluation_log
                     ORDER BY timestamp_us DESC, id DESC LIMIT ?1 OFFSET ?2;",
                )?;
                let rows = stmt.query_map(params![limit_i64, offset_i64], map_row)?;
                for r in rows {
                    list.push(r?);
                }
            }
        }
        Ok(list)
    }

    /// Counts evaluation logs matching optional target DID and source filters.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite query fails.
    pub fn count_evaluation_logs(
        &self,
        target_did: Option<&str>,
        source: Option<&str>,
    ) -> Result<usize, SkybouncerError> {
        let clean_target = match target_did {
            Some(raw) => Some(crate::util::require_non_empty_did(raw, "target_did")?),
            None => None,
        };
        let clean_source = source.filter(|s| !s.trim().is_empty() && *s != "all");
        let conn = self.conn.lock();

        let count: i64 = match (clean_target, clean_source) {
            (Some(t), Some(s)) => {
                let mut stmt = conn.prepare_cached(
                    "SELECT COUNT(*) FROM evaluation_log WHERE target_did = ?1 AND source = ?2;",
                )?;
                stmt.query_row(params![t, s], |row| row.get(0))?
            }
            (Some(t), None) => {
                let mut stmt = conn
                    .prepare_cached("SELECT COUNT(*) FROM evaluation_log WHERE target_did = ?1;")?;
                stmt.query_row(params![t], |row| row.get(0))?
            }
            (None, Some(s)) => {
                let mut stmt =
                    conn.prepare_cached("SELECT COUNT(*) FROM evaluation_log WHERE source = ?1;")?;
                stmt.query_row(params![s], |row| row.get(0))?
            }
            (None, None) => {
                let mut stmt = conn.prepare_cached("SELECT COUNT(*) FROM evaluation_log;")?;
                stmt.query_row([], |row| row.get(0))?
            }
        };
        Ok(usize::try_from(count.max(0)).unwrap_or(0))
    }

    /// Prunes evaluation logs to prevent unbounded growth, retaining at most `max_retained` newest rows.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite execution fails.
    pub fn prune_evaluation_logs(&self, max_retained: usize) -> Result<usize, SkybouncerError> {
        let max_i64 = i64::try_from(max_retained.max(1)).unwrap_or(5000);
        let conn = self.conn.lock();
        let mut stmt = conn.prepare_cached(
            "DELETE FROM evaluation_log WHERE id NOT IN (
                SELECT id FROM evaluation_log ORDER BY timestamp_us DESC, id DESC LIMIT ?1
             );",
        )?;
        let deleted = stmt.execute(params![max_i64])?;
        Ok(deleted)
    }
}
