use super::*;

impl SkybouncerEngine {
    /// Checks whether an account is currently recorded as bounced in the SQLite cache.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite query fails.
    pub fn is_bounced(&self, subject_did: &str) -> Result<bool, SkybouncerError> {
        self.cache.is_bounced(subject_did)
    }

    /// Retrieves detailed record of a bounced violator if present.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite query fails.
    pub fn get_bounced_user(
        &self,
        subject_did: &str,
    ) -> Result<Option<BouncedUser>, SkybouncerError> {
        self.cache.get_bounced_user(subject_did)
    }

    /// Lists recently bounced violators ordered by most recent bounce timestamp descending.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite query fails.
    pub fn list_recent_bounces(&self, limit: usize) -> Result<Vec<BouncedUser>, SkybouncerError> {
        self.cache.list_recent_bounces(limit)
    }

    /// Lists recently bounced violators filtered by an optional protected user DID,
    /// ordered by most recent bounce timestamp descending.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite query fails.
    pub fn list_recent_bounces_for(
        &self,
        protected_did: Option<&str>,
        limit: usize,
    ) -> Result<Vec<BouncedUser>, SkybouncerError> {
        self.cache.list_recent_bounces_for(protected_did, limit)
    }

    /// Pardons an account by deleting its listitems from the PDS and purging the cache.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if PDS deletion or cache mutation fails.
    pub async fn pardon_user(
        &self,
        protected_did: &str,
        subject_did: &str,
    ) -> Result<bool, SkybouncerError> {
        let pds_client = self.resolve_pds_client_for(protected_did).await?;
        self.modlist_manager
            .pardon_user(&pds_client, protected_did, subject_did)
            .await
    }

    /// Upgrades a temporary bounce for `(protected_did, subject_did)` to permanent
    /// (`expires_at = NULL`).
    ///
    /// Returns:
    /// - `Ok(Some(true))` if a temporary bounce was found and upgraded to permanent.
    /// - `Ok(Some(false))` if a bounce record exists and is already permanent.
    /// - `Ok(None)` if no bounce record exists for `(protected_did, subject_did)`.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if SQLite cache mutation fails.
    pub async fn upgrade_bounce_to_permanent(
        &self,
        protected_did: &str,
        subject_did: &str,
    ) -> Result<Option<bool>, SkybouncerError> {
        self.modlist_manager
            .upgrade_bounce_to_permanent(protected_did, subject_did)
            .await
    }

    /// Manually bounces (or re-bounces after a pardon) `subject_did` onto `protected_did`'s
    /// moderation list using the protected user's active [`crate::classifier::BounceDuration`].
    ///
    /// If `subject_did` was previously allowlisted (e.g. via `pardon and allow`), removes their
    /// allowlist immunity once the bounce is active. Returns `(outcome, was_allowlisted)`.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if PDS mutation or SQLite cache access fails.
    pub async fn manual_bounce_user(
        &self,
        protected_did: &str,
        subject_did: &str,
    ) -> Result<(ManualBounceOutcome, bool), SkybouncerError> {
        if let Some(existing) = self
            .cache
            .get_bounced_user_for(protected_did, subject_did)?
        {
            let was_allowlisted = self.remove_from_allowlist(protected_did, subject_did)?;
            return Ok((
                ManualBounceOutcome::AlreadyBounced {
                    is_permanent: existing.expires_at.is_none(),
                },
                was_allowlisted,
            ));
        }

        let duration = self.rubric_for(protected_did).bounce_duration;
        let pds_client = self.resolve_pds_client_for(protected_did).await?;
        let outcome = self
            .modlist_manager
            .manual_bounce_or_perm(&pds_client, protected_did, subject_did, duration, false)
            .await
            .inspect_err(|_e| {
                self.stats
                    .errors_encountered
                    .fetch_add(1, Ordering::Relaxed);
            })?;

        if matches!(outcome, ManualBounceOutcome::Bounced { .. }) {
            self.stats.bounces_executed.fetch_add(1, Ordering::Relaxed);
            self.stats.bounced.fetch_add(1, Ordering::Relaxed);
        }
        let was_allowlisted = self.remove_from_allowlist(protected_did, subject_did)?;
        Ok((outcome, was_allowlisted))
    }

    /// Permanently blocks `subject_did` on `protected_did`'s moderation list:
    /// - If `subject_did` has an active temporary bounce, upgrades it in-place to permanent with
    ///   zero extra PDS writes.
    /// - If `subject_did` is not currently bounced (e.g. after `pardon` or TTL expiration),
    ///   creates a permanent `app.bsky.graph.listitem` record on the PDS and restores any prior
    ///   bounce rationale/post metadata from `bounce_history`.
    ///
    /// Also removes `subject_did` from `protected_did`'s allowlist if present.
    /// Returns `(outcome, was_allowlisted)`.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if PDS mutation or SQLite cache access fails.
    pub async fn perm_bounce_user(
        &self,
        protected_did: &str,
        subject_did: &str,
    ) -> Result<(ManualBounceOutcome, bool), SkybouncerError> {
        match self
            .upgrade_bounce_to_permanent(protected_did, subject_did)
            .await?
        {
            Some(true) => {
                let was_allowlisted = self.remove_from_allowlist(protected_did, subject_did)?;
                return Ok((ManualBounceOutcome::UpgradedToPermanent, was_allowlisted));
            }
            Some(false) => {
                let was_allowlisted = self.remove_from_allowlist(protected_did, subject_did)?;
                return Ok((
                    ManualBounceOutcome::AlreadyBounced { is_permanent: true },
                    was_allowlisted,
                ));
            }
            None => {}
        }

        let pds_client = self.resolve_pds_client_for(protected_did).await?;
        let outcome = self
            .modlist_manager
            .manual_bounce_or_perm(
                &pds_client,
                protected_did,
                subject_did,
                crate::classifier::BounceDuration::Permanent,
                true,
            )
            .await
            .inspect_err(|_e| {
                self.stats
                    .errors_encountered
                    .fetch_add(1, Ordering::Relaxed);
            })?;

        if matches!(outcome, ManualBounceOutcome::Bounced { .. }) {
            self.stats.bounces_executed.fetch_add(1, Ordering::Relaxed);
            self.stats.bounced.fetch_add(1, Ordering::Relaxed);
        }
        let was_allowlisted = self.remove_from_allowlist(protected_did, subject_did)?;
        Ok((outcome, was_allowlisted))
    }

    /// Pardons an account by deleting its listitems from the PDS, purging the cache,
    /// and immunizes them from future moderation actions by adding them to the allowlist.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if PDS deletion, cache mutation, or allowlist insertion fails.
    pub async fn pardon_and_allowlist(
        &self,
        protected_did: &str,
        subject_did: &str,
        reason: Option<&str>,
    ) -> Result<bool, SkybouncerError> {
        let pardoned = self.pardon_user(protected_did, subject_did).await?;
        self.add_to_allowlist(
            protected_did,
            subject_did,
            reason.or(Some("Immunized via pardon")),
        )?;
        Ok(pardoned)
    }

    /// Checks whether an author is in the protected user's allowlist (<1µs in-memory lookup).
    #[must_use]
    pub fn is_allowlisted(&self, protected_did: &str, author_did: &str) -> bool {
        self.gate.is_allowlisted(protected_did, author_did)
    }

    /// Adds an author to both persistent SQLite cache and in-memory allowlist for a protected user.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if database insertion fails.
    pub fn add_to_allowlist(
        &self,
        protected_did: &str,
        author_did: &str,
        reason: Option<&str>,
    ) -> Result<(), SkybouncerError> {
        self.cache
            .add_to_allowlist(protected_did, author_did, reason)?;
        self.gate.add_to_allowlist(protected_did, author_did);
        Ok(())
    }

    /// Removes an author from both persistent SQLite cache and in-memory allowlist for a protected user.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if database deletion fails.
    pub fn remove_from_allowlist(
        &self,
        protected_did: &str,
        author_did: &str,
    ) -> Result<bool, SkybouncerError> {
        let removed = self
            .cache
            .remove_from_allowlist(protected_did, author_did)?;
        self.gate.remove_from_allowlist(protected_did, author_did);
        Ok(removed)
    }

    /// Lists all allowlisted authors for a protected user from the persistent database.
    ///
    /// # Errors
    /// Returns [`SkybouncerError::Database`] if database query fails.
    pub fn list_allowlist(
        &self,
        protected_did: &str,
    ) -> Result<Vec<crate::modlist::AllowlistEntry>, SkybouncerError> {
        self.cache.list_allowlist(protected_did)
    }

    /// Ensures that the parent moderation list exists on the sovereign PDS.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if list provisioning fails.
    pub async fn ensure_mod_list(&self, protected_did: &str) -> Result<String, SkybouncerError> {
        let pds_client = self.resolve_pds_client_for(protected_did).await?;
        self.modlist_manager
            .ensure_mod_list(&pds_client, protected_did)
            .await
    }

    /// Ensures that an `app.bsky.graph.listblock` record exists on the sovereign PDS to auto-block list members.
    ///
    /// # Errors
    /// Returns [`SkybouncerError`] if listblock creation fails.
    pub async fn ensure_list_blocked(
        &self,
        protected_did: &str,
        list_uri: &str,
    ) -> Result<(), SkybouncerError> {
        let pds_client = self.resolve_pds_client_for(protected_did).await?;
        self.modlist_manager
            .ensure_list_blocked(&pds_client, protected_did, list_uri)
            .await
    }
}
