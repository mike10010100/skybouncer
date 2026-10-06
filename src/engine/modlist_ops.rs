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
