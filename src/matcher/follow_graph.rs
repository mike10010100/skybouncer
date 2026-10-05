//! In-memory thread-safe follow graph with dynamic Jetstream synchronization.
//!
//! Maintains active follow sets for protected users to enforce the
//! **Non-Followed Cost Control Gate** (<1µs latency, $0 classification cost).
//!
//! # Reverse Index & Jetstream Deletion Semantics
//! In the AT Protocol sync firehose (Jetstream), [`CommitOperation::Delete`]
//! commits for `app.bsky.graph.follow` contain only the `rkey` and `did`; the
//! record payload (`subject` DID) is completely omitted.
//!
//! To correctly handle unfollow events in real-time without making costly remote
//! network requests to an AppView or PDS, [`FollowGraph`] maintains an internal
//! reverse index mapping `(protected_did, rkey) -> followed_did`.

use parking_lot::RwLock;
use skybase::ingest::{CommitOperation, JetstreamCommit};
use std::collections::{HashMap, HashSet};

/// Synchronization event result emitted when processing Jetstream commits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FollowSyncEvent {
    /// Follow was added for a protected user.
    FollowAdded {
        /// Protected user DID.
        protected_did: String,
        /// Record key (`rkey`) of the follow.
        rkey: String,
        /// Followed account DID.
        followed_did: String,
    },
    /// Follow was removed for a protected user via an unfollow delete commit.
    FollowRemoved {
        /// Protected user DID.
        protected_did: String,
        /// Record key (`rkey`) of the follow.
        rkey: String,
        /// Followed account DID that was removed.
        followed_did: String,
    },
    /// Commit was ignored (unrelated collection, untracked DID, or missing payload).
    Ignored,
}

/// Deterministic ordering key for synthetic hydration rkeys.
///
/// Ranks `hydrate_<n>` by ascending numeric index (so `hydrate_0` before `hydrate_10`),
/// then all other synthetic keys (e.g. `seed_*`) lexicographically. Keeps synthetic
/// fallback selection stable across restarts and repeated commits.
fn synthetic_key_rank(key: &str) -> (u8, u64, String) {
    if let Some(rest) = key.strip_prefix("hydrate_") {
        (0, rest.parse::<u64>().unwrap_or(u64::MAX), String::new())
    } else {
        (1, 0, key.to_string())
    }
}

/// Internal state holding the follow sets and reverse indexes.
#[derive(Debug, Default)]
struct FollowGraphInner {
    /// Maps `protected_did` -> Set of `followed_did`s.
    /// Used for O(1) sub-microsecond containment checks.
    follows: HashMap<String, HashSet<String>>,

    /// Reverse index mapping: `protected_did` -> (`rkey` -> `followed_did`).
    /// Enables O(1) removal of follows when processing `CommitOperation::Delete`.
    rkey_to_followed: HashMap<String, HashMap<String, String>>,
}

/// Thread-safe in-memory follow graph tracking accounts followed by protected users.
///
/// Enables sub-microsecond (<1µs) lookup to immediately bypass interactions from
/// accounts the protected user follows, eliminating unnecessary classification API calls.
#[derive(Debug, Default)]
pub struct FollowGraph {
    inner: RwLock<FollowGraphInner>,
}

impl FollowGraph {
    /// Creates an empty [`FollowGraph`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sub-microsecond query checking if `protected_did` follows `candidate_did`.
    ///
    /// Acquires a shared read lock from [`parking_lot::RwLock`]. Executes in ~50–80ns
    /// with zero heap allocations.
    ///
    /// # Arguments
    /// * `protected_did` - DID of the protected user.
    /// * `candidate_did` - DID of the interaction author.
    #[must_use]
    pub fn is_following(&self, protected_did: &str, candidate_did: &str) -> bool {
        let guard = self.inner.read();
        guard
            .follows
            .get(protected_did)
            .is_some_and(|set| set.contains(candidate_did))
    }

    /// Inserts a followed account relationship with its record key.
    ///
    /// Updates both the direct lookup set and the reverse `rkey -> followed_did` index.
    ///
    /// # Arguments
    /// * `protected_did` - DID of the follower (the protected user).
    /// * `rkey` - Record key (`rkey`) of the follow record in ATProto.
    /// * `followed_did` - DID of the account being followed.
    pub fn add_follow(
        &self,
        protected_did: impl Into<String>,
        rkey: impl Into<String>,
        followed_did: impl Into<String>,
    ) {
        let p_did = protected_did.into();
        let rk = rkey.into();
        let f_did = followed_did.into();

        let mut guard = self.inner.write();

        // Check if an existing follow for this rkey pointed to a different DID
        if let Some(user_rkeys) = guard.rkey_to_followed.get_mut(&p_did) {
            if let Some(old_followed) = user_rkeys.insert(rk.clone(), f_did.clone()) {
                if old_followed != f_did {
                    // Clean up old followed DID if no other rkey points to it
                    let still_referenced = user_rkeys.values().any(|v| v == &old_followed);
                    if !still_referenced {
                        if let Some(set) = guard.follows.get_mut(&p_did) {
                            set.remove(&old_followed);
                        }
                    }
                }
            }
        } else {
            let mut user_rkeys = HashMap::new();
            user_rkeys.insert(rk, f_did.clone());
            guard.rkey_to_followed.insert(p_did.clone(), user_rkeys);
        }

        guard.follows.entry(p_did).or_default().insert(f_did);
    }

    /// Removes a followed account using its record key (`rkey`).
    ///
    /// Uses the reverse index to resolve `rkey -> followed_did` and removes the
    /// relationship from the active follow set.
    ///
    /// Returns `Some(followed_did)` if the follow existed and was removed, or `None`.
    pub fn remove_follow_by_rkey(&self, protected_did: &str, rkey: &str) -> Option<String> {
        let mut guard = self.inner.write();

        let followed_did = guard
            .rkey_to_followed
            .get_mut(protected_did)?
            .remove(rkey)?;

        // Only remove from active follows if no other rkey references the same followed DID
        let still_referenced = guard
            .rkey_to_followed
            .get(protected_did)
            .is_some_and(|m| m.values().any(|v| v == &followed_did));

        if !still_referenced {
            if let Some(set) = guard.follows.get_mut(protected_did) {
                set.remove(&followed_did);
            }
        }

        Some(followed_did)
    }

    /// Removes a followed account directly by target DID.
    ///
    /// Also prunes any associated reverse index entries for that DID.
    /// Returns `true` if the follow was present and removed.
    pub fn remove_follow_by_did(&self, protected_did: &str, followed_did: &str) -> bool {
        let mut guard = self.inner.write();

        let removed = guard
            .follows
            .get_mut(protected_did)
            .is_some_and(|set| set.remove(followed_did));

        if removed {
            if let Some(user_rkeys) = guard.rkey_to_followed.get_mut(protected_did) {
                user_rkeys.retain(|_, v| v != followed_did);
            }
        }

        removed
    }

    /// Removes a synthetic follow relationship when a real Jetstream delete commit arrives
    /// for an untracked TID, reconciling cold-start hydration desync.
    ///
    /// Inspects the reverse index for `protected_did` to find a synthetic key (prefixed with
    /// `hydrate_` or `seed_`), removes that key, and removes the followed account from the
    /// active set if not referenced by any other record key.
    ///
    /// # Determinism & inherent ambiguity
    ///
    /// A follow `Delete` commit does not carry the followed account, so a real-TID delete
    /// arriving after synthetic hydration cannot be correlated to a specific account. This
    /// reconciliation is therefore inherently best-effort. To keep behavior reproducible across
    /// restarts and repeated commits, the synthetic key is selected deterministically
    /// (lowest numeric `hydrate_*` index first, then `seed_*` lexicographically) rather than
    /// relying on `HashMap` iteration order. Real (non-synthetic) rkeys are never selected.
    ///
    /// # Arguments
    /// * `protected_did` - DID of the follower (the protected user).
    ///
    /// Returns `Some(followed_did)` if a synthetic follow was found and removed, or `None`.
    pub fn remove_synthetic_follow_fallback(&self, protected_did: &str) -> Option<String> {
        let mut guard = self.inner.write();

        let (followed_did, still_referenced) = {
            let user_rkeys = guard.rkey_to_followed.get_mut(protected_did)?;
            let synthetic_key = user_rkeys
                .keys()
                .filter(|k| k.starts_with("hydrate_") || k.starts_with("seed_"))
                .min_by_key(|k| synthetic_key_rank(k))
                .cloned()?;
            let followed_did = user_rkeys.remove(&synthetic_key)?;
            let still_referenced = user_rkeys.values().any(|v| v == &followed_did);
            (followed_did, still_referenced)
        };

        if !still_referenced {
            if let Some(set) = guard.follows.get_mut(protected_did) {
                set.remove(&followed_did);
            }
        }

        Some(followed_did)
    }

    /// Synchronizes the follow graph from a Jetstream firehose commit in real-time.
    ///
    /// # Invariants
    /// 1. Commits for collections other than `app.bsky.graph.follow` are immediately ignored.
    /// 2. Commits authored by DIDs not in `protected_dids` are immediately ignored with zero lock contention.
    /// 3. [`CommitOperation::Create`] and [`CommitOperation::Update`] parse the `subject` DID from the record payload.
    /// 4. [`CommitOperation::Delete`] removes the follow using the reverse `rkey` index with fallbacks for synthetic hydration keys.
    pub fn handle_commit(
        &self,
        commit: &JetstreamCommit,
        protected_dids: &HashSet<String>,
    ) -> FollowSyncEvent {
        if commit.collection != "app.bsky.graph.follow" || !protected_dids.contains(&commit.did) {
            return FollowSyncEvent::Ignored;
        }

        match commit.operation {
            CommitOperation::Create | CommitOperation::Update => {
                let subject_did = commit
                    .record
                    .as_ref()
                    .and_then(|r| r.get("subject"))
                    .and_then(|s| s.as_str());

                match subject_did {
                    Some(subject) => {
                        self.add_follow(&commit.did, &commit.rkey, subject);
                        FollowSyncEvent::FollowAdded {
                            protected_did: commit.did.clone(),
                            rkey: commit.rkey.clone(),
                            followed_did: subject.to_string(),
                        }
                    }
                    None => {
                        tracing::warn!(
                            did = %commit.did,
                            rkey = %commit.rkey,
                            "Missing or invalid 'subject' in follow commit record"
                        );
                        FollowSyncEvent::Ignored
                    }
                }
            }
            CommitOperation::Delete => {
                // 1. Try exact rkey match in reverse index
                let removed = self.remove_follow_by_rkey(&commit.did, &commit.rkey);

                // 2. Fallback: Check if payload specifies subject DID
                let removed = removed.or_else(|| {
                    commit
                        .record
                        .as_ref()
                        .and_then(|r| r.get("subject"))
                        .and_then(|s| s.as_str())
                        .and_then(|subject| {
                            if self.remove_follow_by_did(&commit.did, subject) {
                                Some(subject.to_string())
                            } else {
                                None
                            }
                        })
                });

                // 3. Fallback: Check if rkey itself is a DID
                let removed = removed.or_else(|| {
                    if commit.rkey.starts_with("did:")
                        && self.remove_follow_by_did(&commit.did, &commit.rkey)
                    {
                        Some(commit.rkey.clone())
                    } else {
                        None
                    }
                });

                // 4. Fallback: Reconcile synthetic rkey if present
                let removed =
                    removed.or_else(|| self.remove_synthetic_follow_fallback(&commit.did));

                match removed {
                    Some(followed_did) => FollowSyncEvent::FollowRemoved {
                        protected_did: commit.did.clone(),
                        rkey: commit.rkey.clone(),
                        followed_did,
                    },
                    None => {
                        tracing::debug!(
                            did = %commit.did,
                            rkey = %commit.rkey,
                            "Delete follow commit for untracked rkey"
                        );
                        FollowSyncEvent::Ignored
                    }
                }
            }
        }
    }

    /// Hydrates a batch of known follows on cold start.
    ///
    /// Acquires the write lock once for the entire batch to ensure atomic loading
    /// and optimal performance.
    ///
    /// # Arguments
    /// * `protected_did` - Protected user DID.
    /// * `records` - Iterator of `(rkey, followed_did)` tuples.
    ///
    /// Returns the number of hydrated follow records.
    pub fn hydrate_batch<I>(&self, protected_did: impl Into<String>, records: I) -> usize
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let p_did = protected_did.into();
        let mut count = 0;
        let mut guard = self.inner.write();

        let FollowGraphInner {
            ref mut follows,
            ref mut rkey_to_followed,
        } = *guard;

        let follows_set = follows.entry(p_did.clone()).or_default();
        let rkeys_map = rkey_to_followed.entry(p_did).or_default();

        for (rkey, followed_did) in records {
            follows_set.insert(followed_did.clone());
            rkeys_map.insert(rkey, followed_did);
            count += 1;
        }

        count
    }

    /// Pre-seeds followed DIDs when rkeys are not known (e.g. for hermetic testing).
    ///
    /// Generates deterministic synthetic rkeys (`seed_{did}`).
    /// Returns the number of pre-seeded accounts.
    pub fn hydrate_dids<I, S>(&self, protected_did: impl Into<String>, dids: I) -> usize
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let p_did = protected_did.into();
        let records = dids.into_iter().map(|d| {
            let did = d.into();
            (format!("seed_{did}"), did)
        });
        self.hydrate_batch(p_did, records)
    }

    /// Returns the number of accounts followed by a protected user.
    #[must_use]
    pub fn follow_count(&self, protected_did: &str) -> usize {
        let guard = self.inner.read();
        guard.follows.get(protected_did).map_or(0, HashSet::len)
    }

    /// Returns the total number of protected users tracked in the follow graph.
    #[must_use]
    pub fn total_protected_users(&self) -> usize {
        let guard = self.inner.read();
        guard.follows.len()
    }

    /// Returns the total number of follow relationships tracked across all protected users.
    #[must_use]
    pub fn total_follows_count(&self) -> usize {
        let guard = self.inner.read();
        guard.follows.values().map(HashSet::len).sum()
    }

    /// Returns a copy of all followed DIDs for a given protected user.
    #[must_use]
    pub fn get_followed_dids(&self, protected_did: &str) -> HashSet<String> {
        let guard = self.inner.read();
        guard
            .follows
            .get(protected_did)
            .cloned()
            .unwrap_or_default()
    }

    /// Checks if a specific `rkey` is tracked in the reverse index.
    #[must_use]
    pub fn contains_rkey(&self, protected_did: &str, rkey: &str) -> bool {
        let guard = self.inner.read();
        guard
            .rkey_to_followed
            .get(protected_did)
            .is_some_and(|m| m.contains_key(rkey))
    }

    /// Checks whether the follow graph is completely empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        let guard = self.inner.read();
        guard.follows.is_empty()
    }

    /// Clears all follow relationships and reverse indexes.
    pub fn clear(&self) {
        let mut guard = self.inner.write();
        guard.follows.clear();
        guard.rkey_to_followed.clear();
    }
}
