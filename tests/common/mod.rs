//! Shared test fixtures and synthetic commit builders for integration tests.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_docs,
    dead_code
)]

use serde_json::json;
use skybase::ingest::events::{CommitOperation, JetstreamCommit};

/// Helper building a synthetic direct reply commit.
pub fn make_reply_commit(
    author_did: &str,
    target_did: &str,
    rkey: &str,
    parent_rkey: &str,
    text: &str,
) -> JetstreamCommit {
    JetstreamCommit {
        did: author_did.to_string(),
        time_us: 1_720_000_000_000_000,
        collection: "app.bsky.feed.post".to_string(),
        rkey: rkey.to_string(),
        operation: CommitOperation::Create,
        cid: Some("bafyreitestcid".to_string()),
        record: Some(json!({
            "$type": "app.bsky.feed.post",
            "text": text,
            "reply": {
                "parent": {
                    "uri": format!("at://{target_did}/app.bsky.feed.post/{parent_rkey}"),
                    "cid": "bafytestparentcid"
                },
                "root": {
                    "uri": format!("at://{target_did}/app.bsky.feed.post/{parent_rkey}"),
                    "cid": "bafytestparentcid"
                }
            },
            "createdAt": "2026-10-02T02:00:00.000Z"
        })),
    }
}

/// Helper building a synthetic thread reply commit where root is protected, parent is other.
pub fn make_thread_reply_commit(
    author_did: &str,
    protected_root_did: &str,
    stranger_parent_did: &str,
    rkey: &str,
    text: &str,
) -> JetstreamCommit {
    JetstreamCommit {
        did: author_did.to_string(),
        time_us: 1_720_000_000_000_000,
        collection: "app.bsky.feed.post".to_string(),
        rkey: rkey.to_string(),
        operation: CommitOperation::Create,
        cid: Some("bafyreitestcid".to_string()),
        record: Some(json!({
            "$type": "app.bsky.feed.post",
            "text": text,
            "reply": {
                "parent": {
                    "uri": format!("at://{stranger_parent_did}/app.bsky.feed.post/other_parent"),
                    "cid": "bafytestparentcid"
                },
                "root": {
                    "uri": format!("at://{protected_root_did}/app.bsky.feed.post/protected_root"),
                    "cid": "bafytestrootcid"
                }
            },
            "createdAt": "2026-10-02T02:00:00.000Z"
        })),
    }
}

/// Helper building a synthetic mention commit.
pub fn make_mention_commit(
    author_did: &str,
    target_did: &str,
    rkey: &str,
    text: &str,
) -> JetstreamCommit {
    JetstreamCommit {
        did: author_did.to_string(),
        time_us: 1_720_000_000_000_000,
        collection: "app.bsky.feed.post".to_string(),
        rkey: rkey.to_string(),
        operation: CommitOperation::Create,
        cid: Some("bafyreitestcid".to_string()),
        record: Some(json!({
            "$type": "app.bsky.feed.post",
            "text": text,
            "facets": [
                {
                    "index": { "byteStart": 0, "byteEnd": 10 },
                    "features": [
                        {
                            "$type": "app.bsky.richtext.facet#mention",
                            "did": target_did
                        }
                    ]
                }
            ],
            "createdAt": "2026-10-02T02:00:00.000Z"
        })),
    }
}

/// Helper building a synthetic quote post commit with app.bsky.embed.record.
pub fn make_quote_commit(
    author_did: &str,
    target_did: &str,
    rkey: &str,
    quoted_rkey: &str,
    text: &str,
) -> JetstreamCommit {
    JetstreamCommit {
        did: author_did.to_string(),
        time_us: 1_720_000_000_000_000,
        collection: "app.bsky.feed.post".to_string(),
        rkey: rkey.to_string(),
        operation: CommitOperation::Create,
        cid: Some("bafyreitestcid".to_string()),
        record: Some(json!({
            "$type": "app.bsky.feed.post",
            "text": text,
            "embed": {
                "$type": "app.bsky.embed.record",
                "record": {
                    "uri": format!("at://{target_did}/app.bsky.feed.post/{quoted_rkey}"),
                    "cid": "bafyquotedcid"
                }
            },
            "createdAt": "2026-10-02T02:00:00.000Z"
        })),
    }
}

/// Helper building a synthetic quote post commit with app.bsky.embed.recordWithMedia.
pub fn make_quote_with_media_commit(
    author_did: &str,
    target_did: &str,
    rkey: &str,
    quoted_rkey: &str,
    text: &str,
) -> JetstreamCommit {
    JetstreamCommit {
        did: author_did.to_string(),
        time_us: 1_720_000_000_000_000,
        collection: "app.bsky.feed.post".to_string(),
        rkey: rkey.to_string(),
        operation: CommitOperation::Create,
        cid: Some("bafyreitestcid".to_string()),
        record: Some(json!({
            "$type": "app.bsky.feed.post",
            "text": text,
            "embed": {
                "$type": "app.bsky.embed.recordWithMedia",
                "record": {
                    "$type": "app.bsky.embed.record",
                    "record": {
                        "uri": format!("at://{target_did}/app.bsky.feed.post/{quoted_rkey}"),
                        "cid": "bafyquotedcid"
                    }
                },
                "media": {
                    "$type": "app.bsky.embed.images",
                    "images": []
                }
            },
            "createdAt": "2026-10-02T02:00:00.000Z"
        })),
    }
}

/// Helper building an app.bsky.graph.follow create commit.
pub fn make_follow_create_commit(
    follower_did: &str,
    followed_did: &str,
    rkey: &str,
) -> JetstreamCommit {
    JetstreamCommit {
        did: follower_did.to_string(),
        time_us: 1_720_000_000_000_000,
        collection: "app.bsky.graph.follow".to_string(),
        rkey: rkey.to_string(),
        operation: CommitOperation::Create,
        cid: Some("bafyfollowcid".to_string()),
        record: Some(json!({
            "$type": "app.bsky.graph.follow",
            "subject": followed_did,
            "createdAt": "2026-10-02T02:00:00.000Z"
        })),
    }
}

/// Helper building an app.bsky.graph.follow delete commit (record is None).
pub fn make_follow_delete_commit(follower_did: &str, rkey: &str) -> JetstreamCommit {
    JetstreamCommit {
        did: follower_did.to_string(),
        time_us: 1_720_000_000_000_000,
        collection: "app.bsky.graph.follow".to_string(),
        rkey: rkey.to_string(),
        operation: CommitOperation::Delete,
        cid: None,
        record: None,
    }
}

/// Helper building a standalone post commit with no replies, facets, or embed.
pub fn make_standalone_post_commit(author_did: &str, rkey: &str, text: &str) -> JetstreamCommit {
    JetstreamCommit {
        did: author_did.to_string(),
        time_us: 1_720_000_000_000_000,
        collection: "app.bsky.feed.post".to_string(),
        rkey: rkey.to_string(),
        operation: CommitOperation::Create,
        cid: Some("bafyreitestcid".to_string()),
        record: Some(json!({
            "$type": "app.bsky.feed.post",
            "text": text,
            "createdAt": "2026-10-02T02:00:00.000Z"
        })),
    }
}

use parking_lot::Mutex;
use skybase::repo::PdsRepoClient;
use std::sync::Arc;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Mock PDS XRPC server simulating sovereign ATProto repo mutations and DPoP authentication.
pub struct MockPdsServer {
    server: MockServer,
    pub created_records: Arc<Mutex<Vec<serde_json::Value>>>,
    pub deleted_records: Arc<Mutex<Vec<serde_json::Value>>>,
    pub create_error: Arc<Mutex<Option<(u16, String, String)>>>,
    pub delete_error: Arc<Mutex<Option<(u16, String, String)>>>,
    pub nonce_challenge: Arc<Mutex<Option<String>>>,
    pub existing_lists: Arc<Mutex<Vec<(String, String, String)>>>,
}

impl MockPdsServer {
    /// Starts a new ephemeral loopback MockServer on 127.0.0.1 with dynamic handlers.
    pub async fn start() -> Self {
        let server = MockServer::start().await;
        let created_records = Arc::new(Mutex::new(Vec::new()));
        let deleted_records = Arc::new(Mutex::new(Vec::new()));
        let create_error = Arc::new(Mutex::new(None));
        let delete_error = Arc::new(Mutex::new(None));
        let nonce_challenge = Arc::new(Mutex::new(None));
        let existing_lists = Arc::new(Mutex::new(Vec::new()));

        // Dynamic createRecord responder
        let cr = Arc::clone(&created_records);
        let ce = Arc::clone(&create_error);
        let nc = Arc::clone(&nonce_challenge);
        Mock::given(method("POST"))
            .and(path("/xrpc/com.atproto.repo.createRecord"))
            .respond_with(move |req: &wiremock::Request| {
                if let Some(nonce) = nc.lock().take() {
                    return ResponseTemplate::new(401)
                        .insert_header("DPoP-Nonce", nonce)
                        .set_body_json(serde_json::json!({
                            "error": "use_dpop_nonce",
                            "message": "DPoP proof requires nonce"
                        }));
                }

                if let Some((status, err_code, msg)) = ce.lock().take() {
                    return ResponseTemplate::new(status).set_body_json(serde_json::json!({
                        "error": err_code,
                        "message": msg
                    }));
                }

                let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
                cr.lock().push(body.clone());
                let repo = body["repo"].as_str().unwrap_or("did:plc:mock");
                let collection = body["collection"].as_str().unwrap_or("unknown");
                let rkey = body["rkey"].as_str().unwrap_or("generated_rkey");

                let uri = format!("at://{repo}/{collection}/{rkey}");
                let cid = format!("bafy{rkey}mockcid");

                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "uri": uri,
                    "cid": cid,
                }))
            })
            .mount(&server)
            .await;

        // Dynamic deleteRecord responder
        let dr = Arc::clone(&deleted_records);
        let de = Arc::clone(&delete_error);
        Mock::given(method("POST"))
            .and(path("/xrpc/com.atproto.repo.deleteRecord"))
            .respond_with(move |req: &wiremock::Request| {
                if let Some((status, err_code, msg)) = de.lock().take() {
                    return ResponseTemplate::new(status).set_body_json(serde_json::json!({
                        "error": err_code,
                        "message": msg
                    }));
                }

                let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
                dr.lock().push(body);
                ResponseTemplate::new(200).set_body_json(serde_json::json!({}))
            })
            .mount(&server)
            .await;

        // Dynamic listRecords responder
        let el = Arc::clone(&existing_lists);
        Mock::given(method("GET"))
            .and(path("/xrpc/com.atproto.repo.listRecords"))
            .respond_with(move |req: &wiremock::Request| {
                let url = &req.url;
                let mut collection = String::new();
                let mut repo = String::new();
                for (k, v) in url.query_pairs() {
                    if k == "collection" {
                        collection = v.to_string();
                    } else if k == "repo" {
                        repo = v.to_string();
                    }
                }

                let guard = el.lock();
                let matching: Vec<serde_json::Value> = guard
                    .iter()
                    .filter(|(r, _, _)| {
                        (repo.is_empty() || r == &repo)
                            && (collection.is_empty() || collection == "app.bsky.graph.list")
                    })
                    .map(|(r, list_rkey, name)| {
                        serde_json::json!({
                            "uri": format!("at://{r}/app.bsky.graph.list/{list_rkey}"),
                            "cid": format!("bafy{list_rkey}existingcid"),
                            "value": {
                                "$type": "app.bsky.graph.list",
                                "purpose": "app.bsky.graph.defs#modlist",
                                "name": name,
                                "createdAt": "2026-10-02T00:00:00.000Z"
                            }
                        })
                    })
                    .collect();

                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "records": matching
                }))
            })
            .mount(&server)
            .await;

        Self {
            server,
            created_records,
            deleted_records,
            create_error,
            delete_error,
            nonce_challenge,
            existing_lists,
        }
    }

    /// Returns the base URI string of the mock server.
    pub fn uri(&self) -> String {
        self.server.uri()
    }

    /// Constructs an authenticated [`PdsRepoClient`] targeted at this mock server.
    pub fn pds_client(&self, did: &str) -> PdsRepoClient {
        PdsRepoClient::from_credentials(self.uri(), did, "mock_token")
            .expect("mock PdsRepoClient creation should succeed")
    }

    /// Injects a one-time DPoP nonce challenge (HTTP 401 use_dpop_nonce) on createRecord.
    pub async fn mount_nonce_challenge_once(&self, nonce: &str) {
        *self.nonce_challenge.lock() = Some(nonce.to_string());
    }

    /// Mounts a one-time failure response on createRecord.
    pub async fn mount_create_error_once(&self, status: u16, error_code: &str, message: &str) {
        *self.create_error.lock() = Some((status, error_code.to_string(), message.to_string()));
    }

    /// Mounts a one-time failure response on deleteRecord.
    pub async fn mount_delete_error_once(&self, status: u16, error_code: &str, message: &str) {
        *self.delete_error.lock() = Some((status, error_code.to_string(), message.to_string()));
    }

    /// Mounts an existing moderation list response for `listRecords` query.
    pub async fn mount_existing_list(&self, repo: &str, list_rkey: &str, name: &str) {
        self.existing_lists.lock().push((
            repo.to_string(),
            list_rkey.to_string(),
            name.to_string(),
        ));
    }
}
