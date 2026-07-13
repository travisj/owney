//! RFC 8621 mail methods over ms-storage.
//!
//! `register` adds Mailbox/Email/Thread get/query/changes and Email/set
//! (keywords + mailbox moves) to a jmap-core dispatcher. State tokens are the
//! per-type modseqs maintained by ms-storage — `/changes` is a direct range
//! query, exactly the discipline the storage layer enforces on every write.

mod calendar_methods;

use std::sync::Arc;

use jmap_core::{Dispatcher, MethodError};
use owney_api::JmapCtx;
use owney_core::DataType;
use owney_spam;
use owney_storage::EmailRow;
use serde::Deserialize;
use serde_json::{Value, json};

pub const MAIL_CAPABILITY: &str = "urn:ietf:params:jmap:mail";
pub const SUBMISSION_CAPABILITY: &str = "urn:ietf:params:jmap:submission";

/// Session capability object for `urn:ietf:params:jmap:mail`.
pub fn mail_capability() -> Value {
    json!({
        "maxMailboxesPerEmail": 32,
        "maxMailboxDepth": 10,
        "maxSizeMailboxName": 200,
        "maxSizeAttachmentsPerEmail": 50_000_000u64,
        "emailQuerySortOptions": ["receivedAt"],
        "mayCreateTopLevelMailbox": true,
    })
}

/// Register all mail methods on the dispatcher.
pub fn register(dispatcher: &mut Dispatcher<JmapCtx>) {
    dispatcher.add_capability(MAIL_CAPABILITY, mail_capability());

    dispatcher.register("Mailbox/get", MAIL_CAPABILITY, mailbox_get);
    dispatcher.register("Mailbox/changes", MAIL_CAPABILITY, |args, ctx| {
        changes(args, ctx, DataType::Mailbox)
    });
    dispatcher.register("Email/get", MAIL_CAPABILITY, email_get);
    dispatcher.register("Email/query", MAIL_CAPABILITY, email_query);
    dispatcher.register("Email/changes", MAIL_CAPABILITY, |args, ctx| {
        changes(args, ctx, DataType::Email)
    });
    dispatcher.register("Email/set", MAIL_CAPABILITY, email_set);
    dispatcher.register("Thread/get", MAIL_CAPABILITY, thread_get);
    dispatcher.register("Thread/changes", MAIL_CAPABILITY, |args, ctx| {
        changes(args, ctx, DataType::Thread)
    });

    dispatcher.add_capability(
        SUBMISSION_CAPABILITY,
        json!({"maxDelayedSend": 0, "submissionExtensions": {}}),
    );
    dispatcher.register("Identity/get", SUBMISSION_CAPABILITY, identity_get);
    dispatcher.register("EmailSubmission/set", SUBMISSION_CAPABILITY, submission_set);
    dispatcher.register("ChatPreference/get", MAIL_CAPABILITY, chat_preference_get);
    dispatcher.register("ChatPreference/set", MAIL_CAPABILITY, chat_preference_set);

    // Calendar methods
    dispatcher.add_capability(calendar_methods::CALENDAR_CAPABILITY, calendar_methods::calendar_capability());
    dispatcher.register("Calendar/get", calendar_methods::CALENDAR_CAPABILITY, calendar_methods::calendar_get);
    dispatcher.register("Calendar/share", calendar_methods::CALENDAR_CAPABILITY, calendar_methods::calendar_share);
    dispatcher.register("CalendarInvitation/get", calendar_methods::CALENDAR_CAPABILITY, calendar_methods::calendar_invitation_get);
    dispatcher.register("CalendarInvitation/set", calendar_methods::CALENDAR_CAPABILITY, calendar_methods::calendar_invitation_set);
}

fn storage_err(err: owney_storage::StorageError) -> MethodError {
    MethodError::ServerFail(err.to_string())
}

/// Every mail method takes accountId; reject calls for other accounts.
fn check_account(ctx: &JmapCtx, account_id: &str) -> Result<owney_core::AccountId, MethodError> {
    if account_id != ctx.account.id.to_string() {
        return Err(MethodError::AccountNotFound);
    }
    Ok(ctx.account.id)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetArgs {
    account_id: String,
    #[serde(default)]
    ids: Option<Vec<String>>,
    /// Subset of properties to return. `None` means "all" (per RFC 8621
    /// §6.1). Unknown properties cause an `invalidArguments` error at
    /// `Email/get` time (via [`Subset::from_list`]).
    #[serde(default)]
    properties: Option<Vec<String>>,
    #[serde(default)]
    fetch_text_body_values: bool,
}

/// A property subset scope applied at the `Foo/get` boundary.
///
/// `None` ⇒ all canonical properties.
/// `Some(set)` ⇒ only the listed canonical properties.
///
/// RFC 8621 §6.1 / §6.4 — `null` ↔ "all", and an unknown property
/// is `invalidArguments`. We sanity-check at parse time, but the
/// real validation (does a property exist for *this* data type)
/// happens in the per-call `select` step.
#[derive(Debug, Clone)]
struct Subset {
    /// The caller's requested properties (the projection target).
    requested: std::collections::HashSet<String>,
}

impl Subset {
    fn from_list(
        type_name: &'static str,
        requested: &[String],
    ) -> Result<Option<Self>, MethodError> {
        let allowed: std::collections::HashSet<&'static str> = match type_name {
            "Email" => [
                "id",
                "blobId",
                "threadId",
                "mailboxIds",
                "keywords",
                "size",
                "receivedAt",
                "sender",
                "from",
                "to",
                "cc",
                "bcc",
                "replyTo",
                "subject",
                "messageId",
                "inReplyTo",
                "snippet",
                "bodyValues",
                "textBody",
                "htmlBody",
                "attachments",
                "hasAttachment",
                "preview",
                "authResults",
                "pgpStatus",
            ]
            .into_iter()
            .collect(),
            "Mailbox" => [
                "id",
                "name",
                "parentId",
                "role",
                "sortOrder",
                "totalEmails",
                "unreadEmails",
                "totalThreads",
                "unreadThreads",
                "myRights",
            ]
            .into_iter()
            .collect(),
            _ => {
                return Err(MethodError::InvalidArguments(format!(
                    "{type_name}/get does not accept a properties filter"
                )));
            }
        };
        for prop in requested {
            if !allowed.contains(prop.as_str()) {
                return Err(MethodError::InvalidArguments(format!(
                    "unknown property {prop:?} in {type_name}/get"
                )));
            }
        }
        let requested: std::collections::HashSet<String> =
            requested.iter().cloned().collect();
        Ok(Some(Self { requested }))
    }

    fn select(
        &self,
        full: &serde_json::Map<String, Value>,
    ) -> serde_json::Map<String, Value> {
        // RFC 8621: zero-length list = "no properties" (return empty Map);
        // non-empty list = the listed properties. We trust the caller
        // already checked the list against the canonical allow-list.
        full
            .iter()
            .filter(|(k, _)| self.requested.contains(*k))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

/// Helper: take `Option<&Subset>` (which `Option<&Subset>::None` means "all")
/// and project to a `Map`.
fn project(
    subset: Option<&Subset>,
    full: &serde_json::Map<String, Value>,
) -> serde_json::Map<String, Value> {
    match subset {
        Some(set) => set.select(full),
        None => full.clone(),
    }
}

async fn mailbox_get(args: Value, ctx: Arc<JmapCtx>) -> Result<Value, MethodError> {
    let args: GetArgs = parse(args)?;
    let account_id = check_account(&ctx, &args.account_id)?;

    let subset = match args.properties.as_ref() {
        None => None,
        Some(list) => Subset::from_list("Mailbox", list)?,
    };

    let mailboxes = ctx
        .storage
        .mailboxes(account_id)
        .await
        .map_err(storage_err)?;
    let state = ctx
        .storage
        .state(account_id, DataType::Mailbox)
        .await
        .map_err(storage_err)?;

    let mut list = Vec::new();
    let mut not_found: Vec<String> = Vec::new();
    match &args.ids {
        None => {
            for m in &mailboxes {
                list.push(Value::Object(mailbox_projected(m, subset.as_ref())));
            }
        }
        Some(ids) => {
            for id in ids {
                match mailboxes.iter().find(|m| &m.id == id) {
                    Some(mailbox) => {
                        list.push(Value::Object(mailbox_projected(mailbox, subset.as_ref())));
                    }
                    None => not_found.push(id.clone()),
                }
            }
        }
    }

    Ok(json!({
        "accountId": args.account_id,
        "state": state.to_string(),
        "list": list,
        "notFound": not_found,
    }))
}

fn mailbox_json(mailbox: &owney_storage::MailboxRow) -> Value {
    // `totalThreads` / `unreadThreads` are required by RFC 8621 §6.1 but the
    // storage layer's `mailboxes()` query doesn't compute them. They were
    // previously returned as `total_emails` / `unread_emails`, which is
    // semantically wrong (a thread with 100 replies is *one* thread, 100 emails).
    // Until `owney_storage::MailboxRow` carries the threaded count separately,
    // surface them as `null` so clients can render the row without being
    // lied to. (Tracked: Phase N+1 storage refactor.)
    json!({
        "id": mailbox.id,
        "name": mailbox.name,
        "parentId": mailbox.parent_id,
        "role": mailbox.role,
        "sortOrder": mailbox.sort_order,
        "totalEmails": mailbox.total_emails,
        "unreadEmails": mailbox.unread_emails,
        "totalThreads": Value::Null,
        "unreadThreads": Value::Null,
        "myRights": {
            "mayReadItems": true, "mayAddItems": true, "mayRemoveItems": true,
            "maySetSeen": true, "maySetKeywords": true, "mayCreateChild": true,
            "mayRename": true, "mayDelete": true, "maySubmit": true,
        },
        "isSubscribed": true,
    })
}

fn mailbox_projected(
    mailbox: &owney_storage::MailboxRow,
    subset: Option<&Subset>,
) -> serde_json::Map<String, Value> {
    let full = mailbox_json(mailbox);
    let map = full.as_object().expect("mailbox_json returns an Object");
    project(subset, map)
}

 async fn email_get(args: Value, ctx: Arc<JmapCtx>) -> Result<Value, MethodError> {
    let args: GetArgs = parse(args)?;
    let account_id = check_account(&ctx, &args.account_id)?;

    let ids = args
        .ids
        .as_ref()
        .ok_or_else(|| MethodError::InvalidArguments("Email/get requires ids".into()))?;
    let parsed_ids: Vec<owney_core::EmailId> = ids.iter().filter_map(|id| id.parse().ok()).collect();

    let subset = match args.properties.as_ref() {
        None => None,
        Some(list) => Subset::from_list("Email", list)?,
    };

    let rows = ctx
        .storage
        .emails_by_ids(account_id, parsed_ids)
        .await
        .map_err(storage_err)?;
    let state = ctx
        .storage
        .state(account_id, DataType::Email)
        .await
        .map_err(storage_err)?;

    let mut list = Vec::with_capacity(rows.len());
    for row in &rows {
        let full = email_json(&ctx, row, args.fetch_text_body_values).await?;
        let map = full
            .as_object()
            .ok_or_else(|| MethodError::InvalidArguments("internal: email not object".into()))?;
        let projected = project(subset.as_ref(), map);
        list.push(Value::Object(projected));
    }
    let not_found: Vec<&String> = ids
        .iter()
        .filter(|id| !rows.iter().any(|r| &&r.id == id))
        .collect();

    Ok(json!({
        "accountId": args.account_id,
        "state": state.to_string(),
        "list": list,
        "notFound": not_found,
    }))
}

/// Build the RFC 8621 Email object. Envelope-level metadata comes from the
/// database; address headers, preview, and body text are parsed on demand
/// from the (decrypted) raw blob.
async fn email_json(ctx: &JmapCtx, row: &EmailRow, fetch_body: bool) -> Result<Value, MethodError> {
    let mut email = json!({
        "id": row.id,
        "blobId": row.blob_id,
        "threadId": row.thread_id,
        "mailboxIds": row.mailbox_ids.iter().map(|id| (id.clone(), Value::Bool(true))).collect::<serde_json::Map<_,_>>(),
        "keywords": row.keywords.iter().map(|k| (k.clone(), Value::Bool(true))).collect::<serde_json::Map<_,_>>(),
        "size": row.size,
        "receivedAt": owney_core::time::iso8601_utc(row.received_at),
        "messageId": row.message_id.as_ref().map(|id| vec![id.clone()]),
        "subject": row.subject,
        "pgpStatus": row
            .pgp_status
            .as_deref()
            .and_then(|s| serde_json::from_str::<Value>(s).ok()),
        "chatMode": row.chat_mode,
    });

    let blob_id = row
        .blob_id
        .parse()
        .map_err(|_| MethodError::ServerFail("bad blob id".into()))?;
    let raw = ctx.storage.get_blob(blob_id).await.map_err(storage_err)?;
    if let Some(message) = mail_parser::MessageParser::default().parse(&raw) {
        email["from"] = addresses(message.from());
        email["to"] = addresses(message.to());
        email["cc"] = addresses(message.cc());
        email["sentAt"] = message
            .date()
            .map(|d| Value::String(d.to_rfc3339()))
            .unwrap_or(Value::Null);
        let body = message.body_text(0).unwrap_or_default();
        email["preview"] = Value::String(body.chars().take(200).collect::<String>());
        if fetch_body {
            email["bodyValues"] = json!({
                "1": {"value": body, "isTruncated": false, "isEncodingProblem": false},
            });
            email["textBody"] =
                json!([{"partId": "1", "blobId": row.blob_id, "type": "text/plain"}]);
        }
    }
    Ok(email)
}

fn addresses(list: Option<&mail_parser::Address<'_>>) -> Value {
    match list {
        None => Value::Null,
        Some(address) => Value::Array(
            address
                .iter()
                .map(|addr| {
                    json!({
                        "name": addr.name(),
                        "email": addr.address().unwrap_or_default(),
                    })
                })
                .collect(),
        ),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct QueryArgs {
    account_id: String,
    #[serde(default)]
    filter: Option<QueryFilter>,
    #[serde(default)]
    position: Option<i64>,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(dead_code)] // hasKeyword/notKeyword/text are wire-fields for the AST work in Phase 5.B follow-up
struct QueryFilter {
    #[serde(default)]
    in_mailbox: Option<String>,
    #[serde(default)]
    has_keyword: Option<String>,
    #[serde(default)]
    not_keyword: Option<String>,
    /// Bare `text` matcher — matches an email whose subject or any text
    /// part contains the value as a substring. Optional; absent is a
    /// no-op (matches everything).
    #[serde(default)]
    text: Option<String>,
    /// RFC 8621 — filter emails received after this unix timestamp
    #[serde(default)]
    after: Option<i64>,
    /// RFC 8621 — filter emails received before this unix timestamp
    #[serde(default)]
    before: Option<i64>,
    /// RFC 8621 — filter to a specific thread
    #[serde(default)]
    all_in_thread: Option<String>,
    /// RFC 8621 — filter to flagged emails (presence of $flagged keyword)
    #[serde(default)]
    is_flagged: Option<bool>,
    /// RFC 8621 — filter to unread emails (absence of $Seen keyword)
    #[serde(default)]
    is_unread: Option<bool>,
}

// Per RFC 8621 §6.3.2, `Email/query` filters live in a single object.
// Unknown keys must surface as `invalidArguments` rather than being
// silently ignored (the latter defeats typo-driven data leaks).
// The wired-through subset here is intentionally minimal — see the
// `Email/query` follow-up for full RFC 8621 coverage.

async fn email_query(args: Value, ctx: Arc<JmapCtx>) -> Result<Value, MethodError> {
    let args: QueryArgs = parse(args)?;
    let account_id = check_account(&ctx, &args.account_id)?;

    let position = args.position.unwrap_or(0).max(0) as usize;
    let limit = args.limit.unwrap_or(50).min(500);
    let in_mailbox = args.filter.as_ref().and_then(|f| f.in_mailbox.clone());
    let text_filter = args.filter.as_ref().and_then(|f| f.text.clone());
    let has_keyword = args.filter.as_ref().and_then(|f| f.has_keyword.clone());
    let not_keyword = args.filter.as_ref().and_then(|f| f.not_keyword.clone());
    let after = args.filter.as_ref().and_then(|f| f.after);
    let before = args.filter.as_ref().and_then(|f| f.before);
    let all_in_thread = args.filter.as_ref().and_then(|f| f.all_in_thread.clone());
    let is_flagged = args.filter.as_ref().and_then(|f| f.is_flagged);
    let is_unread = args.filter.as_ref().and_then(|f| f.is_unread);

    let (ids, total, state) = if let Some(ref text) = text_filter {
        // Use tantivy search if text filter is present
        let search_index = ctx.storage.search_index(account_id);
        let search_limit = 1000; // Get more results for further filtering
        let search_results = search_index
            .search(text, search_limit)
            .await
            .unwrap_or_default();

        // Extract email IDs from scored results (already ranked by relevance)
        let search_email_ids: Vec<owney_core::EmailId> =
            search_results.iter().map(|r| r.email_id).collect();

        // Filter search results by mailbox, keywords, dates, and thread
        let filtered_ids = ctx
            .storage
            .filter_emails(
                account_id,
                search_email_ids,
                in_mailbox.as_deref(),
                has_keyword.as_deref(),
                not_keyword.as_deref(),
                after,
                before,
                all_in_thread.as_deref(),
                is_flagged,
                is_unread,
            )
            .await
            .map_err(storage_err)?;

        let total = filtered_ids.len() as u64;
        let state = ctx
            .storage
            .state(account_id, DataType::Email)
            .await
            .map_err(storage_err)?;

        let ids: Vec<String> = filtered_ids
            .iter()
            .skip(position)
            .take(limit)
            .map(|id| id.to_string())
            .collect();

        (ids, total, state)
    } else if after.is_some()
        || before.is_some()
        || all_in_thread.is_some()
        || is_flagged.is_some()
        || is_unread.is_some()
    {
        // Use enhanced query with RFC 8621 filters
        ctx.storage
            .query_emails_with_filters(
                account_id,
                in_mailbox,
                after,
                before,
                all_in_thread,
                is_flagged,
                is_unread,
                position,
                limit,
            )
            .await
            .map_err(storage_err)?
    } else {
        // Simple query with just mailbox filter
        ctx.storage
            .query_emails(account_id, in_mailbox, position, limit)
            .await
            .map_err(storage_err)?
    };

    Ok(json!({
        "accountId": args.account_id,
        "queryState": state.to_string(),
        "canCalculateChanges": false,
        "position": position,
        "ids": ids,
        "total": total,
    }))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChangesArgs {
    account_id: String,
    since_state: String,
    #[serde(default)]
    max_changes: Option<usize>,
}

async fn changes(
    args: Value,
    ctx: Arc<JmapCtx>,
    data_type: DataType,
) -> Result<Value, MethodError> {
    let args: ChangesArgs = parse(args)?;
    let account_id = check_account(&ctx, &args.account_id)?;
    let since: u64 = args
        .since_state
        .parse()
        .map_err(|_| MethodError::CannotCalculateChanges)?;

    let result = ctx
        .storage
        .changes_since(
            account_id,
            data_type,
            since,
            args.max_changes.unwrap_or(256),
        )
        .await
        .map_err(storage_err)?;

    Ok(json!({
        "accountId": args.account_id,
        "oldState": args.since_state,
        "newState": result.new_state.to_string(),
        "hasMoreChanges": result.has_more,
        "created": result.created,
        "updated": result.updated,
        "destroyed": [],
    }))
}

async fn thread_get(args: Value, ctx: Arc<JmapCtx>) -> Result<Value, MethodError> {
    let args: GetArgs = parse(args)?;
    let account_id = check_account(&ctx, &args.account_id)?;
    let ids = args
        .ids
        .as_ref()
        .ok_or_else(|| MethodError::InvalidArguments("Thread/get requires ids".into()))?;
    let thread_ids: Vec<owney_core::ThreadId> = ids.iter().filter_map(|id| id.parse().ok()).collect();

    let threads = ctx
        .storage
        .thread_emails(account_id, thread_ids)
        .await
        .map_err(storage_err)?;
    let state = ctx
        .storage
        .state(account_id, DataType::Thread)
        .await
        .map_err(storage_err)?;

    let list: Vec<Value> = threads
        .iter()
        .map(|(id, email_ids)| json!({"id": id, "emailIds": email_ids}))
        .collect();
    let not_found: Vec<&String> = ids
        .iter()
        .filter(|id| !threads.iter().any(|(t, _)| &t == id))
        .collect();

    Ok(json!({
        "accountId": args.account_id,
        "state": state.to_string(),
        "list": list,
        "notFound": not_found,
    }))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetArgs {
    account_id: String,
    #[serde(default)]
    create: Option<serde_json::Map<String, Value>>,
    #[serde(default)]
    update: Option<serde_json::Map<String, Value>>,
}

/// Email/set supporting updates only (keywords, mailboxIds) — flag, mark
/// read, move, archive. Create (drafts) and destroy arrive with submission.
async fn email_set(args: Value, ctx: Arc<JmapCtx>) -> Result<Value, MethodError> {
    let args: SetArgs = parse(args)?;
    let account_id = check_account(&ctx, &args.account_id)?;

    let old_state = ctx
        .storage
        .state(account_id, DataType::Email)
        .await
        .map_err(storage_err)?;

    let mut updated = serde_json::Map::new();
    let mut not_updated = serde_json::Map::new();
    let mut created = serde_json::Map::new();
    let mut not_created = serde_json::Map::new();

    for (client_id, object) in args.create.unwrap_or_default() {
        match apply_create(&ctx, account_id, &object).await {
            Ok(server_ids) => {
                created.insert(client_id, server_ids);
            }
            Err(description) => {
                not_created.insert(
                    client_id,
                    json!({"type": "invalidProperties", "description": description}),
                );
            }
        }
    }

    for (id, patch) in args.update.unwrap_or_default() {
        match apply_update(&ctx, account_id, &id, &patch).await {
            Ok(()) => {
                updated.insert(id, Value::Null);
            }
            Err(description) => {
                not_updated.insert(
                    id,
                    json!({"type": "invalidProperties", "description": description}),
                );
            }
        }
    }

    let new_state = ctx
        .storage
        .state(account_id, DataType::Email)
        .await
        .map_err(storage_err)?;

    Ok(json!({
        "accountId": args.account_id,
        "oldState": old_state.to_string(),
        "newState": new_state.to_string(),
        "updated": updated,
        "notUpdated": not_updated,
        "created": created,
        "notCreated": not_created,
        "destroyed": [],
    }))
}

/// Email/set create: compose an RFC 5322 message from the JMAP Email object
/// (drafts are the primary use) and ingest it into the requested mailbox.
async fn apply_create(
    ctx: &JmapCtx,
    account_id: owney_core::AccountId,
    object: &Value,
) -> Result<Value, String> {
    let mailbox_ids: Vec<String> = object
        .get("mailboxIds")
        .and_then(Value::as_object)
        .map(|map| map.keys().cloned().collect())
        .unwrap_or_default();
    let first_mailbox: owney_core::MailboxId = mailbox_ids
        .first()
        .ok_or("mailboxIds is required")?
        .parse()
        .map_err(|_| "bad mailbox id".to_owned())?;

    let chat_mode = object
        .get("chatMode")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let raw = compose_from_jmap(&ctx.account, object)?;
    let ingested = ctx
        .storage
        .ingest_email_into(
            account_id,
            raw,
            owney_storage::MailboxTarget::Id(first_mailbox),
            None,
            chat_mode,
        )
        .await
        .map_err(|err| err.to_string())?;

    // Keywords (e.g. $draft, $seen) apply after the row exists.
    if let Some(keywords) = object.get("keywords").and_then(Value::as_object) {
        let keywords: Vec<String> = keywords.keys().cloned().collect();
        ctx.storage
            .update_email(account_id, ingested.id, Some(keywords), None)
            .await
            .map_err(|err| err.to_string())?;
    }

    Ok(json!({
        "id": ingested.id.to_string(),
        "blobId": ingested.blob_id.to_hex(),
        "threadId": ingested.thread_id.to_string(),
    }))
}

/// Build RFC 5322 bytes from a (pragmatic subset of a) JMAP Email object.
fn compose_from_jmap(account: &owney_storage::Account, object: &Value) -> Result<Vec<u8>, String> {
    fn address_list(value: Option<&Value>) -> Vec<String> {
        value
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .filter_map(|entry| {
                        let email = entry.get("email")?.as_str()?;
                        match entry.get("name").and_then(Value::as_str) {
                            Some(name) if !name.is_empty() => Some(format!("{name} <{email}>")),
                            _ => Some(format!("<{email}>")),
                        }
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    let from = {
        let provided = address_list(object.get("from"));
        if provided.is_empty() {
            match &account.display_name {
                Some(name) => format!("{name} <{}>", account.email),
                None => format!("<{}>", account.email),
            }
        } else {
            provided.join(", ")
        }
    };
    let to = address_list(object.get("to"));
    let cc = address_list(object.get("cc"));
    let subject = object
        .get("subject")
        .and_then(Value::as_str)
        .unwrap_or_default();

    // Body: first textBody part's value from bodyValues.
    let body = object
        .get("textBody")
        .and_then(Value::as_array)
        .and_then(|parts| parts.first())
        .and_then(|part| part.get("partId"))
        .and_then(Value::as_str)
        .and_then(|part_id| {
            object
                .get("bodyValues")?
                .get(part_id)?
                .get("value")?
                .as_str()
        })
        .unwrap_or_default()
        .replace('\n', "\r\n");

    let domain = account
        .email
        .rsplit_once('@')
        .map(|(_, d)| d)
        .unwrap_or("local");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let mut headers = format!(
        "From: {from}\r\nSubject: {subject}\r\nDate: {date}\r\n\
         Message-ID: <{id}@{domain}>\r\nMIME-Version: 1.0\r\n\
         Content-Type: text/plain; charset=utf-8\r\n",
        date = owney_core::time::rfc2822_utc(now),
        id = uuid::Uuid::now_v7(),
    );
    if !to.is_empty() {
        headers.push_str(&format!("To: {}\r\n", to.join(", ")));
    }
    if !cc.is_empty() {
        headers.push_str(&format!("Cc: {}\r\n", cc.join(", ")));
    }
    Ok(format!("{headers}\r\n{body}").into_bytes())
}

/// Identity/get: one identity per account (RFC 8621 §6).
async fn identity_get(args: Value, ctx: Arc<JmapCtx>) -> Result<Value, MethodError> {
    let args: GetArgs = parse(args)?;
    check_account(&ctx, &args.account_id)?;
    // RFC 8621 §6.4: `name` is optional (nullable) — `null` when unset.
    // Don't fall back to the bare email; that's a leakage of the local-part.
    let name = ctx.account.display_name.clone().map(Value::String).unwrap_or(Value::Null);
    Ok(json!({
        "accountId": args.account_id,
        "state": "0",
        "list": [{
            "id": "default",
            "name": name,
            "email": ctx.account.email,
            "replyTo": null,
            "bcc": null,
            "textSignature": "",
            "htmlSignature": "",
            "mayDelete": false,
        }],
        "notFound": [],
    }))
}

/// ChatPreference/get: list chat mode preferences for all contacts.
async fn chat_preference_get(args: Value, ctx: Arc<JmapCtx>) -> Result<Value, MethodError> {
    let args: GetArgs = parse(args)?;
    let account_id = check_account(&ctx, &args.account_id)?;

    let prefs = ctx
        .storage
        .list_chat_preferences(account_id)
        .await
        .map_err(storage_err)?;

    let mut list = Vec::new();
    for pref in prefs {
        list.push(json!({
            "id": pref.contact_email,
            "contactEmail": pref.contact_email,
            "preference": pref.preference.as_str(),
        }));
    }

    Ok(json!({
        "accountId": args.account_id,
        "state": "0",
        "list": list,
        "notFound": [],
    }))
}

/// ChatPreference/set: update chat mode preferences.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChatPrefSetArgs {
    account_id: String,
    #[serde(default)]
    create: Option<serde_json::Map<String, Value>>,
    #[serde(default)]
    update: Option<serde_json::Map<String, Value>>,
    #[serde(default)]
    destroy: Option<Vec<String>>,
}

async fn chat_preference_set(args: Value, ctx: Arc<JmapCtx>) -> Result<Value, MethodError> {
    let args: ChatPrefSetArgs = parse(args)?;
    let account_id = check_account(&ctx, &args.account_id)?;

    let mut created = serde_json::Map::new();
    let mut updated = serde_json::Map::new();
    let mut destroyed = Vec::new();

    for (client_id, object) in args.create.unwrap_or_default() {
        let result: Result<Value, String> = async {
            let contact_email = object
                .get("contactEmail")
                .and_then(Value::as_str)
                .ok_or("contactEmail is required".to_owned())?;
            let pref_str = object
                .get("preference")
                .and_then(Value::as_str)
                .ok_or("preference is required".to_owned())?;
            let preference =
                owney_storage::ChatMode::from_str(pref_str)
                    .ok_or_else(|| format!("invalid preference: {}", pref_str))?;

            ctx.storage
                .set_chat_preference(account_id, contact_email, preference)
                .await
                .map_err(|e| e.to_string())?;

            Ok(json!({
                "id": contact_email,
            }))
        }
        .await;

        match result {
            Ok(id_obj) => {
                created.insert(client_id, id_obj);
            }
            Err(err) => {
                created.insert(client_id, json!({"type": "serverFail", "description": err}));
            }
        }
    }

    for (contact_email, object) in args.update.unwrap_or_default() {
        let result: Result<(), String> = async {
            let pref_str = object
                .get("preference")
                .and_then(Value::as_str)
                .ok_or("preference is required".to_owned())?;
            let preference =
                owney_storage::ChatMode::from_str(pref_str)
                    .ok_or_else(|| format!("invalid preference: {}", pref_str))?;

            ctx.storage
                .set_chat_preference(account_id, &contact_email, preference)
                .await
                .map_err(|e| e.to_string())?;
            Ok(())
        }
        .await;

        if result.is_ok() {
            updated.insert(contact_email, json!({}));
        }
    }

    for contact_email in args.destroy.unwrap_or_default() {
        let result = ctx
            .storage
            .delete_chat_preference(account_id, &contact_email)
            .await;
        if result.is_ok() {
            destroyed.push(contact_email);
        }
    }

    Ok(json!({
        "accountId": args.account_id,
        "created": created,
        "updated": updated,
        "destroyed": destroyed,
    }))
}

/// EmailSubmission/set: hand a stored message to the outbound pipeline.
async fn submission_set(args: Value, ctx: Arc<JmapCtx>) -> Result<Value, MethodError> {
    let args: SetArgs = parse(args)?;
    let account_id = check_account(&ctx, &args.account_id)?;
    let submitter = ctx
        .submitter
        .clone()
        .ok_or_else(|| MethodError::ServerFail("submission is not enabled".into()))?;

    let mut created = serde_json::Map::new();
    let mut not_created = serde_json::Map::new();

    for (client_id, object) in args.create.unwrap_or_default() {
        let result: Result<Value, String> = async {
            let email_id: owney_core::EmailId = object
                .get("emailId")
                .and_then(Value::as_str)
                .ok_or("emailId is required")?
                .parse()
                .map_err(|_| "bad emailId".to_owned())?;

            let rows = ctx
                .storage
                .emails_by_ids(account_id, vec![email_id])
                .await
                .map_err(|err| err.to_string())?;
            let row = rows.first().ok_or("no such email")?;
            let blob_id: owney_core::BlobId =
                row.blob_id.parse().map_err(|_| "bad blob".to_owned())?;
            let raw = ctx
                .storage
                .get_blob(blob_id)
                .await
                .map_err(|err| err.to_string())?;

            // Envelope: explicit, or derived from the message headers.
            let (mail_from, recipients) = match object.get("envelope") {
                Some(envelope) => {
                    let mail_from = envelope
                        .get("mailFrom")
                        .and_then(|m| m.get("email"))
                        .and_then(Value::as_str)
                        .unwrap_or(&ctx.account.email)
                        .to_owned();
                    let recipients: Vec<String> = envelope
                        .get("rcptTo")
                        .and_then(Value::as_array)
                        .map(|list| {
                            list.iter()
                                .filter_map(|r| r.get("email")?.as_str().map(str::to_owned))
                                .collect()
                        })
                        .unwrap_or_default();
                    (mail_from, recipients)
                }
                None => {
                    let recipients = recipients_from_raw(&raw);
                    (ctx.account.email.clone(), recipients)
                }
            };
            if recipients.is_empty() {
                return Err("no recipients".to_owned());
            }

            let queued = submitter
                .submit_with_priority(account_id, mail_from, recipients, raw, row.chat_mode)
                .await
                .map_err(|err| err.to_string())?;
            Ok(json!({
                "id": queued.first().map(|id| id.to_string()).unwrap_or_default(),
                "undoStatus": "final",
            }))
        }
        .await;

        match result {
            Ok(value) => {
                created.insert(client_id, value);
            }
            Err(description) => {
                not_created.insert(
                    client_id,
                    json!({"type": "invalidProperties", "description": description}),
                );
            }
        }
    }

    Ok(json!({
        "accountId": args.account_id,
        "oldState": "0",
        "newState": "0",
        "created": created,
        "notCreated": not_created,
        "updated": {},
        "destroyed": [],
    }))
}

/// All To/Cc/Bcc addresses from a raw message.
fn recipients_from_raw(raw: &[u8]) -> Vec<String> {
    let Some(message) = mail_parser::MessageParser::default().parse(raw) else {
        return Vec::new();
    };
    let mut recipients = Vec::new();
    for addresses in [message.to(), message.cc(), message.bcc()]
        .into_iter()
        .flatten()
    {
        for addr in addresses.iter() {
            if let Some(email) = addr.address() {
                recipients.push(email.to_owned());
            }
        }
    }
    recipients
}

async fn apply_update(
    ctx: &JmapCtx,
    account_id: owney_core::AccountId,
    id: &str,
    patch: &Value,
) -> Result<(), String> {
    let email_id: owney_core::EmailId = id.parse().map_err(|_| format!("bad id {id}"))?;
    let Value::Object(patch) = patch else {
        return Err("patch must be an object".into());
    };

    // Load current keywords/mailboxes so `keywords/$seen` style patches apply
    // on top of existing state.
    let rows = ctx
        .storage
        .emails_by_ids(account_id, vec![email_id])
        .await
        .map_err(|err| err.to_string())?;
    let row = rows.first().ok_or_else(|| format!("no email {id}"))?;

    let mut keywords: Option<Vec<String>> = None;
    let mut mailbox_ids: Option<Vec<String>> = None;

    for (key, value) in patch {
        if key == "keywords" {
            let Value::Object(map) = value else {
                return Err("keywords must be an object".into());
            };
            keywords = Some(map.keys().cloned().collect());
        } else if let Some(keyword) = key.strip_prefix("keywords/") {
            let mut current = keywords.take().unwrap_or_else(|| row.keywords.clone());
            let keyword = keyword.to_lowercase();
            match value {
                Value::Bool(true) => {
                    if !current.contains(&keyword) {
                        current.push(keyword);
                    }
                }
                Value::Bool(false) | Value::Null => current.retain(|k| k != &keyword),
                _ => return Err(format!("bad value for {key}")),
            }
            keywords = Some(current);
        } else if key == "mailboxIds" {
            let Value::Object(map) = value else {
                return Err("mailboxIds must be an object".into());
            };
            mailbox_ids = Some(map.keys().cloned().collect());
        } else if let Some(mailbox) = key.strip_prefix("mailboxIds/") {
            let mut current = mailbox_ids
                .take()
                .unwrap_or_else(|| row.mailbox_ids.clone());
            match value {
                Value::Bool(true) => {
                    if !current.iter().any(|m| m == mailbox) {
                        current.push(mailbox.to_owned());
                    }
                }
                Value::Bool(false) | Value::Null => current.retain(|m| m != mailbox),
                _ => return Err(format!("bad value for {key}")),
            }
            mailbox_ids = Some(current);
        } else {
            return Err(format!("unsupported property {key}"));
        }
    }

    let mailbox_ids = match mailbox_ids {
        Some(ids) => Some(
            ids.iter()
                .map(|id| id.parse().map_err(|_| format!("bad mailbox id {id}")))
                .collect::<Result<Vec<owney_core::MailboxId>, String>>()?,
        ),
        None => None,
    };

    // Track if $junk status changed for Bayes training
    let old_is_junk = row.keywords.iter().any(|k| k == "$junk");
    let new_is_junk = keywords
        .as_ref()
        .map(|kw| kw.iter().any(|k| k == "$junk"))
        .unwrap_or(old_is_junk);

    ctx.storage
        .update_email(account_id, email_id, keywords, mailbox_ids)
        .await
        .map_err(|err| err.to_string())?;

    // Train Bayes classifier if $junk status changed
    if old_is_junk != new_is_junk {
        let blob_id: owney_core::BlobId = row.blob_id.parse().map_err(|_| "bad blob".to_owned())?;
        if let Ok(raw) = ctx.storage.get_blob(blob_id).await {
            let tokens = owney_spam::bayes::tokenize(&raw);
            let is_spam = new_is_junk; // new_is_junk=true means moved TO junk (spam training)
            let _ = ctx.storage.train_spam_tokens(account_id, &tokens, is_spam).await;
        }
    }

    Ok(())
}

fn parse<T: serde::de::DeserializeOwned>(args: Value) -> Result<T, MethodError> {
    serde_json::from_value(args).map_err(|err| MethodError::InvalidArguments(err.to_string()))
}
