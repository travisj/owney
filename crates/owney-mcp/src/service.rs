//! The mailbox service the MCP tools call. Deliberately the same operations
//! the JMAP layer exposes — MCP and JMAP are two skins over one service, so an
//! agent and a client can never drift apart.

use std::sync::Arc;

use owney_core::{AccountId, EmailId, MailboxId};
use owney_storage::Storage;
use serde_json::{Value, json};

/// Everything a request needs: the authenticated account and its handles.
#[allow(missing_debug_implementations)]
pub struct McpCtx {
    pub account_id: AccountId,
    pub account_email: String,
    pub storage: Arc<Storage>,
    pub submitter: Option<Arc<dyn owney_delivery::Submitter>>,
    /// Whether this token is allowed to send mail.
    pub may_send: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("{0}")]
    Invalid(String),
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("storage: {0}")]
    Storage(#[from] owney_storage::StorageError),
}

fn parse_email_id(id: &str) -> Result<EmailId, ServiceError> {
    id.parse()
        .map_err(|_| ServiceError::Invalid(format!("bad email id {id}")))
}

impl McpCtx {
    pub async fn list_mailboxes(&self) -> Result<Value, ServiceError> {
        let mailboxes = self.storage.mailboxes(self.account_id).await?;
        Ok(json!(
            mailboxes
                .iter()
                .map(|m| json!({
                    "id": m.id,
                    "name": m.name,
                    "role": m.role,
                    "total": m.total_emails,
                    "unread": m.unread_emails,
                }))
                .collect::<Vec<_>>()
        ))
    }

    pub async fn search(
        &self,
        mailbox_role: Option<&str>,
        limit: usize,
    ) -> Result<Value, ServiceError> {
        let in_mailbox = match mailbox_role {
            Some(role) => {
                self.storage
                    .mailbox_id_by_role(self.account_id, role)
                    .await?
            }
            None => None,
        };
        let (ids, total, _state) = self
            .storage
            .query_emails(self.account_id, in_mailbox, 0, limit.min(100))
            .await?;
        let parsed: Vec<EmailId> = ids.iter().filter_map(|id| id.parse().ok()).collect();
        let rows = self.storage.emails_by_ids(self.account_id, parsed).await?;
        Ok(json!({
            "total": total,
            "results": rows.iter().map(|r| json!({
                "id": r.id,
                "threadId": r.thread_id,
                "from": r.from_addr,
                "subject": r.subject,
                "keywords": r.keywords,
                "receivedAt": owney_core::time::iso8601_utc(r.received_at),
            })).collect::<Vec<_>>(),
        }))
    }

    pub async fn get_email(&self, id: &str) -> Result<Value, ServiceError> {
        let email_id = parse_email_id(id)?;
        let rows = self
            .storage
            .emails_by_ids(self.account_id, vec![email_id])
            .await?;
        let row = rows
            .into_iter()
            .next()
            .ok_or_else(|| ServiceError::Invalid(format!("no email {id}")))?;

        let blob_id = row
            .blob_id
            .parse()
            .map_err(|_| ServiceError::Invalid("bad blob".into()))?;
        let raw = self.storage.get_blob(blob_id).await?;
        let body = mail_parser::MessageParser::default()
            .parse(&raw)
            .and_then(|m| m.body_text(0).map(|b| b.into_owned()))
            .unwrap_or_default();
        let annotations = self.storage.annotations(email_id).await?;

        Ok(json!({
            "id": row.id,
            "threadId": row.thread_id,
            "from": row.from_addr,
            "subject": row.subject,
            "keywords": row.keywords,
            "mailboxIds": row.mailbox_ids,
            "receivedAt": owney_core::time::iso8601_utc(row.received_at),
            "body": body,
            "aiAnnotations": annotations.iter().map(|(kind, content)| {
                json!({"kind": kind, "content": serde_json::from_str::<Value>(content).unwrap_or_else(|_| json!(content))})
            }).collect::<Vec<_>>(),
        }))
    }

    pub async fn get_thread(&self, thread_id: &str) -> Result<Value, ServiceError> {
        let tid = thread_id
            .parse()
            .map_err(|_| ServiceError::Invalid(format!("bad thread id {thread_id}")))?;
        let threads = self
            .storage
            .thread_emails(self.account_id, vec![tid])
            .await?;
        let email_ids = threads
            .into_iter()
            .next()
            .map(|(_, ids)| ids)
            .unwrap_or_default();
        let parsed: Vec<EmailId> = email_ids.iter().filter_map(|id| id.parse().ok()).collect();
        let rows = self.storage.emails_by_ids(self.account_id, parsed).await?;
        Ok(json!({
            "threadId": thread_id,
            "emails": rows.iter().map(|r| json!({
                "id": r.id, "from": r.from_addr, "subject": r.subject,
                "receivedAt": owney_core::time::iso8601_utc(r.received_at),
            })).collect::<Vec<_>>(),
        }))
    }

    /// Move to a role mailbox (archive, junk, trash, inbox, screener).
    pub async fn move_email(&self, id: &str, role: &str) -> Result<Value, ServiceError> {
        let email_id = parse_email_id(id)?;
        let mailbox = self
            .storage
            .mailbox_id_by_role(self.account_id, role)
            .await?
            .ok_or_else(|| ServiceError::Invalid(format!("no {role} mailbox")))?;
        let mailbox: MailboxId = mailbox
            .parse()
            .map_err(|_| ServiceError::Invalid("bad mailbox".into()))?;

        // Record for undo (prior placement), then move.
        let rows = self
            .storage
            .emails_by_ids(self.account_id, vec![email_id])
            .await?;
        let prior = rows
            .first()
            .map(|r| r.mailbox_ids.clone())
            .unwrap_or_default();
        self.storage
            .update_email(self.account_id, email_id, None, Some(vec![mailbox]))
            .await?;
        self.storage
            .record_ai_action(
                self.account_id,
                Some(email_id),
                "mcp:move",
                &format!("Moved to {role}"),
                Some(json!({ "mailboxIds": prior }).to_string()),
            )
            .await?;
        Ok(json!({"moved": id, "to": role}))
    }

    pub async fn set_keyword(
        &self,
        id: &str,
        keyword: &str,
        present: bool,
    ) -> Result<Value, ServiceError> {
        let email_id = parse_email_id(id)?;
        let rows = self
            .storage
            .emails_by_ids(self.account_id, vec![email_id])
            .await?;
        let row = rows
            .first()
            .ok_or_else(|| ServiceError::Invalid(format!("no email {id}")))?;
        let mut keywords = row.keywords.clone();
        let keyword = keyword.to_lowercase();
        if present {
            if !keywords.contains(&keyword) {
                keywords.push(keyword.clone());
            }
        } else {
            keywords.retain(|k| k != &keyword);
        }
        self.storage
            .update_email(self.account_id, email_id, Some(keywords), None)
            .await?;
        Ok(json!({"id": id, "keyword": keyword, "present": present}))
    }

    pub async fn summarize_thread(&self, thread_id: &str) -> Result<Value, ServiceError> {
        // Uses stored per-message summaries when present; the model call
        // itself lives in ms-ai and is invoked by the enrichment worker.
        let thread = self.get_thread(thread_id).await?;
        Ok(json!({
            "threadId": thread_id,
            "note": "per-message AI summaries appear in get_email.aiAnnotations",
            "emails": thread["emails"],
        }))
    }

    pub async fn create_draft(
        &self,
        to: &[String],
        subject: &str,
        body: &str,
    ) -> Result<Value, ServiceError> {
        let drafts = self
            .storage
            .mailbox_id_by_role(self.account_id, "drafts")
            .await?
            .ok_or_else(|| ServiceError::Invalid("no drafts mailbox".into()))?;
        let drafts: MailboxId = drafts
            .parse()
            .map_err(|_| ServiceError::Invalid("bad mailbox".into()))?;

        let raw = compose(&self.account_email, to, subject, body);
        let ingested = self
            .storage
            .ingest_email_into(
                self.account_id,
                raw,
                owney_storage::MailboxTarget::Id(drafts),
                None,
                false,
            )
            .await?;
        self.storage
            .update_email(
                self.account_id,
                ingested.id,
                Some(vec!["$draft".into()]),
                None,
            )
            .await?;
        Ok(json!({"draftId": ingested.id.to_string()}))
    }

    pub async fn send_email(
        &self,
        to: &[String],
        subject: &str,
        body: &str,
    ) -> Result<Value, ServiceError> {
        if !self.may_send {
            return Err(ServiceError::Forbidden(
                "this token is not permitted to send mail".into(),
            ));
        }
        let submitter = self
            .submitter
            .as_ref()
            .ok_or_else(|| ServiceError::Invalid("sending is not enabled".into()))?;
        if to.is_empty() {
            return Err(ServiceError::Invalid(
                "at least one recipient required".into(),
            ));
        }
        let raw = compose(&self.account_email, to, subject, body);
        let queued = submitter
            .submit(
                self.account_id,
                self.account_email.clone(),
                to.to_vec(),
                raw,
            )
            .await
            .map_err(|err| match err {
                owney_delivery::SubmitError::Refused(msg) => ServiceError::Forbidden(msg),
                owney_delivery::SubmitError::Transport(msg) => ServiceError::Invalid(msg),
            })?;
        Ok(json!({"queued": queued.len()}))
    }

    pub async fn get_ai_activity(&self, limit: usize) -> Result<Value, ServiceError> {
        let actions = self
            .storage
            .ai_actions(self.account_id, limit.min(100))
            .await?;
        Ok(json!(
            actions
                .iter()
                .map(|a| json!({
                    "id": a.id.to_string(),
                    "skill": a.skill,
                    "description": a.description,
                    "undone": a.undone,
                    "undoable": a.inverse_patch.is_some(),
                    "createdAt": owney_core::time::iso8601_utc(a.created_at),
                }))
                .collect::<Vec<_>>()
        ))
    }

    pub async fn undo_action(&self, action_id: &str) -> Result<Value, ServiceError> {
        let id = action_id
            .parse()
            .map_err(|_| ServiceError::Invalid(format!("bad action id {action_id}")))?;
        owney_ai::undo_action(&self.storage, self.account_id, id)
            .await
            .map_err(|err| ServiceError::Invalid(err.to_string()))?;
        Ok(json!({"undone": action_id}))
    }

    pub async fn nl_search(&self, _query: &str, limit: usize) -> Result<Value, ServiceError> {
        // TODO: Integrate owney_ai::nl_search::translate_to_filter to convert query to JMAP filter.
        // For now, return recent emails from inbox (stub implementation).
        // This demonstrates the MCP tool plumbing; real AI-based translation comes later.
        // Reuse the existing search method which returns inbox emails.
        self.search(Some("inbox"), limit).await
    }
}

fn compose(from: &str, to: &[String], subject: &str, body: &str) -> Vec<u8> {
    let domain = from.rsplit_once('@').map(|(_, d)| d).unwrap_or("local");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    format!(
        "From: <{from}>\r\nTo: {to}\r\nSubject: {subject}\r\nDate: {date}\r\n\
         Message-ID: <{id}@{domain}>\r\nMIME-Version: 1.0\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\r\n{body}",
        to = to.join(", "),
        date = owney_core::time::rfc2822_utc(now),
        id = uuid::Uuid::now_v7(),
        body = body.replace('\n', "\r\n"),
    )
    .into_bytes()
}
