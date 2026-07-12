//! The JMAP session object (RFC 8620 §2): client discovery.
//!
//! Clients fetch the session object via `GET /.well-known/jmap` to discover:
//! - Server capabilities and their properties
//! - Available accounts and per-account capabilities
//! - Endpoint URLs (JMAP API, upload, download, etc.)
//! - Server session state
//!
//! # Session Object
//!
//! [`Session`] is the top-level response. Fields:
//! - `capabilities`: Server-wide capabilities (e.g. `urn:ietf:params:jmap:core`)
//!   and their properties (RFC 8620 §2).
//! - `accounts`: Map of account ID to [`SessionAccount`].
//! - `primaryAccounts`: For each capability, which account to use by default.
//! - `username`, `state`: Username and an opaque token. If `state` changes,
//!   clients should refetch the session (server configuration changed).
//! - API URLs: `apiUrl`, `downloadUrl`, `uploadUrl`, `eventSourceUrl`.
//!   These use template placeholders (e.g. `{accountId}`, `{blobId}`)
//!   that clients fill in (RFC 8620 §2).
//!
//! # SessionAccount
//!
//! [`SessionAccount`] describes one account:
//! - `name`: Display name for the account.
//! - `isPersonal`: True if this is the user's personal account.
//! - `isReadOnly`: True if the account is read-only.
//! - `accountCapabilities`: Per-account capabilities (not including core,
//!   which every account implicitly supports).
//!
//! # Common Pattern: Single-Account Server
//!
//! Most personal JMAP servers have one account. Use [`Session::for_account`]
//! to build the session:
//!
//! ```ignore
//! let mut dispatcher: Dispatcher<MyContext> = Dispatcher::new("v1");
//! dispatcher.add_capability("urn:ietf:params:jmap:mail", json!({}));
//! dispatcher.add_capability("urn:ietf:params:jmap:submission", json!({}));
//! // ... register methods ...
//!
//! let session = Session::for_account(
//!     "https://mail.example.com",   // base URL
//!     "alice@example.com",           // username
//!     "account-123",                 // account ID
//!     dispatcher.capabilities().clone(),  // capabilities
//!     "s0",                          // session state
//! );
//!
//! // Return session as JSON at GET /.well-known/jmap
//! ```
//!
//! This automatically:
//! - Sets up URL templates (apiUrl, uploadUrl, etc.)
//! - Filters out `urn:ietf:params:jmap:core` from account capabilities
//! - Maps each capability to the account as the primary account
//!
//! # Multi-Account Servers
//!
//! For servers with multiple accounts, build [`Session`] directly:
//!
//! ```ignore
//! let mut capabilities = BTreeMap::new();
//! capabilities.insert("urn:ietf:params:jmap:core".to_owned(), core_cap);
//! capabilities.insert("urn:ietf:params:jmap:mail".to_owned(), mail_cap);
//!
//! let mut accounts = BTreeMap::new();
//! accounts.insert("account-1".to_owned(), SessionAccount {
//!     name: "alice@example.com".to_owned(),
//!     is_personal: true,
//!     is_read_only: false,
//!     account_capabilities: /* mail-only accounts */,
//! });
//! accounts.insert("account-2".to_owned(), SessionAccount {
//!     name: "shared-folder".to_owned(),
//!     is_personal: false,
//!     is_read_only: false,
//!     account_capabilities: /* mail-only accounts */,
//! });
//!
//! let session = Session {
//!     capabilities,
//!     accounts,
//!     primary_accounts: /* capability → default account */,
//!     username: "alice@example.com",
//!     api_url: "https://mail.example.com/jmap/api",
//!     download_url: "https://mail.example.com/jmap/download/{accountId}/{blobId}/{name}",
//!     upload_url: "https://mail.example.com/jmap/upload/{accountId}",
//!     event_source_url: "https://mail.example.com/jmap/events",
//!     state: "s0",
//! };
//! ```
//!
//! # URL Templates
//!
//! The session object contains URL templates with placeholders. Clients
//! replace these with their own values:
//! - `{accountId}`: The account ID (from `Session::accounts` keys)
//! - `{blobId}`: A blob identifier
//! - `{name}`: A display name
//! - `{type}`: A MIME type
//! - `{types}`, `{closeafter}`, `{ping}`: EventSource parameters
//!
//! Example: If `downloadUrl` is
//! ```
//! https://mail.example.com/jmap/download/{accountId}/{blobId}/{name}
//! ```
//! A client needing to download blob `b123` from account `a1` would fetch:
//! ```
//! https://mail.example.com/jmap/download/a1/b123/document.pdf
//! ```
//!
//! See RFC 8620 §2 for the complete set of templates.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub capabilities: BTreeMap<String, Value>,
    pub accounts: BTreeMap<String, SessionAccount>,
    /// capability urn → account id to use by default for it.
    pub primary_accounts: BTreeMap<String, String>,
    pub username: String,
    pub api_url: String,
    pub download_url: String,
    pub upload_url: String,
    pub event_source_url: String,
    pub state: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionAccount {
    pub name: String,
    pub is_personal: bool,
    pub is_read_only: bool,
    pub account_capabilities: BTreeMap<String, Value>,
}

impl Session {
    /// A single-account session — the common personal-server case.
    pub fn for_account(
        base_url: &str,
        username: &str,
        account_id: &str,
        capabilities: BTreeMap<String, Value>,
        state: &str,
    ) -> Self {
        let base = base_url.trim_end_matches('/');
        let account_capabilities: BTreeMap<String, Value> = capabilities
            .keys()
            .filter(|urn| *urn != crate::CORE_CAPABILITY)
            .map(|urn| (urn.clone(), Value::Object(Default::default())))
            .collect();
        let primary_accounts = account_capabilities
            .keys()
            .map(|urn| (urn.clone(), account_id.to_owned()))
            .collect();

        let mut accounts = BTreeMap::new();
        accounts.insert(
            account_id.to_owned(),
            SessionAccount {
                name: username.to_owned(),
                is_personal: true,
                is_read_only: false,
                account_capabilities,
            },
        );

        Session {
            capabilities,
            accounts,
            primary_accounts,
            username: username.to_owned(),
            api_url: format!("{base}/jmap/api"),
            download_url: format!(
                "{base}/jmap/download/{{accountId}}/{{blobId}}/{{name}}?type={{type}}"
            ),
            upload_url: format!("{base}/jmap/upload/{{accountId}}"),
            event_source_url: format!(
                "{base}/jmap/eventsource?types={{types}}&closeafter={{closeafter}}&ping={{ping}}"
            ),
            state: state.to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn session_shape() {
        let mut capabilities = BTreeMap::new();
        capabilities.insert(
            crate::CORE_CAPABILITY.to_owned(),
            json!({"maxSizeUpload": 1}),
        );
        capabilities.insert("urn:ietf:params:jmap:mail".to_owned(), json!({}));

        let session = Session::for_account(
            "https://mail.example.com/",
            "alice@example.com",
            "a1",
            capabilities,
            "s0",
        );
        let value = serde_json::to_value(&session).expect("serialize");
        assert_eq!(value["apiUrl"], "https://mail.example.com/jmap/api");
        assert_eq!(value["accounts"]["a1"]["isPersonal"], true);
        assert_eq!(
            value["primaryAccounts"]["urn:ietf:params:jmap:mail"], "a1",
            "mail capability points at the account"
        );
        assert!(
            value["accounts"]["a1"]["accountCapabilities"]
                .get("urn:ietf:params:jmap:core")
                .is_none(),
            "core is not an account capability"
        );
        assert!(value["uploadUrl"].as_str().unwrap().contains("{accountId}"));
        assert!(value["downloadUrl"].as_str().unwrap().contains("{blobId}"));
        assert!(
            value["eventSourceUrl"]
                .as_str()
                .unwrap()
                .contains("{types}")
        );
    }
}
