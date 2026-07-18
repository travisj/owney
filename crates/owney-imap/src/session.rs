//! IMAP session state machine.

use std::net::IpAddr;
use std::sync::Arc;

use owney_core::AccountId;
use owney_storage::Storage;

/// Per-connection IMAP session state.
pub struct ImapSession {
    storage: Arc<Storage>,
    // Kept for forthcoming logging/UNTAGGED support in the IMAP bridge.
    #[allow(dead_code)]
    remote: IpAddr,
    /// Currently authenticated account (None until LOGIN succeeds).
    account: Option<(AccountId, String)>,
    /// Currently selected mailbox ID (None until SELECT succeeds).
    selected_mailbox: Option<String>,
    /// Command tag from client (for response correlation).
    last_tag: String,
    /// Sequence number for UNTAGGED responses.
    #[allow(dead_code)]
    sequence: u32,
}

impl std::fmt::Debug for ImapSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImapSession")
            .field("remote", &self.remote)
            .field("account", &self.account)
            .field("selected_mailbox", &self.selected_mailbox)
            .finish_non_exhaustive()
    }
}

impl ImapSession {
    pub fn new(storage: Arc<Storage>, remote: IpAddr) -> Self {
        Self {
            storage,
            remote,
            account: None,
            selected_mailbox: None,
            last_tag: String::new(),
            sequence: 0,
        }
    }

    /// Process one line of IMAP input. Returns response bytes or None if awaiting more data.
    pub async fn handle_input(&mut self, input: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
        let line = String::from_utf8_lossy(input).trim().to_string();

        if line.is_empty() {
            return Ok(None);
        }

        // Parse tag and command: "A001 LOGIN user password"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            return Ok(Some(b"* BAD Invalid command\r\n".to_vec()));
        }

        let tag = parts[0].to_string();
        let cmd = parts[1].to_uppercase();
        self.last_tag = tag.clone();

        let response = match cmd.as_str() {
            "LOGIN" => self.handle_login(&parts).await,
            "LOGOUT" => self.handle_logout(),
            "CAPABILITY" => self.handle_capability(),
            "SELECT" => self.handle_select(&parts).await,
            "LIST" => self.handle_list(),
            "SEARCH" => self.handle_search().await,
            "FETCH" => self.handle_fetch(&parts).await,
            "NOOP" => self.handle_noop(),
            "APPEND" => self.handle_append_blocked(),
            "STORE" => self.handle_store_blocked(),
            _ => format!("{} BAD Unknown command\r\n", tag),
        };

        Ok(Some(response.into_bytes()))
    }

    async fn handle_login(&mut self, parts: &[&str]) -> String {
        if parts.len() < 4 {
            return format!(
                "{} BAD LOGIN requires username and password\r\n",
                self.last_tag
            );
        }

        let username = parts[2];
        let password = parts[3];

        // Password is treated as a bearer token (created via `owneyd admin token`)
        match self.storage.account_by_token(password).await {
            Ok(Some(account)) => {
                // Verify the token's account matches the requested username
                if account.email.eq_ignore_ascii_case(username) {
                    self.account = Some((account.id, account.email.clone()));
                    format!("{} OK LOGIN completed\r\n", self.last_tag)
                } else {
                    format!(
                        "{} NO [AUTHENTICATIONFAILED] Invalid credentials\r\n",
                        self.last_tag
                    )
                }
            }
            Ok(None) => {
                format!(
                    "{} NO [AUTHENTICATIONFAILED] Invalid credentials\r\n",
                    self.last_tag
                )
            }
            Err(_) => {
                format!(
                    "{} NO [UNAVAILABLE] Temporary authentication failure\r\n",
                    self.last_tag
                )
            }
        }
    }

    fn handle_logout(&self) -> String {
        format!(
            "* BYE Owney IMAP4rev2 goodbye\r\n{} OK LOGOUT completed\r\n",
            self.last_tag
        )
    }

    fn handle_capability(&self) -> String {
        format!(
            "* CAPABILITY IMAP4rev2 STARTTLS PLAIN LOGIN\r\n{} OK CAPABILITY completed\r\n",
            self.last_tag
        )
    }

    async fn handle_select(&mut self, parts: &[&str]) -> String {
        if !self.is_authenticated() {
            return format!("{} NO Please login first\r\n", self.last_tag);
        }
        if parts.len() < 3 {
            return format!("{} BAD SELECT requires mailbox name\r\n", self.last_tag);
        }

        // TODO: Fetch mailbox from storage and return FLAGS, EXISTS, RECENT
        self.selected_mailbox = Some(parts[2].to_string());
        format!(
            "* 0 EXISTS\r\n* 0 RECENT\r\n* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n{} OK [READ-ONLY] SELECT completed\r\n",
            self.last_tag
        )
    }

    fn handle_list(&self) -> String {
        // TODO: List mailboxes from storage
        format!(
            "* LIST (\\Noselect) \"/\" \"\"\r\n{} OK LIST completed\r\n",
            self.last_tag
        )
    }

    async fn handle_search(&mut self) -> String {
        if !self.is_authenticated() {
            return format!("{} NO Please login first\r\n", self.last_tag);
        }

        // TODO: Run JMAP query based on SEARCH criteria
        format!("* SEARCH\r\n{} OK SEARCH completed\r\n", self.last_tag)
    }

    async fn handle_fetch(&mut self, parts: &[&str]) -> String {
        if !self.is_authenticated() {
            return format!("{} NO Please login first\r\n", self.last_tag);
        }
        if parts.len() < 3 {
            return format!(
                "{} BAD FETCH requires sequence-set and item-names\r\n",
                self.last_tag
            );
        }

        // TODO: Fetch emails from storage and format as IMAP
        format!("{} OK FETCH completed\r\n", self.last_tag)
    }

    fn handle_noop(&self) -> String {
        format!("{} OK NOOP completed\r\n", self.last_tag)
    }

    fn handle_append_blocked(&self) -> String {
        format!(
            "{} NO APPEND not supported; use JMAP EmailSubmission instead\r\n",
            self.last_tag
        )
    }

    fn handle_store_blocked(&self) -> String {
        format!(
            "{} NO STORE not supported; use JMAP Email/set instead\r\n",
            self.last_tag
        )
    }

    fn is_authenticated(&self) -> bool {
        self.account.is_some()
    }
}
