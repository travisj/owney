//! The JMAP session object (RFC 8620 §2), served at `/.well-known/jmap`.

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
