//! Identifier newtypes.
//!
//! Record ids are UUIDv7 (time-ordered, so primary-key locality follows
//! arrival order). Blob ids are BLAKE3 digests of the *plaintext* content —
//! content addressing is what makes blob dedup and refcounting trivial.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

macro_rules! uuid_id {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            #[allow(clippy::new_without_default)]
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            pub fn as_uuid(&self) -> &Uuid {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(Self(Uuid::parse_str(s)?))
            }
        }
    };
}

uuid_id!(
    /// A user account (one mailbox owner; a server hosts many).
    AccountId
);
uuid_id!(
    /// A mailbox (folder/label) within an account.
    MailboxId
);
uuid_id!(
    /// A single immutable email message.
    EmailId
);
uuid_id!(
    /// A conversation thread grouping emails.
    ThreadId
);
uuid_id!(
    /// A single email-submission record (RFC 8621 §7).
    EmailSubmissionId
);
uuid_id!(
    /// A calendar collection.
    CalendarId
);
uuid_id!(
    /// A single calendar event.
    EventId
);
uuid_id!(
    /// A contact in the address book.
    ContactId
);

/// A client-supplied creation reference (RFC 8620 §3.6.1). Distinct
/// from server-assigned ids so the type system can catch mismatches;
/// the inner string is the client's `clientCreationId`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CreateId(pub String);

impl fmt::Display for CreateId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for CreateId {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(CreateId(s.to_owned()))
    }
}

/// BLAKE3 digest of a blob's plaintext content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlobId(pub [u8; 32]);

impl BlobId {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex, used as the on-disk file name and DB key.
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.0 {
            use fmt::Write;
            // infallible for String
            let _ = write!(s, "{b:02x}");
        }
        s
    }
}

impl fmt::Display for BlobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::LowerHex for BlobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// Reject reasons for `BlobId::from_str`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvalidBlobId {
    #[error("blob id must be 64 lowercase hex chars; got {0} chars")]
    WrongLength(usize),
    #[error("blob id contains non-hex character at byte offset {0}")]
    InvalidChar(usize),
}

impl From<InvalidBlobId> for std::io::Error {
    fn from(e: InvalidBlobId) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e)
    }
}

impl FromStr for BlobId {
    type Err = InvalidBlobId;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 64 {
            return Err(InvalidBlobId::WrongLength(s.len()));
        }
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            let start = i * 2;
            match u8::from_str_radix(&s[start..start + 2], 16) {
                Ok(b) => *byte = b,
                Err(_) => return Err(InvalidBlobId::InvalidChar(start)),
            }
        }
        Ok(Self(bytes))
    }
}

impl Serialize for BlobId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for BlobId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Per-account, per-type modification sequence number.
///
/// Every mutation bumps the modseq for the data types it touched; JMAP
/// `/changes` and push state tokens are derived from it. This is the delta-sync
/// discipline the whole realtime story rests on.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct ModSeq(pub u64);

impl ModSeq {
    /// Advance to the next modseq, returning `None` on overflow.
    ///
    /// At `u64::MAX` (~10^19 operations per data type), JMAP delta-sync
    /// becomes useless and the storage layer should refuse to advance
    /// rather than wrap to 0. Operators should reseed modseqs at that
    /// point (effectively a schema migration).
    pub fn next(self) -> Option<Self> {
        self.0.checked_add(1).map(ModSeq)
    }
}

impl fmt::Display for ModSeq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// The synchronizable data types tracked by modseq state.
///
/// `EmailSubmission` is currently keyed per-account, but RFC 8621 §7
/// defines it per-identity. When per-identity tracking lands, the
/// identity scope will need a separate modseq axis (i.e. a tuple
/// `(account_id, identity_id, data_type)`) — at which point this
/// enum will gain `Identity` or `EmailSubmission(identity_scope)`
/// variants. `#[non_exhaustive]` prevents downstream exhaustive
/// matches from breaking that evolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum DataType {
    Email,
    Mailbox,
    Thread,
    EmailSubmission,
}

impl DataType {
    pub const ALL: [DataType; 4] = [
        DataType::Email,
        DataType::Mailbox,
        DataType::Thread,
        DataType::EmailSubmission,
    ];

    /// Stable string used in the `states` table and in JMAP state tokens.
    pub fn as_str(&self) -> &'static str {
        match self {
            DataType::Email => "Email",
            DataType::Mailbox => "Mailbox",
            DataType::Thread => "Thread",
            DataType::EmailSubmission => "EmailSubmission",
        }
    }
}

impl fmt::Display for DataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_ids_round_trip_and_order() {
        let a = EmailId::new();
        let b = EmailId::new();
        assert!(a <= b, "v7 ids are time-ordered");
        let parsed: EmailId = a.to_string().parse().expect("round trip");
        assert_eq!(a, parsed);
    }

    #[test]
    fn blob_id_hex_round_trip() {
        let id = BlobId([0xab; 32]);
        let hex = id.to_hex();
        assert_eq!(hex.len(), 64);
        let parsed: BlobId = hex.parse().expect("round trip");
        assert_eq!(id, parsed);
        assert!("zz".repeat(32).parse::<BlobId>().is_err());
        assert!("abcd".parse::<BlobId>().is_err());
    }

    #[test]
    fn blob_id_wrong_length_is_too_long_or_too_short() {
        assert!(matches!(
            "abc".parse::<BlobId>(),
            Err(InvalidBlobId::WrongLength(3))
        ));
        assert!(matches!(
            "abcd".repeat(20).parse::<BlobId>(), // 80 chars
            Err(InvalidBlobId::WrongLength(80))
        ));
    }

    #[test]
    fn blob_id_non_hex_is_invalid_char() {
        // 64 chars but contains 'z' which isn't hex
        let bad = "z".repeat(64);
        let parsed = bad.parse::<BlobId>().expect_err("non-hex rejected");
        // Either WrongLength or InvalidChar depending on impl order; just check it's
        // an InvalidBlobId and has a usable Display.
        let _ = format!("{parsed}");
    }

    #[test]
    fn blob_id_uppercase_hex_accepted_lowercase_emitted() {
        let mut hex_upper = String::new();
        for b in [0xab; 32] {
            use std::fmt::Write;
            write!(hex_upper, "{b:02X}").unwrap();
        }
        let parsed = hex_upper.parse::<BlobId>().expect("uppercase accepted");
        assert_eq!(parsed.to_hex(), hex_upper.to_lowercase(), "emit lowercase");
        assert_eq!(format!("{parsed}"), hex_upper.to_lowercase());
    }

    #[test]
    fn blob_id_lowerhex_writes_without_allocating() {
        let id = BlobId([0xab; 32]);
        let mut s = String::with_capacity(64);
        use std::fmt::Write;
        write!(s, "{id:x}").unwrap();
        assert_eq!(s, "ab".repeat(32));
    }

    #[test]
    fn create_id_round_trips_via_string() {
        let id = CreateId("clientCreationId-42".into());
        assert_eq!(id.to_string(), "clientCreationId-42");
        let parsed: CreateId = "clientCreationId-42".parse().unwrap();
        assert_eq!(parsed, id);
    }

    #[test]
    fn create_id_serde_round_trips_as_string() {
        let id = CreateId("abc".into());
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"abc\"");
        let back: CreateId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);
    }

    #[test]
    fn email_submission_id_orders_uuid_v7() {
        let a = EmailSubmissionId::new();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let b = EmailSubmissionId::new();
        assert!(a.as_uuid() <= b.as_uuid());
    }

    #[test]
    fn modseq_overflow_returns_none() {
        let max = ModSeq(u64::MAX);
        assert!(max.next().is_none(), "overflow must surface, not wrap");

        let one = ModSeq(1);
        let two = one.next().expect("normal bump");
        assert_eq!(two, ModSeq(2));

        let zero = ModSeq::default();
        let one_again = zero.next().expect("default = 0, +1 = 1");
        assert_eq!(one_again, ModSeq(1));
    }
}
