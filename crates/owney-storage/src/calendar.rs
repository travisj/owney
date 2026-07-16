//! Calendar storage: calendars and events with recurring event support.
//!
//! Schema:
//! - calendars: user's calendar collections (e.g., "Personal", "Work")
//! - calendar_events: events with optional recurrence rules (RFC 5545 subset)
//!
//! Recurring events are expanded on-demand when fetched; storage holds the
//! base event and rrule string.

use owney_core::{AccountId, CalendarId, EventId};
use rusqlite::{OptionalExtension, params};

use crate::Storage;
use crate::error::StorageError;

#[derive(Debug, Clone)]
pub struct Calendar {
    pub id: CalendarId,
    pub account_id: AccountId,
    pub name: String,
    pub description: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct CalendarEvent {
    pub id: EventId,
    pub calendar_id: CalendarId,
    pub title: String,
    pub description: Option<String>,
    pub start: i64,            // unix timestamp
    pub end: i64,              // unix timestamp
    pub rrule: Option<String>, // RFC 5545 RRULE (e.g., "FREQ=WEEKLY;UNTIL=20260801T000000Z")
    pub created_at: i64,
    pub updated_at: i64,
}

impl Storage {
    /// Create a calendar for an account.
    pub async fn create_calendar(
        &self,
        account_id: AccountId,
        name: String,
        description: Option<String>,
    ) -> Result<Calendar, StorageError> {
        let calendar_id = CalendarId::new();
        let now = crate::unix_now();

        self.db
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO calendars (id, account_id, name, description, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
                    params![
                        calendar_id.to_string(),
                        account_id.to_string(),
                        name,
                        description,
                        now
                    ],
                )?;
                Ok(Calendar {
                    id: calendar_id,
                    account_id,
                    name,
                    description,
                    created_at: now,
                    updated_at: now,
                })
            })
            .await
    }

    /// Get a calendar by ID.
    pub async fn get_calendar(
        &self,
        account_id: AccountId,
        calendar_id: CalendarId,
    ) -> Result<Option<Calendar>, StorageError> {
        self.db
            .call(move |conn| {
                Ok(conn
                    .query_row(
                        "SELECT id, account_id, name, description, created_at, updated_at
                         FROM calendars WHERE id = ?1 AND account_id = ?2",
                        params![calendar_id.to_string(), account_id.to_string()],
                        |row| {
                            Ok(Calendar {
                                id: row
                                    .get::<_, String>(0)?
                                    .parse()
                                    .unwrap_or_else(|_| CalendarId::new()),
                                account_id,
                                name: row.get(2)?,
                                description: row.get(3)?,
                                created_at: row.get(4)?,
                                updated_at: row.get(5)?,
                            })
                        },
                    )
                    .optional()?)
            })
            .await
    }

    /// Get a calendar by ID regardless of owning account (used by
    /// federation sync, where only the calendar ID is known).
    pub async fn get_calendar_by_id(
        &self,
        calendar_id: CalendarId,
    ) -> Result<Option<Calendar>, StorageError> {
        self.db
            .call(move |conn| {
                Ok(conn
                    .query_row(
                        "SELECT id, account_id, name, description, created_at, updated_at
                         FROM calendars WHERE id = ?1",
                        params![calendar_id.to_string()],
                        |row| {
                            Ok(Calendar {
                                id: row
                                    .get::<_, String>(0)?
                                    .parse()
                                    .unwrap_or_else(|_| CalendarId::new()),
                                account_id: row
                                    .get::<_, String>(1)?
                                    .parse()
                                    .unwrap_or_else(|_| AccountId::new()),
                                name: row.get(2)?,
                                description: row.get(3)?,
                                created_at: row.get(4)?,
                                updated_at: row.get(5)?,
                            })
                        },
                    )
                    .optional()?)
            })
            .await
    }

    /// List all calendars for an account.
    pub async fn list_calendars(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<Calendar>, StorageError> {
        self.db
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, account_id, name, description, created_at, updated_at
                     FROM calendars WHERE account_id = ?1 ORDER BY created_at",
                )?;
                let calendars = stmt
                    .query_map(params![account_id.to_string()], |row| {
                        Ok(Calendar {
                            id: row
                                .get::<_, String>(0)?
                                .parse()
                                .unwrap_or_else(|_| CalendarId::new()),
                            account_id,
                            name: row.get(2)?,
                            description: row.get(3)?,
                            created_at: row.get(4)?,
                            updated_at: row.get(5)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(calendars)
            })
            .await
    }

    /// Create an event in a calendar.
    pub async fn create_calendar_event(
        &self,
        calendar_id: CalendarId,
        title: String,
        description: Option<String>,
        start: i64,
        end: i64,
        rrule: Option<String>,
    ) -> Result<CalendarEvent, StorageError> {
        let event_id = EventId::new();
        let now = crate::unix_now();

        self.db
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO calendar_events
                     (id, calendar_id, title, description, start, end, rrule, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)",
                    params![
                        event_id.to_string(),
                        calendar_id.to_string(),
                        title,
                        description,
                        start,
                        end,
                        rrule,
                        now
                    ],
                )?;
                Ok(CalendarEvent {
                    id: event_id,
                    calendar_id,
                    title,
                    description,
                    start,
                    end,
                    rrule,
                    created_at: now,
                    updated_at: now,
                })
            })
            .await
    }

    /// Get an event by ID.
    pub async fn get_calendar_event(
        &self,
        event_id: EventId,
    ) -> Result<Option<CalendarEvent>, StorageError> {
        self.db
            .call(move |conn| {
                Ok(conn
                    .query_row(
                        "SELECT id, calendar_id, title, description, start, end, rrule, created_at, updated_at
                         FROM calendar_events WHERE id = ?1",
                        params![event_id.to_string()],
                        |row| {
                            Ok(CalendarEvent {
                                id: row.get::<_, String>(0)?.parse().unwrap_or_else(|_| EventId::new()),
                                calendar_id: row.get::<_, String>(1)?.parse().unwrap_or_else(|_| CalendarId::new()),
                                title: row.get(2)?,
                                description: row.get(3)?,
                                start: row.get(4)?,
                                end: row.get(5)?,
                                rrule: row.get(6)?,
                                created_at: row.get(7)?,
                                updated_at: row.get(8)?,
                            })
                        },
                    )
                    .optional()?)
            })
            .await
    }

    /// List events in a calendar.
    pub async fn list_calendar_events(
        &self,
        calendar_id: CalendarId,
    ) -> Result<Vec<CalendarEvent>, StorageError> {
        self.db
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, calendar_id, title, description, start, end, rrule, created_at, updated_at
                     FROM calendar_events WHERE calendar_id = ?1 ORDER BY start",
                )?;
                let events = stmt
                    .query_map(params![calendar_id.to_string()], |row| {
                        Ok(CalendarEvent {
                            id: row.get::<_, String>(0)?.parse().unwrap_or_else(|_| EventId::new()),
                            calendar_id,
                            title: row.get(2)?,
                            description: row.get(3)?,
                            start: row.get(4)?,
                            end: row.get(5)?,
                            rrule: row.get(6)?,
                            created_at: row.get(7)?,
                            updated_at: row.get(8)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(events)
            })
            .await
    }

    /// Busy intervals across ALL of an account's calendars overlapping
    /// [from, to) — half-open, so an event ending exactly at `from` is not
    /// busy. Recurring events are NOT expanded (no rrule engine exists);
    /// only the stored base occurrence blocks time.
    pub async fn events_overlapping(
        &self,
        account_id: AccountId,
        from: i64,
        to: i64,
    ) -> Result<Vec<(i64, i64)>, StorageError> {
        self.db
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT e.start, e.end FROM calendar_events e
                     JOIN calendars c ON c.id = e.calendar_id
                     WHERE c.account_id = ?1 AND e.start < ?3 AND e.end > ?2
                     ORDER BY e.start",
                )?;
                let rows = stmt
                    .query_map(params![account_id.to_string(), from, to], |row| {
                        Ok((row.get(0)?, row.get(1)?))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await
    }

    /// Update an event.
    pub async fn update_calendar_event(
        &self,
        event_id: EventId,
        title: Option<String>,
        description: Option<String>,
        start: Option<i64>,
        end: Option<i64>,
        rrule: Option<String>,
    ) -> Result<(), StorageError> {
        let now = crate::unix_now();

        self.db
            .call(move |conn| {
                let mut stmt_parts = vec!["updated_at = ?1".to_string()];
                let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(now)];

                if let Some(t) = title {
                    stmt_parts.push(format!("title = ?{}", params_vec.len() + 1));
                    params_vec.push(Box::new(t));
                }
                if let Some(d) = description {
                    stmt_parts.push(format!("description = ?{}", params_vec.len() + 1));
                    params_vec.push(Box::new(d));
                }
                if let Some(s) = start {
                    stmt_parts.push(format!("start = ?{}", params_vec.len() + 1));
                    params_vec.push(Box::new(s));
                }
                if let Some(e) = end {
                    stmt_parts.push(format!("end = ?{}", params_vec.len() + 1));
                    params_vec.push(Box::new(e));
                }
                if let Some(r) = rrule {
                    stmt_parts.push(format!("rrule = ?{}", params_vec.len() + 1));
                    params_vec.push(Box::new(r));
                }

                let sql = format!(
                    "UPDATE calendar_events SET {} WHERE id = ?{}",
                    stmt_parts.join(", "),
                    params_vec.len() + 1
                );
                params_vec.push(Box::new(event_id.to_string()));

                conn.execute(
                    &sql,
                    rusqlite::params_from_iter(params_vec.iter().map(|p| p.as_ref())),
                )?;
                Ok(())
            })
            .await
    }

    /// Delete an event.
    pub async fn delete_calendar_event(&self, event_id: EventId) -> Result<(), StorageError> {
        self.db
            .call(move |conn| {
                conn.execute(
                    "DELETE FROM calendar_events WHERE id = ?1",
                    params![event_id.to_string()],
                )?;
                Ok(())
            })
            .await
    }

    /// Get calendar events modified since timestamp (for federation sync).
    pub async fn list_calendar_events_since(
        &self,
        calendar_id: CalendarId,
        since_timestamp: i64,
    ) -> Result<Vec<CalendarEvent>, StorageError> {
        self.db
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, calendar_id, title, description, start, end, rrule, created_at, updated_at
                     FROM calendar_events WHERE calendar_id = ?1 AND updated_at > ?2 ORDER BY updated_at",
                )?;
                let events = stmt
                    .query_map(params![calendar_id.to_string(), since_timestamp], |row| {
                        Ok(CalendarEvent {
                            id: row.get::<_, String>(0)?.parse().unwrap_or_else(|_| EventId::new()),
                            calendar_id: row.get::<_, String>(1)?.parse().unwrap_or_else(|_| CalendarId::new()),
                            title: row.get(2)?,
                            description: row.get(3)?,
                            start: row.get(4)?,
                            end: row.get(5)?,
                            rrule: row.get(6)?,
                            created_at: row.get(7)?,
                            updated_at: row.get(8)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(events)
            })
            .await
    }

    /// Bounded, keyset-paged listing of events for federated serving. Orders by
    /// `(updated_at, id)` and takes a compound cursor so ties at the page
    /// boundary neither skip nor repeat. When `exclude_remote` is set, events
    /// that were themselves synced in from a peer are omitted — this is what
    /// stops two servers sharing a calendar both ways from echoing events back
    /// and forth.
    pub async fn list_calendar_events_page(
        &self,
        calendar_id: CalendarId,
        after_updated_at: i64,
        after_id: String,
        limit: usize,
        exclude_remote: bool,
    ) -> Result<Vec<CalendarEvent>, StorageError> {
        self.db
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, calendar_id, title, description, start, end, rrule, created_at, updated_at
                     FROM calendar_events
                     WHERE calendar_id = ?1
                       AND (?2 = 0 OR origin IS NULL OR origin != 'remote')
                       AND (updated_at > ?3 OR (updated_at = ?3 AND id > ?4))
                     ORDER BY updated_at, id
                     LIMIT ?5",
                )?;
                let events = stmt
                    .query_map(
                        params![
                            calendar_id.to_string(),
                            exclude_remote as i64,
                            after_updated_at,
                            after_id,
                            limit as i64
                        ],
                        |row| {
                            let id: EventId = row
                                .get::<_, String>(0)?
                                .parse()
                                .map_err(|_| rusqlite::Error::InvalidQuery)?;
                            let calendar_id: CalendarId = row
                                .get::<_, String>(1)?
                                .parse()
                                .map_err(|_| rusqlite::Error::InvalidQuery)?;
                            Ok(CalendarEvent {
                                id,
                                calendar_id,
                                title: row.get(2)?,
                                description: row.get(3)?,
                                start: row.get(4)?,
                                end: row.get(5)?,
                                rrule: row.get(6)?,
                                created_at: row.get(7)?,
                                updated_at: row.get(8)?,
                            })
                        },
                    )?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(events)
            })
            .await
    }

    /// Create an event that originated on a remote server (synced in). Marked
    /// read-only via its `origin`, and excluded from re-serving. Returns the
    /// local, server-minted event id — the remote id is never used as our key.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_remote_calendar_event(
        &self,
        calendar_id: CalendarId,
        federation_id: &str,
        title: String,
        description: Option<String>,
        start: i64,
        end: i64,
        rrule: Option<String>,
    ) -> Result<EventId, StorageError> {
        let event_id = EventId::new();
        let out = event_id;
        let federation_id = federation_id.to_owned();
        self.db
            .call(move |conn| {
                let now = crate::unix_now();
                conn.execute(
                    "INSERT INTO calendar_events
                       (id, calendar_id, title, description, start, end, rrule,
                        created_at, updated_at, origin, origin_federation)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, 'remote', ?9)",
                    params![
                        event_id.to_string(),
                        calendar_id.to_string(),
                        title,
                        description,
                        start,
                        end,
                        rrule,
                        now,
                        federation_id,
                    ],
                )?;
                Ok(out)
            })
            .await
    }

    /// Update a remote-origin event in place (keeps its local id and origin).
    pub async fn update_remote_calendar_event(
        &self,
        event_id: EventId,
        title: String,
        description: Option<String>,
        start: i64,
        end: i64,
        rrule: Option<String>,
    ) -> Result<(), StorageError> {
        self.db
            .call(move |conn| {
                conn.execute(
                    "UPDATE calendar_events
                     SET title = ?2, description = ?3, start = ?4, end = ?5, rrule = ?6,
                         updated_at = ?7
                     WHERE id = ?1 AND origin = 'remote'",
                    params![
                        event_id.to_string(),
                        title,
                        description,
                        start,
                        end,
                        rrule,
                        crate::unix_now()
                    ],
                )?;
                Ok(())
            })
            .await
    }

    /// Get specific calendar events by ID (for sync).
    pub async fn get_calendar_events_by_ids(
        &self,
        calendar_id: CalendarId,
        event_ids: Vec<EventId>,
    ) -> Result<Vec<CalendarEvent>, StorageError> {
        if event_ids.is_empty() {
            return Ok(Vec::new());
        }

        self.db
            .call(move |conn| {
                let placeholders = event_ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
                let query = format!(
                    "SELECT id, calendar_id, title, description, start, end, rrule, created_at, updated_at
                     FROM calendar_events WHERE calendar_id = ? AND id IN ({})",
                    placeholders
                );

                let mut stmt = conn.prepare(&query)?;
                let calendar_id_str = calendar_id.to_string();
                let event_id_strs: Vec<String> = event_ids.iter().map(|id| id.to_string()).collect();
                let mut params: Vec<&dyn rusqlite::ToSql> = vec![&calendar_id_str];
                for id in &event_id_strs {
                    params.push(id);
                }

                let events = stmt
                    .query_map(params.as_slice(), |row| {
                        Ok(CalendarEvent {
                            id: row.get::<_, String>(0)?.parse().unwrap_or_else(|_| EventId::new()),
                            calendar_id: row.get::<_, String>(1)?.parse().unwrap_or_else(|_| CalendarId::new()),
                            title: row.get(2)?,
                            description: row.get(3)?,
                            start: row.get(4)?,
                            end: row.get(5)?,
                            rrule: row.get(6)?,
                            created_at: row.get(7)?,
                            updated_at: row.get(8)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(events)
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    #[allow(dead_code)]
    async fn harness(tmp: &tempfile::TempDir) -> (crate::Storage, owney_events::EventBus) {
        crate::tests::open(tmp.path()).await
    }

    #[tokio::test]
    async fn create_and_list_calendars() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _events) = harness(&dir).await;
        let acct = storage
            .create_account("alice@example.com", None)
            .await
            .expect("create account");

        let cal = storage
            .create_calendar(acct.id, "Personal".to_string(), None)
            .await
            .expect("create calendar");

        assert_eq!(cal.name, "Personal");

        let calendars = storage
            .list_calendars(acct.id)
            .await
            .expect("list calendars");
        assert_eq!(calendars.len(), 1);
        assert_eq!(calendars[0].id, cal.id);

        storage.close();
    }

    #[tokio::test]
    async fn create_and_fetch_event() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _events) = harness(&dir).await;
        let acct = storage
            .create_account("alice@example.com", None)
            .await
            .expect("create account");

        let cal = storage
            .create_calendar(acct.id, "Work".to_string(), None)
            .await
            .expect("create calendar");

        let now = crate::unix_now();
        let event = storage
            .create_calendar_event(
                cal.id,
                "Team Meeting".to_string(),
                None,
                now + 3600,
                now + 7200,
                None,
            )
            .await
            .expect("create event");

        let fetched = storage
            .get_calendar_event(event.id)
            .await
            .expect("fetch")
            .expect("found");
        assert_eq!(fetched.title, "Team Meeting");
        assert_eq!(fetched.start, now + 3600);

        storage.close();
    }

    #[tokio::test]
    async fn recurring_event() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _events) = harness(&dir).await;
        let acct = storage
            .create_account("alice@example.com", None)
            .await
            .expect("create account");

        let cal = storage
            .create_calendar(acct.id, "Personal".to_string(), None)
            .await
            .expect("create calendar");

        let now = crate::unix_now();
        let event = storage
            .create_calendar_event(
                cal.id,
                "Weekly Standup".to_string(),
                Some("Every Monday at 9am".to_string()),
                now + 3600,
                now + 5400,
                Some("FREQ=WEEKLY;BYDAY=MO".to_string()),
            )
            .await
            .expect("create event");

        let fetched = storage
            .get_calendar_event(event.id)
            .await
            .expect("fetch")
            .expect("found");
        assert_eq!(fetched.rrule, Some("FREQ=WEEKLY;BYDAY=MO".to_string()));

        storage.close();
    }
}
