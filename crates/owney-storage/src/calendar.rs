//! Calendar storage: calendars and events with recurring event support.
//!
//! Schema:
//! - calendars: user's calendar collections (e.g., "Personal", "Work")
//! - calendar_events: events with optional recurrence rules (RFC 5545 subset)
//!
//! Recurring events are expanded on-demand when fetched; storage holds the
//! base event and rrule string.

use owney_core::{AccountId, CalendarId, EventId};
use rusqlite::{params, OptionalExtension};

use crate::error::StorageError;
use crate::Storage;

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
    pub start: i64, // unix timestamp
    pub end: i64,   // unix timestamp
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
                                id: row.get::<_, String>(0)?.parse().unwrap_or_else(|_| CalendarId::new()),
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

    /// List all calendars for an account.
    pub async fn list_calendars(&self, account_id: AccountId) -> Result<Vec<Calendar>, StorageError> {
        self.db
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, account_id, name, description, created_at, updated_at
                     FROM calendars WHERE account_id = ?1 ORDER BY created_at",
                )?;
                let calendars = stmt
                    .query_map(params![account_id.to_string()], |row| {
                        Ok(Calendar {
                            id: row.get::<_, String>(0)?.parse().unwrap_or_else(|_| CalendarId::new()),
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
    pub async fn get_calendar_event(&self, event_id: EventId) -> Result<Option<CalendarEvent>, StorageError> {
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
    pub async fn list_calendar_events(&self, calendar_id: CalendarId) -> Result<Vec<CalendarEvent>, StorageError> {
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
                conn.execute("DELETE FROM calendar_events WHERE id = ?1", params![event_id.to_string()])?;
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
                let mut params: Vec<&dyn rusqlite::ToSql> = vec![&calendar_id.to_string()];
                for id in &event_ids {
                    params.push(&id.to_string());
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
    use super::Storage;

    #[allow(dead_code)]
    async fn harness(tmp: &tempfile::TempDir) -> (crate::Storage, owney_events::EventBus) {
        crate::tests::open(tmp.path()).await
    }

    #[tokio::test]
    async fn create_and_list_calendars() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _events) = harness(&dir).await;
        let acct = storage.create_account("alice@example.com", None).await.expect("create account");

        let cal = storage
            .create_calendar(acct.id, "Personal".to_string(), None)
            .await
            .expect("create calendar");

        assert_eq!(cal.name, "Personal");

        let calendars = storage.list_calendars(acct.id).await.expect("list calendars");
        assert_eq!(calendars.len(), 1);
        assert_eq!(calendars[0].id, cal.id);

        storage.close();
    }

    #[tokio::test]
    async fn create_and_fetch_event() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _events) = harness(&dir).await;
        let acct = storage.create_account("alice@example.com", None).await.expect("create account");

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

        let fetched = storage.get_calendar_event(event.id).await.expect("fetch").expect("found");
        assert_eq!(fetched.title, "Team Meeting");
        assert_eq!(fetched.start, now + 3600);

        storage.close();
    }

    #[tokio::test]
    async fn recurring_event() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _events) = harness(&dir).await;
        let acct = storage.create_account("alice@example.com", None).await.expect("create account");

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

        let fetched = storage.get_calendar_event(event.id).await.expect("fetch").expect("found");
        assert_eq!(fetched.rrule, Some("FREQ=WEEKLY;BYDAY=MO".to_string()));

        storage.close();
    }
}
