//! Public scheduling pages ("book a meeting with me") and their bookings.
//!
//! The availability model is a versioned JSON document stored on the page:
//! weekly per-weekday windows plus per-date overrides, expressed as wall-clock
//! times in the page's IANA timezone. Slot expansion lives in owney-api; this
//! module owns validation, CRUD, and the atomic booking transaction.
//!
//! Double-booking safety: `book_slot` re-checks conflicts and inserts the
//! calendar event + booking inside ONE closure on the single SQLite writer
//! thread, so two concurrent bookings for the same slot serialize and the
//! loser gets `StorageError::Conflict`.

use std::collections::BTreeMap;

use owney_core::{AccountId, BookingId, CalendarId, EventId, SchedulingPageId};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::StorageError;
use crate::{Storage, unix_now};

pub const WEEKDAY_KEYS: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

/// One wall-clock window within a day, `"HH:MM".."HH:MM"` (24h).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeWindow {
    pub start: String,
    pub end: String,
}

impl TimeWindow {
    /// Minutes since local midnight for (start, end); `BadInput` on bad format.
    pub fn parse_minutes(&self) -> Result<(u32, u32), StorageError> {
        let parse = |value: &str| -> Result<u32, StorageError> {
            let (h, m) = value
                .split_once(':')
                .ok_or_else(|| StorageError::BadInput(format!("bad time {value:?}")))?;
            let (h, m): (u32, u32) = match (h.parse(), m.parse()) {
                (Ok(h), Ok(m)) if h < 24 && m < 60 && h < 100 => (h, m),
                _ => return Err(StorageError::BadInput(format!("bad time {value:?}"))),
            };
            Ok(h * 60 + m)
        };
        Ok((parse(&self.start)?, parse(&self.end)?))
    }
}

/// The versioned availability document. Times are wall-clock in the page's
/// timezone. An absent weekday key means the day is unavailable; an override
/// replaces that date's windows entirely (`[]` blocks the date).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Availability {
    pub version: u32,
    #[serde(default)]
    pub weekly: BTreeMap<String, Vec<TimeWindow>>,
    /// Keys are `YYYY-MM-DD` dates in the page timezone.
    #[serde(default)]
    pub overrides: BTreeMap<String, Vec<TimeWindow>>,
}

impl Availability {
    /// Mon-Fri 09:00-17:00 — the default when an owner doesn't specify.
    /// Weekends are supported but excluded unless the owner adds windows.
    pub fn default_business_hours() -> Self {
        let window = vec![TimeWindow {
            start: "09:00".into(),
            end: "17:00".into(),
        }];
        let weekly = ["mon", "tue", "wed", "thu", "fri"]
            .into_iter()
            .map(|day| (day.to_string(), window.clone()))
            .collect();
        Self {
            version: 1,
            weekly,
            overrides: BTreeMap::new(),
        }
    }

    pub fn validate(&self) -> Result<(), StorageError> {
        if self.version != 1 {
            return Err(StorageError::BadInput(format!(
                "unsupported availability version {}",
                self.version
            )));
        }
        for day in self.weekly.keys() {
            if !WEEKDAY_KEYS.contains(&day.as_str()) {
                return Err(StorageError::BadInput(format!("unknown weekday {day:?}")));
            }
        }
        for date in self.overrides.keys() {
            if parse_date(date).is_none() {
                return Err(StorageError::BadInput(format!(
                    "bad override date {date:?} (want YYYY-MM-DD)"
                )));
            }
        }
        for windows in self.weekly.values().chain(self.overrides.values()) {
            let mut previous_end = 0u32;
            for window in windows {
                let (start, end) = window.parse_minutes()?;
                if start >= end {
                    return Err(StorageError::BadInput(format!(
                        "window {}-{} is empty or reversed",
                        window.start, window.end
                    )));
                }
                if start < previous_end {
                    return Err(StorageError::BadInput(
                        "windows must be sorted and non-overlapping".into(),
                    ));
                }
                previous_end = end;
            }
        }
        Ok(())
    }
}

/// `YYYY-MM-DD` → (year, month, day) with range checks; None on garbage.
pub fn parse_date(value: &str) -> Option<(i32, u32, u32)> {
    let bytes = value.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    let year: i32 = value[..4].parse().ok()?;
    let month: u32 = value[5..7].parse().ok()?;
    let day: u32 = value[8..10].parse().ok()?;
    ((1..=12).contains(&month) && (1..=31).contains(&day)).then_some((year, month, day))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageStatus {
    Active,
    Paused,
}

impl PageStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            PageStatus::Active => "active",
            PageStatus::Paused => "paused",
        }
    }

    pub fn parse(value: &str) -> Result<Self, StorageError> {
        match value {
            "active" => Ok(PageStatus::Active),
            "paused" => Ok(PageStatus::Paused),
            other => Err(StorageError::Corrupt(format!("bad page status {other:?}"))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SchedulingPage {
    pub id: SchedulingPageId,
    pub account_id: AccountId,
    pub slug: String,
    pub title: String,
    pub description: Option<String>,
    pub calendar_id: CalendarId,
    pub timezone: String,
    pub availability: Availability,
    pub durations_mins: Vec<u32>,
    pub buffer_before_mins: u32,
    pub buffer_after_mins: u32,
    pub min_notice_mins: u32,
    pub max_per_day: Option<u32>,
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
    pub status: PageStatus,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Creation input; `create_scheduling_page` owns all validation so every
/// caller (JMAP, CLI) gets the same rules.
#[derive(Debug, Clone)]
pub struct NewSchedulingPage {
    pub slug: String,
    pub title: String,
    pub description: Option<String>,
    pub calendar_id: CalendarId,
    pub timezone: String,
    pub availability: Availability,
    pub durations_mins: Vec<u32>,
    pub buffer_before_mins: u32,
    pub buffer_after_mins: u32,
    pub min_notice_mins: u32,
    pub max_per_day: Option<u32>,
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
}

/// Partial update; `None` fields are left unchanged.
#[derive(Debug, Clone, Default)]
pub struct SchedulingPagePatch {
    pub title: Option<String>,
    pub description: Option<Option<String>>,
    pub timezone: Option<String>,
    pub availability: Option<Availability>,
    pub durations_mins: Option<Vec<u32>>,
    pub buffer_before_mins: Option<u32>,
    pub buffer_after_mins: Option<u32>,
    pub min_notice_mins: Option<u32>,
    pub max_per_day: Option<Option<u32>>,
    pub valid_from: Option<Option<String>>,
    pub valid_until: Option<Option<String>>,
    pub status: Option<PageStatus>,
}

#[derive(Debug, Clone)]
pub struct Booking {
    pub id: BookingId,
    pub page_id: SchedulingPageId,
    pub account_id: AccountId,
    pub event_id: EventId,
    pub visitor_name: String,
    pub visitor_email: String,
    pub note: Option<String>,
    pub start: i64,
    pub end: i64,
    pub status: String,
    pub created_at: i64,
}

/// Everything `book_slot` needs; the caller (HTTP handler) has already
/// validated the slot against the availability rules — this transaction only
/// guards CONFLICTS (busy calendar, concurrent booking, day quota, pause).
#[derive(Debug, Clone)]
pub struct BookSlotRequest {
    pub page_id: SchedulingPageId,
    pub visitor_name: String,
    pub visitor_email: String,
    pub note: Option<String>,
    pub start: i64,
    pub end: i64,
    /// Buffer-widened busy interval this booking occupies.
    pub busy_from: i64,
    pub busy_to: i64,
    pub event_title: String,
    pub event_description: Option<String>,
    /// UTC bounds (half-open) of the page-timezone local day, for max_per_day.
    pub day_bounds: (i64, i64),
}

fn validate_slug(slug: &str) -> Result<(), StorageError> {
    let ok_len = (2..=64).contains(&slug.len());
    let ok_chars = slug
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if !ok_len || !ok_chars || slug.starts_with('-') || slug.ends_with('-') {
        return Err(StorageError::BadInput(format!(
            "slug {slug:?} must be 2-64 chars of [a-z0-9-], not edged with '-'"
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_common(
    timezone: &str,
    availability: &Availability,
    durations: &[u32],
    buffer_before: u32,
    buffer_after: u32,
    min_notice: u32,
    valid_from: Option<&str>,
    valid_until: Option<&str>,
) -> Result<(), StorageError> {
    if timezone.parse::<chrono_tz::Tz>().is_err() {
        return Err(StorageError::BadInput(format!(
            "unknown IANA timezone {timezone:?}"
        )));
    }
    availability.validate()?;
    if durations.is_empty() || durations.iter().any(|d| !(5..=480).contains(d)) {
        return Err(StorageError::BadInput(
            "durations must be 1+ values between 5 and 480 minutes".into(),
        ));
    }
    if buffer_before > 24 * 60 || buffer_after > 24 * 60 || min_notice > 90 * 24 * 60 {
        return Err(StorageError::BadInput(
            "buffers must be <= 24h and notice <= 90 days".into(),
        ));
    }
    for date in [valid_from, valid_until].into_iter().flatten() {
        if parse_date(date).is_none() {
            return Err(StorageError::BadInput(format!(
                "bad date {date:?} (want YYYY-MM-DD)"
            )));
        }
    }
    if let (Some(from), Some(until)) = (valid_from, valid_until)
        && from > until
    {
        return Err(StorageError::BadInput(
            "validFrom must not be after validUntil".into(),
        ));
    }
    Ok(())
}

fn row_to_page(row: &rusqlite::Row<'_>) -> Result<SchedulingPage, rusqlite::Error> {
    let corrupt = |i: usize, err: String| {
        rusqlite::Error::FromSqlConversionFailure(
            i,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, err)),
        )
    };
    let id: String = row.get(0)?;
    let account_id: String = row.get(1)?;
    let calendar_id: String = row.get(5)?;
    let availability: String = row.get(7)?;
    let durations: String = row.get(8)?;
    let status: String = row.get(15)?;
    Ok(SchedulingPage {
        id: id.parse().map_err(|e| corrupt(0, format!("{e}")))?,
        account_id: account_id.parse().map_err(|e| corrupt(1, format!("{e}")))?,
        slug: row.get(2)?,
        title: row.get(3)?,
        description: row.get(4)?,
        calendar_id: calendar_id
            .parse()
            .map_err(|e| corrupt(5, format!("{e}")))?,
        timezone: row.get(6)?,
        availability: serde_json::from_str(&availability)
            .map_err(|e| corrupt(7, format!("{e}")))?,
        durations_mins: serde_json::from_str(&durations).map_err(|e| corrupt(8, format!("{e}")))?,
        buffer_before_mins: row.get::<_, i64>(9)? as u32,
        buffer_after_mins: row.get::<_, i64>(10)? as u32,
        min_notice_mins: row.get::<_, i64>(11)? as u32,
        max_per_day: row.get::<_, Option<i64>>(12)?.map(|v| v as u32),
        valid_from: row.get(13)?,
        valid_until: row.get(14)?,
        status: PageStatus::parse(&status).map_err(|e| corrupt(15, format!("{e}")))?,
        created_at: row.get(16)?,
        updated_at: row.get(17)?,
    })
}

const PAGE_COLUMNS: &str = "id, account_id, slug, title, description, calendar_id, timezone, \
     availability, durations_mins, buffer_before_mins, buffer_after_mins, min_notice_mins, \
     max_per_day, valid_from, valid_until, status, created_at, updated_at";

fn row_to_booking(row: &rusqlite::Row<'_>) -> Result<Booking, rusqlite::Error> {
    let corrupt = |i: usize, err: String| {
        rusqlite::Error::FromSqlConversionFailure(
            i,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, err)),
        )
    };
    let id: String = row.get(0)?;
    let page_id: String = row.get(1)?;
    let account_id: String = row.get(2)?;
    let event_id: String = row.get(3)?;
    Ok(Booking {
        id: id.parse().map_err(|e| corrupt(0, format!("{e}")))?,
        page_id: page_id.parse().map_err(|e| corrupt(1, format!("{e}")))?,
        account_id: account_id.parse().map_err(|e| corrupt(2, format!("{e}")))?,
        event_id: event_id.parse().map_err(|e| corrupt(3, format!("{e}")))?,
        visitor_name: row.get(4)?,
        visitor_email: row.get(5)?,
        note: row.get(6)?,
        start: row.get(7)?,
        end: row.get(8)?,
        status: row.get(9)?,
        created_at: row.get(10)?,
    })
}

const BOOKING_COLUMNS: &str = "id, page_id, account_id, event_id, visitor_name, visitor_email, \
     note, start, end, status, created_at";

impl Storage {
    pub async fn create_scheduling_page(
        &self,
        account_id: AccountId,
        new: NewSchedulingPage,
    ) -> Result<SchedulingPage, StorageError> {
        validate_slug(&new.slug)?;
        validate_common(
            &new.timezone,
            &new.availability,
            &new.durations_mins,
            new.buffer_before_mins,
            new.buffer_after_mins,
            new.min_notice_mins,
            new.valid_from.as_deref(),
            new.valid_until.as_deref(),
        )?;
        if new.title.is_empty() || new.title.len() > 200 {
            return Err(StorageError::BadInput("title must be 1-200 chars".into()));
        }

        let id = SchedulingPageId::new();
        self.db
            .call(move |conn| {
                let tx = conn.transaction()?;
                // The target calendar must belong to the page owner.
                let owns: bool = tx
                    .query_row(
                        "SELECT 1 FROM calendars WHERE id = ?1 AND account_id = ?2",
                        params![new.calendar_id.to_string(), account_id.to_string()],
                        |_| Ok(true),
                    )
                    .optional()?
                    .unwrap_or(false);
                if !owns {
                    return Err(StorageError::NotAuthorized);
                }

                let now = unix_now();
                let inserted = tx.execute(
                    "INSERT INTO scheduling_pages
                       (id, account_id, slug, title, description, calendar_id, timezone,
                        availability, durations_mins, buffer_before_mins, buffer_after_mins,
                        min_notice_mins, max_per_day, valid_from, valid_until, status,
                        created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                             'active', ?16, ?16)
                     ON CONFLICT (slug) DO NOTHING",
                    params![
                        id.to_string(),
                        account_id.to_string(),
                        new.slug,
                        new.title,
                        new.description,
                        new.calendar_id.to_string(),
                        new.timezone,
                        serde_json::to_string(&new.availability)
                            .map_err(|e| StorageError::BadInput(e.to_string()))?,
                        serde_json::to_string(&new.durations_mins)
                            .map_err(|e| StorageError::BadInput(e.to_string()))?,
                        new.buffer_before_mins as i64,
                        new.buffer_after_mins as i64,
                        new.min_notice_mins as i64,
                        new.max_per_day.map(|v| v as i64),
                        new.valid_from,
                        new.valid_until,
                        now,
                    ],
                )?;
                if inserted == 0 {
                    return Err(StorageError::BadInput(format!(
                        "slug {:?} is already in use",
                        new.slug
                    )));
                }
                let page = tx.query_row(
                    &format!("SELECT {PAGE_COLUMNS} FROM scheduling_pages WHERE id = ?1"),
                    [id.to_string()],
                    row_to_page,
                )?;
                tx.commit()?;
                Ok(page)
            })
            .await
    }

    pub async fn update_scheduling_page(
        &self,
        account_id: AccountId,
        page_id: SchedulingPageId,
        patch: SchedulingPagePatch,
    ) -> Result<SchedulingPage, StorageError> {
        self.db
            .call(move |conn| {
                let tx = conn.transaction()?;
                let current = tx
                    .query_row(
                        &format!(
                            "SELECT {PAGE_COLUMNS} FROM scheduling_pages
                             WHERE id = ?1 AND account_id = ?2"
                        ),
                        params![page_id.to_string(), account_id.to_string()],
                        row_to_page,
                    )
                    .optional()?
                    .ok_or(StorageError::NotAuthorized)?;

                let title = patch.title.unwrap_or(current.title);
                let description = patch.description.unwrap_or(current.description);
                let timezone = patch.timezone.unwrap_or(current.timezone);
                let availability = patch.availability.unwrap_or(current.availability);
                let durations = patch.durations_mins.unwrap_or(current.durations_mins);
                let buffer_before = patch
                    .buffer_before_mins
                    .unwrap_or(current.buffer_before_mins);
                let buffer_after = patch.buffer_after_mins.unwrap_or(current.buffer_after_mins);
                let min_notice = patch.min_notice_mins.unwrap_or(current.min_notice_mins);
                let max_per_day = patch.max_per_day.unwrap_or(current.max_per_day);
                let valid_from = patch.valid_from.unwrap_or(current.valid_from);
                let valid_until = patch.valid_until.unwrap_or(current.valid_until);
                let status = patch.status.unwrap_or(current.status);

                if title.is_empty() || title.len() > 200 {
                    return Err(StorageError::BadInput("title must be 1-200 chars".into()));
                }
                validate_common(
                    &timezone,
                    &availability,
                    &durations,
                    buffer_before,
                    buffer_after,
                    min_notice,
                    valid_from.as_deref(),
                    valid_until.as_deref(),
                )?;

                tx.execute(
                    "UPDATE scheduling_pages SET
                       title = ?2, description = ?3, timezone = ?4, availability = ?5,
                       durations_mins = ?6, buffer_before_mins = ?7, buffer_after_mins = ?8,
                       min_notice_mins = ?9, max_per_day = ?10, valid_from = ?11,
                       valid_until = ?12, status = ?13, updated_at = ?14
                     WHERE id = ?1",
                    params![
                        page_id.to_string(),
                        title,
                        description,
                        timezone,
                        serde_json::to_string(&availability)
                            .map_err(|e| StorageError::BadInput(e.to_string()))?,
                        serde_json::to_string(&durations)
                            .map_err(|e| StorageError::BadInput(e.to_string()))?,
                        buffer_before as i64,
                        buffer_after as i64,
                        min_notice as i64,
                        max_per_day.map(|v| v as i64),
                        valid_from,
                        valid_until,
                        status.as_str(),
                        unix_now(),
                    ],
                )?;
                let page = tx.query_row(
                    &format!("SELECT {PAGE_COLUMNS} FROM scheduling_pages WHERE id = ?1"),
                    [page_id.to_string()],
                    row_to_page,
                )?;
                tx.commit()?;
                Ok(page)
            })
            .await
    }

    /// Ownership-scoped fetch (owner surfaces).
    pub async fn get_scheduling_page(
        &self,
        account_id: AccountId,
        page_id: SchedulingPageId,
    ) -> Result<Option<SchedulingPage>, StorageError> {
        self.db
            .call(move |conn| {
                Ok(conn
                    .query_row(
                        &format!(
                            "SELECT {PAGE_COLUMNS} FROM scheduling_pages
                             WHERE id = ?1 AND account_id = ?2"
                        ),
                        params![page_id.to_string(), account_id.to_string()],
                        row_to_page,
                    )
                    .optional()?)
            })
            .await
    }

    /// Public lookup by slug (the booking page). Returns paused pages too —
    /// the HTTP layer decides how to present them (uniform 404).
    pub async fn get_scheduling_page_by_slug(
        &self,
        slug: &str,
    ) -> Result<Option<SchedulingPage>, StorageError> {
        let slug = slug.to_owned();
        self.db
            .call(move |conn| {
                Ok(conn
                    .query_row(
                        &format!("SELECT {PAGE_COLUMNS} FROM scheduling_pages WHERE slug = ?1"),
                        [slug],
                        row_to_page,
                    )
                    .optional()?)
            })
            .await
    }

    pub async fn list_scheduling_pages(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<SchedulingPage>, StorageError> {
        self.db
            .call(move |conn| {
                let mut stmt = conn.prepare(&format!(
                    "SELECT {PAGE_COLUMNS} FROM scheduling_pages
                     WHERE account_id = ?1 ORDER BY created_at"
                ))?;
                let rows = stmt
                    .query_map([account_id.to_string()], row_to_page)?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await
    }

    pub async fn list_bookings(
        &self,
        account_id: AccountId,
        page_id: Option<SchedulingPageId>,
    ) -> Result<Vec<Booking>, StorageError> {
        self.db
            .call(move |conn| {
                let rows = match page_id {
                    Some(page_id) => {
                        let mut stmt = conn.prepare(&format!(
                            "SELECT {BOOKING_COLUMNS} FROM bookings
                             WHERE account_id = ?1 AND page_id = ?2 ORDER BY start"
                        ))?;
                        stmt.query_map(
                            params![account_id.to_string(), page_id.to_string()],
                            row_to_booking,
                        )?
                        .collect::<Result<Vec<_>, _>>()?
                    }
                    None => {
                        let mut stmt = conn.prepare(&format!(
                            "SELECT {BOOKING_COLUMNS} FROM bookings
                             WHERE account_id = ?1 ORDER BY start"
                        ))?;
                        stmt.query_map([account_id.to_string()], row_to_booking)?
                            .collect::<Result<Vec<_>, _>>()?
                    }
                };
                Ok(rows)
            })
            .await
    }

    /// Confirmed bookings whose start falls in [from, to) — used for the
    /// max-per-day counts when computing slots.
    pub async fn list_confirmed_bookings_in_range(
        &self,
        page_id: SchedulingPageId,
        from: i64,
        to: i64,
    ) -> Result<Vec<Booking>, StorageError> {
        self.db
            .call(move |conn| {
                let mut stmt = conn.prepare(&format!(
                    "SELECT {BOOKING_COLUMNS} FROM bookings
                     WHERE page_id = ?1 AND status = 'confirmed'
                       AND start >= ?2 AND start < ?3
                     ORDER BY start"
                ))?;
                let rows = stmt
                    .query_map(params![page_id.to_string(), from, to], row_to_booking)?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await
    }

    /// Book one slot atomically: conflict re-checks + calendar-event insert +
    /// booking insert run in a single transaction on the writer thread. A
    /// concurrent booking of the same slot gets `Conflict`.
    pub async fn book_slot(&self, req: BookSlotRequest) -> Result<Booking, StorageError> {
        if req.end <= req.start {
            return Err(StorageError::BadInput("slot must end after start".into()));
        }
        self.db
            .call(move |conn| {
                let tx = conn.transaction()?;

                // 1. The page must still exist and be active (a pause racing
                //    the booking loses).
                let (account_id, calendar_id, max_per_day): (String, String, Option<i64>) = tx
                    .query_row(
                        "SELECT account_id, calendar_id, max_per_day FROM scheduling_pages
                         WHERE id = ?1 AND status = 'active'",
                        [req.page_id.to_string()],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .optional()?
                    .ok_or_else(|| StorageError::Conflict("page unavailable".into()))?;

                // 2. Busy check against ALL the owner's calendar events.
                let busy: bool = tx.query_row(
                    "SELECT EXISTS(
                           SELECT 1 FROM calendar_events e
                           JOIN calendars c ON c.id = e.calendar_id
                           WHERE c.account_id = ?1 AND e.start < ?3 AND e.end > ?2)",
                    params![account_id, req.busy_from, req.busy_to],
                    |row| row.get(0),
                )?;
                if busy {
                    return Err(StorageError::Conflict("slot no longer available".into()));
                }

                // 3. Belt-and-braces against confirmed bookings (covers any
                //    future status whose event row might be absent).
                let double: bool = tx.query_row(
                    "SELECT EXISTS(
                       SELECT 1 FROM bookings
                       WHERE account_id = ?1 AND status = 'confirmed'
                         AND start < ?3 AND end > ?2)",
                    params![account_id, req.busy_from, req.busy_to],
                    |row| row.get(0),
                )?;
                if double {
                    return Err(StorageError::Conflict("slot no longer available".into()));
                }

                // 4. Day quota.
                if let Some(limit) = max_per_day {
                    let (day_lo, day_hi) = req.day_bounds;
                    let count: i64 = tx.query_row(
                        "SELECT count(*) FROM bookings
                         WHERE page_id = ?1 AND status = 'confirmed'
                           AND start >= ?2 AND start < ?3",
                        params![req.page_id.to_string(), day_lo, day_hi],
                        |row| row.get(0),
                    )?;
                    if count >= limit {
                        return Err(StorageError::Conflict("no more bookings that day".into()));
                    }
                }

                // 5+6. Calendar event + booking, same transaction.
                let now = unix_now();
                let event_id = EventId::new();
                tx.execute(
                    "INSERT INTO calendar_events
                       (id, calendar_id, title, description, start, end, rrule,
                        created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, ?7)",
                    params![
                        event_id.to_string(),
                        calendar_id,
                        req.event_title,
                        req.event_description,
                        req.start,
                        req.end,
                        now,
                    ],
                )?;
                let booking_id = BookingId::new();
                tx.execute(
                    "INSERT INTO bookings
                       (id, page_id, account_id, event_id, visitor_name, visitor_email,
                        note, start, end, status, cancel_token, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'confirmed', ?10, ?11)",
                    params![
                        booking_id.to_string(),
                        req.page_id.to_string(),
                        account_id,
                        event_id.to_string(),
                        req.visitor_name,
                        req.visitor_email,
                        req.note,
                        req.start,
                        req.end,
                        Uuid::new_v4().simple().to_string(),
                        now,
                    ],
                )?;
                let booking = tx.query_row(
                    &format!("SELECT {BOOKING_COLUMNS} FROM bookings WHERE id = ?1"),
                    [booking_id.to_string()],
                    row_to_booking,
                )?;
                tx.commit()?;
                Ok(booking)
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use owney_core::CalendarId;

    use super::*;
    use crate::tests::open;

    async fn harness() -> (
        tempfile::TempDir,
        Storage,
        AccountId,
        CalendarId,
        SchedulingPage,
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let (storage, _events) = open(dir.path()).await;
        let account = storage
            .create_account("alice@example.com", None)
            .await
            .expect("account");
        let calendar = storage
            .create_calendar(account.id, "Personal".into(), None)
            .await
            .expect("calendar");
        let page = storage
            .create_scheduling_page(account.id, new_page("meet-alice", calendar.id))
            .await
            .expect("page");
        (dir, storage, account.id, calendar.id, page)
    }

    fn new_page(slug: &str, calendar_id: CalendarId) -> NewSchedulingPage {
        NewSchedulingPage {
            slug: slug.into(),
            title: "Meet with Alice".into(),
            description: None,
            calendar_id,
            timezone: "America/Denver".into(),
            availability: Availability::default_business_hours(),
            durations_mins: vec![30],
            buffer_before_mins: 0,
            buffer_after_mins: 0,
            min_notice_mins: 0,
            max_per_day: None,
            valid_from: None,
            valid_until: None,
        }
    }

    fn book_req(page: &SchedulingPage, start: i64, end: i64) -> BookSlotRequest {
        BookSlotRequest {
            page_id: page.id,
            visitor_name: "Bob".into(),
            visitor_email: "bob@remote.test".into(),
            note: None,
            start,
            end,
            busy_from: start,
            busy_to: end,
            event_title: "Meeting: Bob & Alice".into(),
            event_description: None,
            day_bounds: (
                start - start.rem_euclid(86_400),
                start - start.rem_euclid(86_400) + 86_400,
            ),
        }
    }

    #[tokio::test]
    async fn page_roundtrip_and_slug_rules() {
        let (_dir, storage, account, calendar, page) = harness().await;

        assert_eq!(page.slug, "meet-alice");
        assert_eq!(page.status, PageStatus::Active);
        assert_eq!(page.availability.weekly.len(), 5, "Mon-Fri default");
        assert!(!page.availability.weekly.contains_key("sat"));

        let fetched = storage
            .get_scheduling_page_by_slug("meet-alice")
            .await
            .expect("by slug")
            .expect("exists");
        assert_eq!(fetched.id, page.id);

        // Duplicate slug rejected.
        assert!(matches!(
            storage
                .create_scheduling_page(account, new_page("meet-alice", calendar))
                .await,
            Err(StorageError::BadInput(_))
        ));
        // Bad slugs rejected.
        for bad in ["A", "has space", "-edge", "edge-", "x"] {
            assert!(
                matches!(
                    storage
                        .create_scheduling_page(account, new_page(bad, calendar))
                        .await,
                    Err(StorageError::BadInput(_))
                ),
                "slug {bad:?} should be rejected"
            );
        }
        storage.close();
    }

    #[tokio::test]
    async fn validation_rejects_bad_tz_and_availability() {
        let (_dir, storage, account, calendar, _page) = harness().await;

        let mut bad_tz = new_page("bad-tz", calendar);
        bad_tz.timezone = "Mars/Olympus".into();
        assert!(matches!(
            storage.create_scheduling_page(account, bad_tz).await,
            Err(StorageError::BadInput(_))
        ));

        let mut reversed = new_page("reversed", calendar);
        reversed.availability.weekly.insert(
            "sat".into(),
            vec![TimeWindow {
                start: "17:00".into(),
                end: "09:00".into(),
            }],
        );
        assert!(matches!(
            storage.create_scheduling_page(account, reversed).await,
            Err(StorageError::BadInput(_))
        ));

        let mut overlapping = new_page("overlapping", calendar);
        overlapping.availability.weekly.insert(
            "mon".into(),
            vec![
                TimeWindow {
                    start: "09:00".into(),
                    end: "12:00".into(),
                },
                TimeWindow {
                    start: "11:00".into(),
                    end: "13:00".into(),
                },
            ],
        );
        assert!(matches!(
            storage.create_scheduling_page(account, overlapping).await,
            Err(StorageError::BadInput(_))
        ));

        // Unknown JSON field is rejected at parse time.
        assert!(
            serde_json::from_str::<Availability>(r#"{"version":1,"weekly":{},"bogus":true}"#)
                .is_err()
        );
        storage.close();
    }

    #[tokio::test]
    async fn cross_account_authz() {
        let (_dir, storage, _alice, alice_calendar, page) = harness().await;
        let mallory = storage
            .create_account("mallory@example.com", None)
            .await
            .expect("account")
            .id;

        // Mallory cannot create a page on alice's calendar.
        assert!(matches!(
            storage
                .create_scheduling_page(mallory, new_page("mallory-meet", alice_calendar))
                .await,
            Err(StorageError::NotAuthorized)
        ));
        // Nor read or update alice's page through the owner surface.
        assert!(
            storage
                .get_scheduling_page(mallory, page.id)
                .await
                .expect("get")
                .is_none()
        );
        assert!(matches!(
            storage
                .update_scheduling_page(mallory, page.id, SchedulingPagePatch::default())
                .await,
            Err(StorageError::NotAuthorized)
        ));
        storage.close();
    }

    #[tokio::test]
    async fn booking_race_yields_exactly_one_winner() {
        let (_dir, storage, _account, _calendar, page) = harness().await;
        let start = unix_now() + 86_400;
        let end = start + 1_800;

        let (a, b) = tokio::join!(
            storage.book_slot(book_req(&page, start, end)),
            storage.book_slot(book_req(&page, start, end)),
        );
        let winners = [&a, &b].iter().filter(|r| r.is_ok()).count();
        assert_eq!(winners, 1, "exactly one booking must win: {a:?} {b:?}");
        assert!(
            [&a, &b]
                .iter()
                .any(|r| matches!(r, Err(StorageError::Conflict(_)))),
            "the loser must get Conflict"
        );

        // The winner produced both rows.
        let bookings = storage
            .list_bookings(page.account_id, Some(page.id))
            .await
            .expect("bookings");
        assert_eq!(bookings.len(), 1);
        let events = storage
            .list_calendar_events(page.calendar_id)
            .await
            .expect("events");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, bookings[0].event_id);
        storage.close();
    }

    #[tokio::test]
    async fn booking_conflicts_with_existing_event_and_pause() {
        let (_dir, storage, account, calendar, page) = harness().await;
        let start = unix_now() + 86_400;

        // A pre-existing event on ANY owned calendar blocks the slot.
        storage
            .create_calendar_event(calendar, "Busy".into(), None, start, start + 3_600, None)
            .await
            .expect("event");
        assert!(matches!(
            storage
                .book_slot(book_req(&page, start + 1_800, start + 3_600))
                .await,
            Err(StorageError::Conflict(_))
        ));

        // An adjacent slot (touching, not overlapping) is fine.
        storage
            .book_slot(book_req(&page, start + 3_600, start + 5_400))
            .await
            .expect("adjacent slot books");

        // Paused page refuses bookings.
        storage
            .update_scheduling_page(
                account,
                page.id,
                SchedulingPagePatch {
                    status: Some(PageStatus::Paused),
                    ..Default::default()
                },
            )
            .await
            .expect("pause");
        assert!(matches!(
            storage
                .book_slot(book_req(&page, start + 7_200, start + 9_000))
                .await,
            Err(StorageError::Conflict(_))
        ));
        storage.close();
    }

    #[tokio::test]
    async fn max_per_day_enforced() {
        let (_dir, storage, account, _calendar, page) = harness().await;
        storage
            .update_scheduling_page(
                account,
                page.id,
                SchedulingPagePatch {
                    max_per_day: Some(Some(1)),
                    ..Default::default()
                },
            )
            .await
            .expect("limit");

        let day = (unix_now() + 86_400) - (unix_now() + 86_400).rem_euclid(86_400);
        let mut first = book_req(&page, day + 3_600, day + 5_400);
        first.day_bounds = (day, day + 86_400);
        storage.book_slot(first).await.expect("first booking");

        let mut second = book_req(&page, day + 7_200, day + 9_000);
        second.day_bounds = (day, day + 86_400);
        assert!(matches!(
            storage.book_slot(second).await,
            Err(StorageError::Conflict(_))
        ));
        storage.close();
    }
}
