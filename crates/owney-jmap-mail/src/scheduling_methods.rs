//! Owner-side JMAP methods for public scheduling pages.
//!
//! - `SchedulingPage/get`     list/fetch the account's pages
//! - `SchedulingPage/set`     create/update (pause via `{"status":"paused"}`)
//! - `SchedulingBooking/get`  list bookings made through the pages
//!
//! The public booking flow itself is HTTP (`/schedule/{slug}`), not JMAP —
//! visitors have no JMAP session.

use std::sync::Arc;

use jmap_core::MethodError;
use owney_api::JmapCtx;
use owney_storage::{
    Availability, NewSchedulingPage, PageStatus, SchedulingPage, SchedulingPagePatch,
};
use serde_json::{Map, Value, json};

pub const SCHEDULING_CAPABILITY: &str = "urn:owney:params:jmap:scheduling";

pub fn scheduling_capability() -> Value {
    json!({
        "maxPagesPerAccount": 20,
        "maxDurationsPerPage": 8,
    })
}

fn check_account(ctx: &JmapCtx, account_id: &str) -> Result<owney_core::AccountId, MethodError> {
    if account_id != ctx.account.id.to_string() {
        return Err(MethodError::AccountNotFound);
    }
    Ok(ctx.account.id)
}

/// Authorization boundary: storage `NotAuthorized` is `forbidden`, bad input
/// is `invalidArguments`, the rest is a server fail.
fn storage_err(e: owney_storage::StorageError) -> MethodError {
    match e {
        owney_storage::StorageError::NotAuthorized => MethodError::Forbidden,
        owney_storage::StorageError::BadInput(msg) => MethodError::InvalidArguments(msg),
        other => MethodError::ServerFail(other.to_string()),
    }
}

fn page_json(page: &SchedulingPage, public_url: &str) -> Value {
    json!({
        "id": page.id.to_string(),
        "slug": page.slug,
        "url": format!("{}/schedule/{}", public_url.trim_end_matches('/'), page.slug),
        "title": page.title,
        "description": page.description,
        "calendarId": page.calendar_id.to_string(),
        "timezone": page.timezone,
        "availability": serde_json::to_value(&page.availability).unwrap_or(Value::Null),
        "durationsMins": page.durations_mins,
        "bufferBeforeMins": page.buffer_before_mins,
        "bufferAfterMins": page.buffer_after_mins,
        "minNoticeMins": page.min_notice_mins,
        "maxPerDay": page.max_per_day,
        "validFrom": page.valid_from,
        "validUntil": page.valid_until,
        "status": page.status.as_str(),
    })
}

pub async fn scheduling_page_get(args: Value, ctx: Arc<JmapCtx>) -> Result<Value, MethodError> {
    let account_id = check_account(
        &ctx,
        args["accountId"]
            .as_str()
            .ok_or_else(|| MethodError::InvalidArguments("accountId required".into()))?,
    )?;
    let ids: Option<Vec<&str>> = args["ids"]
        .as_array()
        .map(|list| list.iter().filter_map(Value::as_str).collect());

    let pages = ctx
        .storage
        .list_scheduling_pages(account_id)
        .await
        .map_err(storage_err)?;
    let list: Vec<Value> = pages
        .iter()
        .filter(|page| {
            ids.as_ref()
                .is_none_or(|ids| ids.contains(&page.id.to_string().as_str()))
        })
        .map(|page| page_json(page, &ctx.public_url))
        .collect();

    Ok(json!({
        "accountId": args["accountId"],
        "list": list,
        "notFound": [],
    }))
}

/// Build a `NewSchedulingPage` from a create object, applying the documented
/// defaults (slug from the account localpart, business-hours availability,
/// one 30-minute duration, UTC).
fn parse_create(
    ctx: &JmapCtx,
    object: &Map<String, Value>,
) -> Result<NewSchedulingPage, MethodError> {
    let invalid = |msg: String| MethodError::InvalidArguments(msg);

    let calendar_id = object
        .get("calendarId")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("calendarId is required".into()))?
        .parse()
        .map_err(|_| invalid("bad calendarId".into()))?;

    let localpart = ctx.account.email.split('@').next().unwrap_or("me");
    let default_slug: String = localpart
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() || c.is_ascii_digit() {
                c
            } else {
                '-'
            }
        })
        .collect();
    let display = ctx
        .account
        .display_name
        .clone()
        .unwrap_or_else(|| ctx.account.email.clone());

    let availability = match object.get("availability") {
        None | Some(Value::Null) => Availability::default_business_hours(),
        Some(value) => serde_json::from_value(value.clone())
            .map_err(|err| invalid(format!("bad availability: {err}")))?,
    };
    let durations = match object.get("durationsMins") {
        None | Some(Value::Null) => vec![30],
        Some(value) => serde_json::from_value(value.clone())
            .map_err(|err| invalid(format!("bad durationsMins: {err}")))?,
    };

    let get_str = |key: &str| object.get(key).and_then(Value::as_str).map(str::to_owned);
    let get_u32 = |key: &str| -> Result<Option<u32>, MethodError> {
        match object.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(value) => value
                .as_u64()
                .and_then(|v| u32::try_from(v).ok())
                .map(Some)
                .ok_or_else(|| invalid(format!("bad {key}"))),
        }
    };

    Ok(NewSchedulingPage {
        slug: get_str("slug").unwrap_or(default_slug),
        title: get_str("title").unwrap_or_else(|| format!("Meet with {display}")),
        description: get_str("description"),
        calendar_id,
        timezone: get_str("timezone").unwrap_or_else(|| "UTC".into()),
        availability,
        durations_mins: durations,
        buffer_before_mins: get_u32("bufferBeforeMins")?.unwrap_or(0),
        buffer_after_mins: get_u32("bufferAfterMins")?.unwrap_or(0),
        min_notice_mins: get_u32("minNoticeMins")?.unwrap_or(0),
        max_per_day: get_u32("maxPerDay")?,
        valid_from: get_str("validFrom"),
        valid_until: get_str("validUntil"),
    })
}

fn parse_patch(object: &Map<String, Value>) -> Result<SchedulingPagePatch, MethodError> {
    let invalid = |msg: String| MethodError::InvalidArguments(msg);
    let mut patch = SchedulingPagePatch::default();

    for (key, value) in object {
        match key.as_str() {
            "title" => patch.title = value.as_str().map(str::to_owned),
            "description" => {
                patch.description = Some(value.as_str().map(str::to_owned));
            }
            "timezone" => patch.timezone = value.as_str().map(str::to_owned),
            "availability" => {
                patch.availability = Some(
                    serde_json::from_value(value.clone())
                        .map_err(|err| invalid(format!("bad availability: {err}")))?,
                );
            }
            "durationsMins" => {
                patch.durations_mins = Some(
                    serde_json::from_value(value.clone())
                        .map_err(|err| invalid(format!("bad durationsMins: {err}")))?,
                );
            }
            "bufferBeforeMins" | "bufferAfterMins" | "minNoticeMins" => {
                let parsed = value
                    .as_u64()
                    .and_then(|v| u32::try_from(v).ok())
                    .ok_or_else(|| invalid(format!("bad {key}")))?;
                match key.as_str() {
                    "bufferBeforeMins" => patch.buffer_before_mins = Some(parsed),
                    "bufferAfterMins" => patch.buffer_after_mins = Some(parsed),
                    _ => patch.min_notice_mins = Some(parsed),
                }
            }
            "maxPerDay" => {
                patch.max_per_day = Some(match value {
                    Value::Null => None,
                    other => Some(
                        other
                            .as_u64()
                            .and_then(|v| u32::try_from(v).ok())
                            .ok_or_else(|| invalid("bad maxPerDay".into()))?,
                    ),
                });
            }
            "validFrom" => patch.valid_from = Some(value.as_str().map(str::to_owned)),
            "validUntil" => patch.valid_until = Some(value.as_str().map(str::to_owned)),
            "status" => {
                patch.status = Some(match value.as_str() {
                    Some("active") => PageStatus::Active,
                    Some("paused") => PageStatus::Paused,
                    _ => return Err(invalid("status must be active|paused".into())),
                });
            }
            other => return Err(invalid(format!("unknown property {other:?}"))),
        }
    }
    Ok(patch)
}

pub async fn scheduling_page_set(args: Value, ctx: Arc<JmapCtx>) -> Result<Value, MethodError> {
    let account_id = check_account(
        &ctx,
        args["accountId"]
            .as_str()
            .ok_or_else(|| MethodError::InvalidArguments("accountId required".into()))?,
    )?;

    let mut created = Map::new();
    let mut not_created = Map::new();
    if let Some(create) = args["create"].as_object() {
        for (creation_id, object) in create {
            let Some(object) = object.as_object() else {
                not_created.insert(
                    creation_id.clone(),
                    json!({"type": "invalidProperties", "description": "not an object"}),
                );
                continue;
            };
            let result = match parse_create(&ctx, object) {
                Ok(new) => ctx
                    .storage
                    .create_scheduling_page(account_id, new)
                    .await
                    .map_err(storage_err),
                Err(err) => Err(err),
            };
            match result {
                Ok(page) => {
                    created.insert(creation_id.clone(), page_json(&page, &ctx.public_url));
                }
                Err(MethodError::Forbidden) => return Err(MethodError::Forbidden),
                Err(err) => {
                    not_created.insert(
                        creation_id.clone(),
                        json!({"type": "invalidProperties", "description": err.to_string()}),
                    );
                }
            }
        }
    }

    let mut updated = Map::new();
    let mut not_updated = Map::new();
    if let Some(update) = args["update"].as_object() {
        for (id, object) in update {
            let result = async {
                let page_id = id
                    .parse()
                    .map_err(|_| MethodError::InvalidArguments("bad page id".into()))?;
                let object = object
                    .as_object()
                    .ok_or_else(|| MethodError::InvalidArguments("not an object".into()))?;
                let patch = parse_patch(object)?;
                ctx.storage
                    .update_scheduling_page(account_id, page_id, patch)
                    .await
                    .map_err(storage_err)
            }
            .await;
            match result {
                Ok(page) => {
                    updated.insert(id.clone(), page_json(&page, &ctx.public_url));
                }
                Err(MethodError::Forbidden) => return Err(MethodError::Forbidden),
                Err(err) => {
                    not_updated.insert(
                        id.clone(),
                        json!({"type": "invalidProperties", "description": err.to_string()}),
                    );
                }
            }
        }
    }

    if args["destroy"].as_array().is_some_and(|d| !d.is_empty()) {
        return Err(MethodError::InvalidArguments(
            "destroy is not supported; pause the page instead".into(),
        ));
    }

    Ok(json!({
        "accountId": args["accountId"],
        "created": created,
        "notCreated": not_created,
        "updated": updated,
        "notUpdated": not_updated,
    }))
}

pub async fn scheduling_booking_get(args: Value, ctx: Arc<JmapCtx>) -> Result<Value, MethodError> {
    let account_id = check_account(
        &ctx,
        args["accountId"]
            .as_str()
            .ok_or_else(|| MethodError::InvalidArguments("accountId required".into()))?,
    )?;
    let page_id = match args["pageId"].as_str() {
        Some(id) => Some(
            id.parse()
                .map_err(|_| MethodError::InvalidArguments("bad pageId".into()))?,
        ),
        None => None,
    };

    let bookings = ctx
        .storage
        .list_bookings(account_id, page_id)
        .await
        .map_err(storage_err)?;
    let list: Vec<Value> = bookings
        .iter()
        .map(|b| {
            json!({
                "id": b.id.to_string(),
                "pageId": b.page_id.to_string(),
                "eventId": b.event_id.to_string(),
                "visitorName": b.visitor_name,
                "visitorEmail": b.visitor_email,
                "note": b.note,
                "start": b.start,
                "end": b.end,
                "startUtc": owney_core::time::iso8601_utc(b.start),
                "status": b.status,
            })
        })
        .collect();

    Ok(json!({
        "accountId": args["accountId"],
        "list": list,
        "notFound": [],
    }))
}

#[cfg(test)]
mod tests {
    use owney_storage::{Account, Storage};

    use super::*;

    async fn setup() -> (tempfile::TempDir, Arc<Storage>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let events = owney_events::EventBus::new(64);
        let storage = Storage::open(dir.path(), events).expect("open storage");
        (dir, Arc::new(storage))
    }

    fn ctx_for(storage: &Arc<Storage>, account: Account) -> Arc<JmapCtx> {
        Arc::new(JmapCtx {
            account,
            storage: storage.clone(),
            submitter: None,
            public_url: "http://alice.local:8381".to_string(),
            federation: Default::default(),
        })
    }

    #[tokio::test]
    async fn create_get_pause_roundtrip() {
        let (_dir, storage) = setup().await;
        let alice = storage
            .create_account("alice@example.com", Some("Alice"))
            .await
            .expect("alice");
        let calendar = storage
            .create_calendar(alice.id, "Personal".into(), None)
            .await
            .expect("calendar");
        let ctx = ctx_for(&storage, alice.clone());

        let result = scheduling_page_set(
            json!({
                "accountId": alice.id.to_string(),
                "create": {"c1": {"calendarId": calendar.id.to_string(), "timezone": "America/Denver"}},
            }),
            ctx.clone(),
        )
        .await
        .expect("set");
        let page = &result["created"]["c1"];
        assert_eq!(page["slug"], "alice", "slug derived from localpart");
        assert_eq!(page["title"], "Meet with Alice");
        assert_eq!(page["durationsMins"], json!([30]));
        assert_eq!(page["url"], "http://alice.local:8381/schedule/alice");
        let page_id = page["id"].as_str().expect("id").to_string();

        let fetched = scheduling_page_get(json!({"accountId": alice.id.to_string()}), ctx.clone())
            .await
            .expect("get");
        assert_eq!(fetched["list"].as_array().expect("list").len(), 1);
        assert_eq!(
            fetched["list"][0]["availability"]["weekly"]["mon"][0]["start"],
            "09:00"
        );

        let paused = scheduling_page_set(
            json!({
                "accountId": alice.id.to_string(),
                "update": {page_id.clone(): {"status": "paused"}},
            }),
            ctx,
        )
        .await
        .expect("pause");
        assert_eq!(paused["updated"][&page_id]["status"], "paused");
    }

    #[tokio::test]
    async fn cross_account_is_rejected() {
        let (_dir, storage) = setup().await;
        let alice = storage
            .create_account("alice@example.com", None)
            .await
            .expect("alice");
        let mallory = storage
            .create_account("mallory@example.com", None)
            .await
            .expect("mallory");
        let alice_calendar = storage
            .create_calendar(alice.id, "Personal".into(), None)
            .await
            .expect("calendar");

        // Mallory impersonating alice's accountId: accountNotFound.
        let err = scheduling_page_get(
            json!({"accountId": alice.id.to_string()}),
            ctx_for(&storage, mallory.clone()),
        )
        .await
        .expect_err("must fail");
        assert!(matches!(err, MethodError::AccountNotFound));

        // Mallory creating a page on alice's calendar: forbidden.
        let err = scheduling_page_set(
            json!({
                "accountId": mallory.id.to_string(),
                "create": {"c1": {"calendarId": alice_calendar.id.to_string()}},
            }),
            ctx_for(&storage, mallory),
        )
        .await
        .expect_err("must fail");
        assert!(matches!(err, MethodError::Forbidden));
    }
}
