//! Public "schedule a meeting with me" pages: a Calendly-style booking flow
//! served without authentication.
//!
//! - `GET  /schedule/{slug}`        server-rendered booking page (HTML)
//! - `GET  /schedule/{slug}/slots`  available slots as JSON
//! - `POST /schedule/{slug}/book`   book one slot (rate limited)
//!
//! The server never trusts a client-picked slot: `book` re-derives the valid
//! slot set for that day and requires membership, then the storage layer's
//! atomic `book_slot` guards against concurrent double-booking (HTTP 409).
//! Unknown and paused slugs are both a uniform 404 (no existence oracle).

pub mod ics;
pub mod mail;
pub mod rate_limit;
pub mod slots;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::extract::{ConnectInfo, Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use chrono::{NaiveDate, TimeZone};
use chrono_tz::Tz;
use owney_storage::{BookSlotRequest, PageStatus, SchedulingPage, StorageError};
use rate_limit::RateLimiter;
use serde::Deserialize;
use serde_json::json;

use crate::ApiState;

const MAX_RANGE_DAYS: i64 = 31;
const MAX_HORIZON_DAYS: i64 = 60;

pub fn routes() -> Router<Arc<ApiState>> {
    let limiter = Arc::new(RateLimiter::new());
    Router::new()
        .route("/schedule/{slug}", get(page_html))
        .route("/schedule/{slug}/slots", get(slots_json))
        .route("/schedule/{slug}/book", post(book))
        .layer(Extension(limiter))
}

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "no such page").into_response()
}

fn bad_request(msg: impl Into<String>) -> Response {
    (StatusCode::BAD_REQUEST, msg.into()).into_response()
}

fn server_fail(err: impl std::fmt::Display) -> Response {
    tracing::error!(%err, "scheduling endpoint failed");
    (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
}

/// Active page for a slug, or a uniform 404.
async fn active_page(state: &ApiState, slug: &str) -> Result<SchedulingPage, Response> {
    match state.storage.get_scheduling_page_by_slug(slug).await {
        Ok(Some(page)) if page.status == PageStatus::Active => Ok(page),
        Ok(_) => Err(not_found()),
        Err(err) => Err(server_fail(err)),
    }
}

/// Infallible client-ip extractor: reads `ConnectInfo` when the server was
/// started with `into_make_service_with_connect_info`, and falls back to a
/// shared key otherwise (tower::oneshot in tests). axum 0.8's optional
/// extractors don't cover `ConnectInfo`, hence the hand-rolled impl.
#[derive(Debug, Clone, Copy)]
struct ClientIp(std::net::IpAddr);

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let ip = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|info| info.0.ip())
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        Ok(ClientIp(ip))
    }
}

// Err is a full Response for ergonomic `?`-free match at call sites;
// one per request, so the size is irrelevant.
#[allow(clippy::result_large_err)]
fn page_tz(page: &SchedulingPage) -> Result<Tz, Response> {
    page.timezone
        .parse()
        .map_err(|_| server_fail(format!("stored timezone {:?} invalid", page.timezone)))
}

fn today_in(tz: Tz, now: i64) -> NaiveDate {
    match tz.timestamp_opt(now, 0) {
        chrono::LocalResult::Single(dt) | chrono::LocalResult::Ambiguous(dt, _) => dt.date_naive(),
        chrono::LocalResult::None => chrono::Utc
            .timestamp_opt(now, 0)
            .single()
            .map(|dt| dt.date_naive())
            .unwrap_or_default(),
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Compute available slots for [from..=to]; shared by `slots_json` and the
/// re-derivation inside `book`.
async fn slots_for_range(
    state: &ApiState,
    page: &SchedulingPage,
    tz: Tz,
    duration_mins: u32,
    from: NaiveDate,
    to: NaiveDate,
    now: i64,
) -> Result<Vec<slots::Slot>, Response> {
    let (range_lo, _) = slots::local_day_bounds(tz, from);
    let (_, range_hi) = slots::local_day_bounds(tz, to);
    // Widen the busy fetch so buffers and the longest meeting are covered.
    let widen = i64::from(page.durations_mins.iter().max().copied().unwrap_or(30)) * 60
        + i64::from(page.buffer_before_mins.max(page.buffer_after_mins)) * 60;

    let mut busy = state
        .storage
        .events_overlapping(page.account_id, range_lo - widen, range_hi + widen)
        .await
        .map_err(server_fail)?;
    // Confirmed bookings also block (belt-and-braces with their events) and
    // feed the per-day quota counts.
    let bookings = state
        .storage
        .list_confirmed_bookings_in_range(page.id, range_lo - widen, range_hi + widen)
        .await
        .map_err(server_fail)?;
    let mut booked_per_day: HashMap<NaiveDate, u32> = HashMap::new();
    for booking in &bookings {
        busy.push((booking.start, booking.end));
        *booked_per_day
            .entry(today_in(tz, booking.start))
            .or_default() += 1;
    }

    let params = slots::SlotParams {
        tz,
        availability: &page.availability,
        duration_mins,
        buffer_before_mins: page.buffer_before_mins,
        buffer_after_mins: page.buffer_after_mins,
        min_notice_mins: page.min_notice_mins,
        max_per_day: page.max_per_day,
        valid_from: page.valid_from.as_deref().and_then(|d| d.parse().ok()),
        valid_until: page.valid_until.as_deref().and_then(|d| d.parse().ok()),
        now,
    };
    Ok(slots::compute_slots(
        &params,
        from,
        to,
        &busy,
        &booked_per_day,
    ))
}

#[derive(Debug, Deserialize)]
struct SlotsQuery {
    from: Option<String>,
    to: Option<String>,
    duration: Option<u32>,
}

async fn slots_json(
    State(state): State<Arc<ApiState>>,
    Extension(limiter): Extension<Arc<RateLimiter>>,
    ClientIp(ip): ClientIp,
    Path(slug): Path<String>,
    Query(query): Query<SlotsQuery>,
) -> Response {
    if !limiter.allow(ip, "slots", 60, 60) {
        return (StatusCode::TOO_MANY_REQUESTS, "slow down").into_response();
    }
    let page = match active_page(&state, &slug).await {
        Ok(page) => page,
        Err(resp) => return resp,
    };
    let tz = match page_tz(&page) {
        Ok(tz) => tz,
        Err(resp) => return resp,
    };
    let now = unix_now();
    let today = today_in(tz, now);

    let duration = query.duration.unwrap_or(page.durations_mins[0]);
    if !page.durations_mins.contains(&duration) {
        return bad_request(format!("duration must be one of {:?}", page.durations_mins));
    }
    let from: NaiveDate = match query.from.as_deref().map(str::parse) {
        None => today,
        Some(Ok(date)) => date,
        Some(Err(_)) => return bad_request("bad `from` date (want YYYY-MM-DD)"),
    };
    let to: NaiveDate = match query.to.as_deref().map(str::parse) {
        None => from + chrono::Duration::days(13),
        Some(Ok(date)) => date,
        Some(Err(_)) => return bad_request("bad `to` date (want YYYY-MM-DD)"),
    };
    if to < from || (to - from).num_days() >= MAX_RANGE_DAYS {
        return bad_request(format!("range must be 1..={MAX_RANGE_DAYS} days"));
    }
    if to > today + chrono::Duration::days(MAX_HORIZON_DAYS) {
        return bad_request(format!("horizon is {MAX_HORIZON_DAYS} days"));
    }

    let slots = match slots_for_range(&state, &page, tz, duration, from, to, now).await {
        Ok(slots) => slots,
        Err(resp) => return resp,
    };
    let slot_values: Vec<serde_json::Value> = slots
        .iter()
        .map(|slot| {
            let local = tz
                .timestamp_opt(slot.start, 0)
                .single()
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_default();
            json!({"start": slot.start, "end": slot.end, "startLocal": local})
        })
        .collect();
    axum::Json(json!({
        "timezone": page.timezone,
        "durationMins": duration,
        "slots": slot_values,
    }))
    .into_response()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BookBody {
    start: i64,
    duration_mins: u32,
    name: String,
    email: String,
    #[serde(default)]
    note: Option<String>,
}

#[allow(clippy::result_large_err)]
fn validate_visitor(body: &BookBody) -> Result<(), Response> {
    if body.name.is_empty() || body.name.chars().count() > 200 {
        return Err(bad_request("name must be 1-200 chars"));
    }
    let email = &body.email;
    let ok = email.len() <= 254
        && email.matches('@').count() == 1
        && !email.starts_with('@')
        && !email.ends_with('@')
        && !email.chars().any(|c| c.is_control() || c.is_whitespace());
    if !ok {
        return Err(bad_request("bad email address"));
    }
    if body
        .note
        .as_deref()
        .is_some_and(|n| n.chars().count() > 2000)
    {
        return Err(bad_request("note must be <= 2000 chars"));
    }
    Ok(())
}

async fn book(
    State(state): State<Arc<ApiState>>,
    Extension(limiter): Extension<Arc<RateLimiter>>,
    ClientIp(ip): ClientIp,
    Path(slug): Path<String>,
    body: Result<axum::Json<BookBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if !limiter.allow(ip, "book", 10, 3600) {
        return (StatusCode::TOO_MANY_REQUESTS, "slow down").into_response();
    }
    let axum::Json(body) = match body {
        Ok(body) => body,
        Err(err) => return bad_request(format!("bad request body: {err}")),
    };
    if let Err(resp) = validate_visitor(&body) {
        return resp;
    }
    let page = match active_page(&state, &slug).await {
        Ok(page) => page,
        Err(resp) => return resp,
    };
    let tz = match page_tz(&page) {
        Ok(tz) => tz,
        Err(resp) => return resp,
    };
    if !page.durations_mins.contains(&body.duration_mins) {
        return bad_request(format!("duration must be one of {:?}", page.durations_mins));
    }

    // Re-derive the slot SHAPE for the local day containing the pick (grid,
    // windows, notice, valid range) with no busy filtering — the pick must be
    // one of these or it was never bookable (400). Busy/quota conflicts are
    // the atomic `book_slot` transaction's job (409), so a just-taken slot
    // is distinguishable from an off-grid time.
    let now = unix_now();
    let day = today_in(tz, body.start);
    let params = slots::SlotParams {
        tz,
        availability: &page.availability,
        duration_mins: body.duration_mins,
        buffer_before_mins: page.buffer_before_mins,
        buffer_after_mins: page.buffer_after_mins,
        min_notice_mins: page.min_notice_mins,
        max_per_day: None, // quota is enforced atomically in book_slot
        valid_from: page.valid_from.as_deref().and_then(|d| d.parse().ok()),
        valid_until: page.valid_until.as_deref().and_then(|d| d.parse().ok()),
        now,
    };
    let valid = slots::compute_slots(&params, day, day, &[], &HashMap::new());
    let Some(slot) = valid.iter().find(|slot| slot.start == body.start) else {
        return bad_request("that time is not an available slot");
    };

    let owner = match state.storage.account(page.account_id).await {
        Ok(Some(account)) => account,
        Ok(None) => return not_found(),
        Err(err) => return server_fail(err),
    };
    let owner_label = owner
        .display_name
        .clone()
        .unwrap_or_else(|| owner.email.clone());

    let booking = match state
        .storage
        .book_slot(BookSlotRequest {
            page_id: page.id,
            visitor_name: body.name.clone(),
            visitor_email: body.email.clone(),
            note: body.note.clone(),
            start: slot.start,
            end: slot.end,
            busy_from: slot.start - i64::from(page.buffer_before_mins) * 60,
            busy_to: slot.end + i64::from(page.buffer_after_mins) * 60,
            event_title: format!("Meeting: {} & {}", body.name, owner_label),
            event_description: body.note.clone(),
            day_bounds: slots::local_day_bounds(tz, day),
        })
        .await
    {
        Ok(booking) => booking,
        Err(StorageError::Conflict(msg)) => {
            return (StatusCode::CONFLICT, msg).into_response();
        }
        Err(StorageError::BadInput(msg)) => return bad_request(msg),
        Err(err) => return server_fail(err),
    };

    // Confirmation emails. Failures are logged but never undo the booking —
    // the calendar event is the source of truth.
    send_confirmations(&state, &page, &owner, &booking, tz).await;

    (
        StatusCode::CREATED,
        axum::Json(json!({
            "bookingId": booking.id.to_string(),
            "start": booking.start,
            "end": booking.end,
            "timezone": page.timezone,
        })),
    )
        .into_response()
}

async fn send_confirmations(
    state: &ApiState,
    page: &SchedulingPage,
    owner: &owney_storage::Account,
    booking: &owney_storage::Booking,
    tz: Tz,
) {
    let host = crate::fed_sig::host_of(&state.public_url);
    let owner_label = owner
        .display_name
        .clone()
        .unwrap_or_else(|| owner.email.clone());
    let local_time = tz
        .timestamp_opt(booking.start, 0)
        .single()
        .map(|dt| dt.format("%A %Y-%m-%d %H:%M %Z").to_string())
        .unwrap_or_else(|| booking.start.to_string());

    let ics = ics::render(&ics::IcsInvite {
        uid: &format!("{}@{}", booking.id, host),
        dtstamp: booking.created_at,
        start: booking.start,
        end: booking.end,
        summary: &format!("Meeting: {} & {}", booking.visitor_name, owner_label),
        description: booking.note.as_deref(),
        organizer_name: &owner_label,
        organizer_email: &owner.email,
        attendee_name: &booking.visitor_name,
        attendee_email: &booking.visitor_email,
    });

    // Visitor: real outbound delivery (PGP/DKIM/queue). Absent submitter is a
    // documented degradation (read-only deployments, tests).
    if let Some(submitter) = &state.submitter {
        let raw = mail::compose(&mail::Confirmation {
            host: &host,
            from_name: Some(&owner_label),
            from_email: &owner.email,
            to: &booking.visitor_email,
            subject: &format!("Confirmed: {} on {}", page.title, local_time),
            text_body: &format!(
                "Hi {},\r\n\r\nYou're booked with {} on {} ({} minutes).\r\n\r\n\
                 The attached invite adds it to your calendar.\r\n",
                booking.visitor_name,
                owner_label,
                local_time,
                (booking.end - booking.start) / 60,
            ),
            ics: &ics,
        });
        if let Err(err) = submitter
            .submit(
                owner.id,
                owner.email.clone(),
                vec![booking.visitor_email.clone()],
                raw,
            )
            .await
        {
            tracing::warn!(%err, "booking confirmation to visitor failed to queue");
        }
    } else {
        tracing::warn!("no submitter configured; visitor confirmation not sent");
    }

    // Owner: direct local ingest — lands in the inbox immediately and fires
    // an Email StateChange so their clients get push.
    let raw = mail::compose(&mail::Confirmation {
        host: &host,
        from_name: Some("Owney Scheduling"),
        from_email: &owner.email,
        to: &owner.email,
        subject: &format!("New booking: {} on {}", booking.visitor_name, local_time),
        text_body: &format!(
            "{} <{}> booked \"{}\" on {}.\r\n{}\r\n",
            booking.visitor_name,
            booking.visitor_email,
            page.title,
            local_time,
            booking
                .note
                .as_deref()
                .map(|n| format!("\r\nNote: {n}"))
                .unwrap_or_default(),
        ),
        ics: &ics,
    });
    if let Err(err) = state
        .storage
        .ingest_email(owner.id, raw, "inbox", None)
        .await
    {
        tracing::warn!(%err, "booking notification to owner failed to ingest");
    }
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

async fn page_html(State(state): State<Arc<ApiState>>, Path(slug): Path<String>) -> Response {
    let page = match active_page(&state, &slug).await {
        Ok(page) => page,
        Err(resp) => return resp,
    };
    let title = html_escape(&page.title);
    let description = page
        .description
        .as_deref()
        .map(|d| format!("<p class=\"desc\">{}</p>", html_escape(d)))
        .unwrap_or_default();
    let durations = serde_json::to_string(&page.durations_mins).unwrap_or_else(|_| "[30]".into());
    let timezone = html_escape(&page.timezone);
    let slug = html_escape(&slug);

    Html(format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: -apple-system, system-ui, sans-serif; max-width: 640px;
         margin: 2rem auto; padding: 0 1rem; line-height: 1.5; }}
  h1 {{ margin-bottom: .25rem; }}
  .desc, .tz {{ color: #777; }}
  .days {{ display: flex; gap: .5rem; flex-wrap: wrap; margin: 1rem 0; }}
  .days button, .slots button, form button, .durations button {{
    padding: .5rem .75rem; border: 1px solid #999; border-radius: 6px;
    background: transparent; cursor: pointer; font: inherit; }}
  .days button.active, .durations button.active {{ background: #4a7dff; color: #fff; border-color: #4a7dff; }}
  .slots {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(90px, 1fr));
           gap: .5rem; margin: 1rem 0; }}
  form {{ display: none; margin-top: 1rem; }}
  form.visible {{ display: block; }}
  form input, form textarea {{ display: block; width: 100%; margin: .5rem 0;
    padding: .5rem; font: inherit; box-sizing: border-box; }}
  #status {{ margin-top: 1rem; font-weight: 600; }}
  .durations {{ display: flex; gap: .5rem; }}
</style>
</head>
<body>
<h1>{title}</h1>
{description}
<p class="tz">Times shown in {timezone}</p>
<div class="durations" id="durations"></div>
<div class="days" id="days"></div>
<div class="slots" id="slots"></div>
<form id="form">
  <div id="picked"></div>
  <input id="name" placeholder="Your name" required maxlength="200">
  <input id="email" type="email" placeholder="you@example.com" required>
  <textarea id="note" placeholder="Anything to add? (optional)" maxlength="2000"></textarea>
  <button type="submit">Confirm booking</button>
</form>
<div id="status"></div>
<script>
const slug = {slug:?};
const durations = {durations};
let duration = durations[0];
let slotsByDay = {{}};
let picked = null;

function fmt(ts) {{
  return new Date(ts * 1000).toLocaleTimeString([], {{hour: '2-digit', minute: '2-digit'}});
}}
function fmtDay(iso) {{
  return new Date(iso + 'T12:00:00').toLocaleDateString([], {{weekday: 'short', month: 'short', day: 'numeric'}});
}}

async function load() {{
  const today = new Date();
  const from = today.toISOString().slice(0, 10);
  const to = new Date(today.getTime() + 13 * 86400e3).toISOString().slice(0, 10);
  const resp = await fetch(`/schedule/${{slug}}/slots?from=${{from}}&to=${{to}}&duration=${{duration}}`);
  if (!resp.ok) {{ document.getElementById('status').textContent = 'Could not load times.'; return; }}
  const data = await resp.json();
  slotsByDay = {{}};
  for (const slot of data.slots) {{
    const day = slot.startLocal.slice(0, 10);
    (slotsByDay[day] = slotsByDay[day] || []).push(slot);
  }}
  renderDurations();
  renderDays();
}}

function renderDurations() {{
  const el = document.getElementById('durations');
  el.innerHTML = '';
  if (durations.length < 2) return;
  for (const d of durations) {{
    const b = document.createElement('button');
    b.textContent = d + ' min';
    b.className = d === duration ? 'active' : '';
    b.onclick = () => {{ duration = d; picked = null; load(); }};
    el.appendChild(b);
  }}
}}

function renderDays() {{
  const days = Object.keys(slotsByDay).sort();
  const el = document.getElementById('days');
  el.innerHTML = '';
  document.getElementById('slots').innerHTML = '';
  document.getElementById('form').className = '';
  if (!days.length) {{ document.getElementById('status').textContent = 'No times available in the next two weeks.'; return; }}
  document.getElementById('status').textContent = '';
  days.forEach((day, i) => {{
    const b = document.createElement('button');
    b.textContent = fmtDay(day);
    b.onclick = () => renderSlots(day, b);
    el.appendChild(b);
    if (i === 0) renderSlots(day, b);
  }});
}}

function renderSlots(day, activeBtn) {{
  document.querySelectorAll('.days button').forEach(b => b.className = '');
  if (activeBtn) activeBtn.className = 'active';
  const el = document.getElementById('slots');
  el.innerHTML = '';
  for (const slot of slotsByDay[day]) {{
    const b = document.createElement('button');
    b.textContent = fmt(slot.start);
    b.onclick = () => {{
      picked = slot;
      document.getElementById('picked').textContent =
        `Booking ${{fmtDay(day)}} at ${{fmt(slot.start)}} (${{duration}} min)`;
      document.getElementById('form').className = 'visible';
    }};
    el.appendChild(b);
  }}
}}

document.getElementById('form').onsubmit = async (e) => {{
  e.preventDefault();
  if (!picked) return;
  const resp = await fetch(`/schedule/${{slug}}/book`, {{
    method: 'POST',
    headers: {{'content-type': 'application/json'}},
    body: JSON.stringify({{
      start: picked.start,
      durationMins: duration,
      name: document.getElementById('name').value,
      email: document.getElementById('email').value,
      note: document.getElementById('note').value || null,
    }}),
  }});
  const status = document.getElementById('status');
  if (resp.status === 201) {{
    document.getElementById('form').className = '';
    document.getElementById('slots').innerHTML = '';
    document.getElementById('days').innerHTML = '';
    status.textContent = 'Booked! Check your email for the invite.';
  }} else if (resp.status === 409) {{
    status.textContent = 'That time was just taken — pick another.';
    picked = null; load();
  }} else {{
    status.textContent = 'Booking failed: ' + await resp.text();
  }}
}};

load();
</script>
</body>
</html>"#
    ))
    .into_response()
}
