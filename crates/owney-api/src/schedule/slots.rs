//! Pure slot computation: expand a page's availability windows into bookable
//! UTC slots for a date range. No IO — everything a caller learned from
//! storage comes in as parameters, so this is exhaustively unit-testable.
//!
//! DST rules (documented behavior, tested against America/Denver):
//! - Spring-forward gap (a local time that doesn't exist): the first valid
//!   instant after the gap is used.
//! - Fall-back ambiguity (a local time that exists twice): the EARLIEST
//!   instant is used.

use std::collections::HashMap;

use chrono::{Datelike, LocalResult, NaiveDate, NaiveDateTime, NaiveTime, TimeZone, Weekday};
use chrono_tz::Tz;
use owney_storage::Availability;

#[derive(Debug)]
pub struct SlotParams<'a> {
    pub tz: Tz,
    pub availability: &'a Availability,
    pub duration_mins: u32,
    pub buffer_before_mins: u32,
    pub buffer_after_mins: u32,
    pub min_notice_mins: u32,
    pub max_per_day: Option<u32>,
    pub valid_from: Option<NaiveDate>,
    pub valid_until: Option<NaiveDate>,
    /// "Now" as a unix timestamp — injected for testability.
    pub now: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Slot {
    pub start: i64,
    pub end: i64,
}

/// Map a wall-clock time in `tz` to a UTC instant, applying the DST rules
/// documented at the top of this module.
pub fn resolve_local(tz: Tz, local: NaiveDateTime) -> i64 {
    match tz.from_local_datetime(&local) {
        LocalResult::Single(dt) => dt.timestamp(),
        LocalResult::Ambiguous(earliest, _latest) => earliest.timestamp(),
        LocalResult::None => {
            // Spring-forward gap: scan forward in 15-minute steps for the
            // first wall-clock time that exists (gaps are 30-120 minutes).
            let mut probe = local;
            for _ in 0..16 {
                probe += chrono::Duration::minutes(15);
                if let LocalResult::Single(dt) | LocalResult::Ambiguous(dt, _) =
                    tz.from_local_datetime(&probe)
                {
                    return dt.timestamp();
                }
            }
            // Unreachable for real timezones; fall back to interpreting the
            // local time as UTC rather than panicking in a public handler.
            local.and_utc().timestamp()
        }
    }
}

/// UTC bounds (half-open) of the local calendar day `date` in `tz`.
pub fn local_day_bounds(tz: Tz, date: NaiveDate) -> (i64, i64) {
    let midnight = |d: NaiveDate| resolve_local(tz, d.and_time(NaiveTime::MIN));
    (midnight(date), midnight(date + chrono::Duration::days(1)))
}

fn weekday_key(weekday: Weekday) -> &'static str {
    match weekday {
        Weekday::Mon => "mon",
        Weekday::Tue => "tue",
        Weekday::Wed => "wed",
        Weekday::Thu => "thu",
        Weekday::Fri => "fri",
        Weekday::Sat => "sat",
        Weekday::Sun => "sun",
    }
}

/// The availability windows for one date, as minutes since local midnight.
/// Overrides replace the weekly rule entirely for that date.
fn windows_for_date(availability: &Availability, date: NaiveDate) -> Vec<(u32, u32)> {
    let key = date.format("%Y-%m-%d").to_string();
    let windows = availability
        .overrides
        .get(&key)
        .or_else(|| availability.weekly.get(weekday_key(date.weekday())));
    windows
        .map(|list| {
            list.iter()
                .filter_map(|w| w.parse_minutes().ok())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn overlaps(a: (i64, i64), b: (i64, i64)) -> bool {
    a.0 < b.1 && b.0 < a.1
}

/// Compute the bookable slots for each date in `[from..=to]`.
///
/// `busy` are UTC half-open intervals (owner's calendar events + confirmed
/// bookings, already buffer-agnostic — buffers are applied to the candidate
/// slot here). `booked_per_day` counts confirmed bookings per local date for
/// the max-per-day rule.
pub fn compute_slots(
    p: &SlotParams,
    from: NaiveDate,
    to: NaiveDate,
    busy: &[(i64, i64)],
    booked_per_day: &HashMap<NaiveDate, u32>,
) -> Vec<Slot> {
    let mut slots = Vec::new();
    let earliest_start = p.now + i64::from(p.min_notice_mins) * 60;
    let duration = i64::from(p.duration_mins) * 60;
    let buffer_before = i64::from(p.buffer_before_mins) * 60;
    let buffer_after = i64::from(p.buffer_after_mins) * 60;

    let mut date = from;
    while date <= to {
        if p.valid_from.is_some_and(|v| date < v) || p.valid_until.is_some_and(|v| date > v) {
            date += chrono::Duration::days(1);
            continue;
        }
        if let Some(limit) = p.max_per_day
            && booked_per_day.get(&date).copied().unwrap_or(0) >= limit
        {
            date += chrono::Duration::days(1);
            continue;
        }

        for (window_start_min, window_end_min) in windows_for_date(p.availability, date) {
            // Step by WALL-CLOCK minutes and resolve each candidate, so a
            // fall-back day offers each wall time once (earliest instant)
            // instead of duplicating the repeated hour. Meetings are real
            // `duration` seconds regardless of DST.
            let minutes_to_local = |mins: u32| {
                date.and_time(
                    NaiveTime::from_num_seconds_from_midnight_opt(mins * 60, 0)
                        .unwrap_or(NaiveTime::MIN),
                )
            };
            let window_end = resolve_local(p.tz, minutes_to_local(window_end_min));

            let mut last_start: Option<i64> = None;
            let mut wall = window_start_min;
            while wall + p.duration_mins <= window_end_min {
                let slot_start = resolve_local(p.tz, minutes_to_local(wall));
                wall += p.duration_mins;
                if last_start == Some(slot_start) {
                    continue; // spring-forward: two wall times hit one instant
                }
                last_start = Some(slot_start);

                let slot = Slot {
                    start: slot_start,
                    end: slot_start + duration,
                };
                if slot.end > window_end {
                    continue;
                }
                let widened = (slot.start - buffer_before, slot.end + buffer_after);
                let is_free = !busy.iter().any(|b| overlaps(widened, *b));
                if slot.start >= earliest_start && is_free {
                    slots.push(slot);
                }
            }
        }
        date += chrono::Duration::days(1);
    }
    slots
}

#[cfg(test)]
mod tests {
    use owney_storage::TimeWindow;

    use super::*;

    fn denver() -> Tz {
        "America/Denver".parse().expect("tz")
    }

    fn business_hours() -> Availability {
        Availability::default_business_hours()
    }

    fn params<'a>(availability: &'a Availability, tz: Tz) -> SlotParams<'a> {
        SlotParams {
            tz,
            availability,
            duration_mins: 30,
            buffer_before_mins: 0,
            buffer_after_mins: 0,
            min_notice_mins: 0,
            max_per_day: None,
            valid_from: None,
            valid_until: None,
            now: 0,
        }
    }

    fn date(s: &str) -> NaiveDate {
        s.parse().expect("date")
    }

    #[test]
    fn weekends_excluded_by_default_but_supported() {
        let availability = business_hours();
        let p = params(&availability, denver());
        // 2026-07-18 is a Saturday, 2026-07-20 a Monday.
        assert!(
            compute_slots(
                &p,
                date("2026-07-18"),
                date("2026-07-18"),
                &[],
                &HashMap::new()
            )
            .is_empty()
        );
        let monday = compute_slots(
            &p,
            date("2026-07-20"),
            date("2026-07-20"),
            &[],
            &HashMap::new(),
        );
        assert_eq!(monday.len(), 16, "8h window / 30min");

        let mut with_saturday = business_hours();
        with_saturday.weekly.insert(
            "sat".into(),
            vec![TimeWindow {
                start: "10:00".into(),
                end: "12:00".into(),
            }],
        );
        let p = params(&with_saturday, denver());
        let saturday = compute_slots(
            &p,
            date("2026-07-18"),
            date("2026-07-18"),
            &[],
            &HashMap::new(),
        );
        assert_eq!(saturday.len(), 4);
    }

    #[test]
    fn overrides_replace_and_block() {
        let mut availability = business_hours();
        availability.overrides.insert("2026-07-20".into(), vec![]); // block Monday
        availability.overrides.insert(
            "2026-07-18".into(), // open a Saturday for 1 hour
            vec![TimeWindow {
                start: "10:00".into(),
                end: "11:00".into(),
            }],
        );
        let p = params(&availability, denver());
        assert!(
            compute_slots(
                &p,
                date("2026-07-20"),
                date("2026-07-20"),
                &[],
                &HashMap::new()
            )
            .is_empty()
        );
        assert_eq!(
            compute_slots(
                &p,
                date("2026-07-18"),
                date("2026-07-18"),
                &[],
                &HashMap::new()
            )
            .len(),
            2
        );
    }

    #[test]
    fn busy_buffers_and_notice_filter() {
        let availability = business_hours();
        // Monday 2026-07-20, Denver is UTC-6 (MDT): 09:00 local = 15:00 UTC.
        let nine_am_utc = 1_784_559_600 - 86_400 * 3; // compute directly below instead
        let _ = nine_am_utc;
        let day_start = resolve_local(
            denver(),
            date("2026-07-20").and_time("09:00:00".parse().unwrap()),
        );

        // Busy 10:00-11:00 local.
        let busy = vec![(day_start + 3_600, day_start + 7_200)];
        let p = params(&availability, denver());
        let slots = compute_slots(
            &p,
            date("2026-07-20"),
            date("2026-07-20"),
            &busy,
            &HashMap::new(),
        );
        assert_eq!(slots.len(), 14, "two 30-min slots blocked");
        assert!(!slots.iter().any(|s| overlaps((s.start, s.end), busy[0])));

        // A 15-min buffer-after also knocks out the 09:30 slot (widened tail
        // touches the busy block).
        let p = SlotParams {
            buffer_after_mins: 15,
            ..params(&availability, denver())
        };
        let buffered = compute_slots(
            &p,
            date("2026-07-20"),
            date("2026-07-20"),
            &busy,
            &HashMap::new(),
        );
        assert_eq!(buffered.len(), 13);

        // min_notice: pretend "now" is Monday 12:00 local — morning gone.
        let p = SlotParams {
            now: day_start + 3 * 3_600,
            min_notice_mins: 60,
            ..params(&availability, denver())
        };
        let notice = compute_slots(
            &p,
            date("2026-07-20"),
            date("2026-07-20"),
            &[],
            &HashMap::new(),
        );
        assert!(notice.iter().all(|s| s.start >= day_start + 4 * 3_600));
        assert_eq!(notice.len(), 8, "13:00-17:00 remain");
    }

    #[test]
    fn valid_range_and_max_per_day() {
        let availability = business_hours();
        let p = SlotParams {
            valid_from: Some(date("2026-07-21")),
            valid_until: Some(date("2026-07-21")),
            ..params(&availability, denver())
        };
        let slots = compute_slots(
            &p,
            date("2026-07-20"),
            date("2026-07-24"),
            &[],
            &HashMap::new(),
        );
        let bounds = local_day_bounds(denver(), date("2026-07-21"));
        assert!(!slots.is_empty());
        assert!(
            slots
                .iter()
                .all(|s| s.start >= bounds.0 && s.start < bounds.1)
        );

        let mut booked = HashMap::new();
        booked.insert(date("2026-07-21"), 2u32);
        let p = SlotParams {
            max_per_day: Some(2),
            valid_from: None,
            valid_until: None,
            ..params(&availability, denver())
        };
        let slots = compute_slots(&p, date("2026-07-21"), date("2026-07-21"), &[], &booked);
        assert!(slots.is_empty(), "day quota reached");
    }

    #[test]
    fn dst_spring_forward_gap() {
        // US DST 2026 starts Sunday 2026-03-08 02:00 local (Denver): 02:00-03:00
        // does not exist. A window 01:00-04:00 must produce slots with no
        // phantom 02:xx local times and correct UTC instants.
        let mut availability = business_hours();
        availability.overrides.insert(
            "2026-03-08".into(),
            vec![TimeWindow {
                start: "01:00".into(),
                end: "04:00".into(),
            }],
        );
        let tz = denver();
        let p = SlotParams {
            duration_mins: 60,
            ..params(&availability, tz)
        };
        let slots = compute_slots(
            &p,
            date("2026-03-08"),
            date("2026-03-08"),
            &[],
            &HashMap::new(),
        );

        // 01:00 MST = 08:00 UTC. The wall clock jumps 02:00->03:00, so the
        // window is 2 real hours (01:00 MST, 03:00 MDT): exactly 2 slots.
        let one_am = resolve_local(tz, date("2026-03-08").and_time("01:00:00".parse().unwrap()));
        assert_eq!(slots.len(), 2, "{slots:?}");
        assert_eq!(slots[0].start, one_am);
        assert_eq!(
            slots[1].start,
            one_am + 3_600,
            "02:00 resolves past the gap"
        );

        // resolve_local on a nonexistent time lands at the first valid
        // instant: 03:00 MDT, which is only ONE real hour after 01:00 MST.
        let gap = resolve_local(tz, date("2026-03-08").and_time("02:30:00".parse().unwrap()));
        assert_eq!(gap, one_am + 3_600, "02:30 -> 03:00 MDT");
    }

    #[test]
    fn dst_fall_back_ambiguity() {
        // US DST 2026 ends Sunday 2026-11-01 02:00 local: 01:00-02:00 happens
        // twice. Rule: earliest instant. Window 00:00-03:00 with 60-min slots:
        // wall-clock hours 00,01,02 = 3 slots, and the 01:00 slot is the MDT
        // (earlier) instant. No duplicate starts.
        let mut availability = business_hours();
        availability.overrides.insert(
            "2026-11-01".into(),
            vec![TimeWindow {
                start: "00:00".into(),
                end: "03:00".into(),
            }],
        );
        let tz = denver();
        let p = SlotParams {
            duration_mins: 60,
            ..params(&availability, tz)
        };
        let slots = compute_slots(
            &p,
            date("2026-11-01"),
            date("2026-11-01"),
            &[],
            &HashMap::new(),
        );

        let midnight = resolve_local(tz, date("2026-11-01").and_time(NaiveTime::MIN));
        assert_eq!(slots.len(), 3, "{slots:?}");
        assert_eq!(slots[0].start, midnight);
        assert_eq!(slots[1].start, midnight + 3_600, "01:00 = earliest (MDT)");
        let starts: std::collections::HashSet<i64> = slots.iter().map(|s| s.start).collect();
        assert_eq!(starts.len(), slots.len(), "no duplicate slot instants");

        // local_day_bounds spans 25 real hours on fall-back day.
        let (lo, hi) = local_day_bounds(tz, date("2026-11-01"));
        assert_eq!(hi - lo, 25 * 3_600);
    }
}
