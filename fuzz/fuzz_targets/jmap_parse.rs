#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    // Try to parse arbitrary bytes as JSON (JMAP requests are JSON).
    // The parser should never panic on any input.
    let _ = serde_json::from_slice::<Value>(data);
});
