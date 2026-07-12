#![no_main]

use libfuzzer_sys::fuzz_target;
use mail_parser::Message;

fuzz_target!(|data: &[u8]| {
    // Try to parse arbitrary bytes as MIME messages.
    // The parser should never panic on any input.
    let _ = Message::parse(data);
});
