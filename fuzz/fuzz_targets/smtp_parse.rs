#![no_main]

use libfuzzer_sys::fuzz_target;
use smtp_proto::request::receiver::RequestReceiver;

fuzz_target!(|data: &[u8]| {
    // Try to parse arbitrary bytes as SMTP requests.
    // The parser should never panic on any input.
    let mut receiver = RequestReceiver::new();
    let _ = receiver.parse(data);
});
