#![no_main]

use libfuzzer_sys::fuzz_target;
use sequoia_openpgp::cert::CertParser;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    // Try to parse arbitrary bytes as PGP certificates/keys.
    // The parser should never panic on any input.
    let cursor = Cursor::new(data);
    let parser = CertParser::from_reader(cursor);
    for _ in parser {
        // Just iterate; we don't care about results, only that it doesn't panic
    }
});
