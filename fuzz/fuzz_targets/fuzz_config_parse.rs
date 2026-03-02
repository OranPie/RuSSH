#![no_main]

use libfuzzer_sys::fuzz_target;
use russh_config::parse_config;

fuzz_target!(|data: &[u8]| {
    // parse_config takes a &str, so convert bytes to string
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = parse_config(s);
    }
});
