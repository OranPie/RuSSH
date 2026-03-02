#![no_main]

use libfuzzer_sys::fuzz_target;
use russh_auth::UserAuthMessage;
use russh_core::PacketCodec;

fuzz_target!(|data: &[u8]| {
    let codec = PacketCodec::with_defaults();
    // Try to parse a UserAuthMessage from arbitrary bytes — must never panic
    let _ = UserAuthMessage::decode(&codec, data);
});
