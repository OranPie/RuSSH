#![no_main]

use libfuzzer_sys::fuzz_target;
use russh_core::PacketCodec;

fuzz_target!(|data: &[u8]| {
    let codec = PacketCodec::with_defaults();
    // Try to decode arbitrary bytes — must never panic, only return errors
    let _ = codec.decode(data);
});
