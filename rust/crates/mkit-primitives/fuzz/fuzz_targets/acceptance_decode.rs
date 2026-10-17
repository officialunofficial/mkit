#![no_main]
libfuzzer_sys::fuzz_target!(|bytes: &[u8]| {
    mkit_primitives_fuzz::acceptance::exercise(bytes);
});
