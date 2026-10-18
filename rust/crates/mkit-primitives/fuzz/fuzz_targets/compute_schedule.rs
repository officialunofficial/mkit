#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| mkit_primitives_fuzz::compute_schedule(data));
