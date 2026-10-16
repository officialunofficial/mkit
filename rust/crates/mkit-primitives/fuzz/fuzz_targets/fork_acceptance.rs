#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    mkit_primitives_fuzz::fork::fuzz_fork_acceptance(data);
});
