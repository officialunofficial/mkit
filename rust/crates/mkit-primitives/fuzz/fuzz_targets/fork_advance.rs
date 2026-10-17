#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    mkit_primitives_fuzz::fork_advance::fuzz_fork_advance(data);
});
