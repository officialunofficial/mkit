#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    mkit_primitives_fuzz::closure_pages::replay(data);
});
