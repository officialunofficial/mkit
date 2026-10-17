#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    mkit_primitives_fuzz::pair_checkpoint::replay(data);
});
