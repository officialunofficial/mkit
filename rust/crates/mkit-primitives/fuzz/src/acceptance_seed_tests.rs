//! Stable replay uses the same target body as libFuzzer.
#[test]
fn acceptance_seed_replay() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/acceptance");
    let mut count = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|ext| ext == "bin") {
            crate::acceptance::exercise(&std::fs::read(path).unwrap());
            count += 1;
        }
    }
    assert_eq!(count, 49);
    // Deterministic arbitrary bytes exercise the same bounded target path.
    let mut state = 0x8f32_0417_u32;
    for length in 0..512 {
        let mut bytes = vec![0; length];
        for byte in &mut bytes {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *byte = state.to_le_bytes()[0];
        }
        crate::acceptance::exercise(&bytes);
    }
}
