//! Differential-test vector exporter for the Lean model of
//! `docs/specs/SPEC-DELTA.md` (Linear MKIT-25, `formal/lean/`).
//!
//! Writes golden and seeded-random base/target pairs to a text file: per case
//! the base, the target, the Rust writer's stream (`delta::encode`), and a
//! list of `A` lines — a stream (the writer's, or a mutated / malformed one),
//! the base it is applied to, and the Rust reader's verdict
//! (`delta::decode`: output bytes, or the error kind). The Lean
//! `delta_difftest` executable (`formal/lean/scripts/difftest-delta.sh`)
//! re-applies every stream with the model of SPEC-DELTA §4 and fails on any
//! disagreement in acceptance, output bytes or error kind; it also checks the
//! writer's stream decodes, re-encodes byte-identically, and equals the Lean
//! model of the Rust writer.
//!
//! Ignored by default (it writes a multi-MB file):
//! `cargo test -p mkit-core --test formal_delta_vectors -- --ignored`.
//! Env: `MKIT_FORMAL_DELTA_OUT` (output path, default under
//! `CARGO_TARGET_TMPDIR`), `MKIT_FORMAL_SEED` (u64), `MKIT_FORMAL_DELTA_CASES`
//! (random case count).
#![allow(clippy::unwrap_used)]
// unwrap is the assertion in test helpers
// Vector generation: small lengths by construction; `rng.next() as u32` is a
// deliberate truncation of random bits.
#![allow(clippy::cast_possible_truncation, clippy::too_many_lines)]

use std::fmt::Write as _;
use std::path::PathBuf;

use mkit_core::DeltaCorruption;
use mkit_core::delta;
use mkit_core::object::MkitError;

/// splitmix64: deterministic, dependency-free.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % (n as u64)).unwrap()
    }
    fn byte(&mut self) -> u8 {
        self.next().to_le_bytes()[0]
    }
    fn bytes(&mut self, n: usize, alphabet: u8) -> Vec<u8> {
        (0..n)
            .map(|_| {
                if alphabet == 0 {
                    self.byte()
                } else {
                    self.byte() % alphabet
                }
            })
            .collect()
    }
}

fn hexd(b: &[u8]) -> String {
    if b.is_empty() {
        "-".to_owned()
    } else {
        hex::encode(b)
    }
}

/// The Rust verdict, in the error vocabulary of the Lean model (`Err`).
fn verdict(r: Result<Vec<u8>, MkitError>) -> String {
    let kind = match r {
        Ok(v) => return format!("OK {}", hexd(&v)),
        Err(MkitError::UnexpectedEof) => "eof",
        Err(MkitError::UnsupportedObjectVersion) => "unsupported_version",
        Err(MkitError::DeltaCorrupt(k)) => match k {
            DeltaCorruption::BaseLenMismatch { .. } => "base_len_mismatch",
            DeltaCorruption::ReservedOpcodeBits(_) => "reserved_opcode_bits",
            DeltaCorruption::ZeroOpcode => "zero_opcode",
            DeltaCorruption::ZeroLengthCopy => "zero_length_copy",
            DeltaCorruption::CopyPastBase { .. } => "copy_past_base",
            DeltaCorruption::ResultLenOverrun { .. } => "result_len_overrun",
            DeltaCorruption::ResultLenUnderrun { .. } => "result_len_underrun",
            other => panic!("unmapped DeltaCorruption {other:?}"),
        },
        Err(e) => panic!("delta::decode returned an unexpected error {e:?}"),
    };
    format!("ERR {kind}")
}

/// Offsets of instruction starts in a well-formed stream (plus the end).
fn boundaries(s: &[u8]) -> Vec<usize> {
    let mut v = vec![];
    let mut p = delta::HEADER_LEN;
    while p < s.len() {
        v.push(p);
        p += if s[p] & 0x80 != 0 {
            7
        } else {
            1 + s[p] as usize
        };
    }
    v.push(s.len());
    v
}

fn set_u32(s: &mut [u8], at: usize, v: u32) {
    s[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn get_u32(s: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(s[at..at + 4].try_into().unwrap())
}

fn copy_op(off: u32, len: u16) -> Vec<u8> {
    let mut v = vec![0x80];
    v.extend_from_slice(&off.to_le_bytes());
    v.extend_from_slice(&len.to_le_bytes());
    v
}

struct Out(String);

impl Out {
    fn apply(&mut self, tag: &str, base: &[u8], case_base: &[u8], s: &[u8]) {
        let b = if base == case_base {
            "=".to_owned()
        } else {
            hexd(base)
        };
        let v = verdict(delta::decode(base, s));
        writeln!(self.0, "A {tag} {b} {} {v}", hexd(s)).unwrap();
    }

    fn case(&mut self, rng: &mut Rng, name: &str, base: &[u8], target: &[u8], mutants: usize) {
        let enc = delta::encode(base, target).unwrap();
        assert_eq!(delta::decode(base, &enc).unwrap(), target, "{name}");
        writeln!(self.0, "CASE {name}").unwrap();
        writeln!(self.0, "BASE {}", hexd(base)).unwrap();
        writeln!(self.0, "TARGET {}", hexd(target)).unwrap();
        writeln!(self.0, "ENC {}", hexd(&enc)).unwrap();
        self.apply("enc", base, base, &enc);
        let bl = u32::try_from(base.len()).unwrap();
        let rl = u32::try_from(target.len()).unwrap();
        for _ in 0..mutants {
            let bs = boundaries(&enc);
            let at = bs[rng.below(bs.len())];
            let mut s = enc.clone();
            let tag = match rng.below(17) {
                0 => {
                    let i = rng.below(s.len());
                    s[i] ^= 1 + rng.byte() % 255;
                    "flip"
                }
                1 => {
                    s.truncate(rng.below(s.len() + 1));
                    "trunc"
                }
                2 => {
                    let n = 1 + rng.below(10);
                    s.extend(rng.bytes(n, 0));
                    "extend"
                }
                3 => {
                    s[0] = loop {
                        let v = rng.byte();
                        if v != 1 {
                            break v;
                        }
                    };
                    "version"
                }
                4 => {
                    let d = if rng.below(2) == 0 { 1 } else { u32::MAX };
                    set_u32(&mut s, 1, bl.wrapping_add(d));
                    "base_len"
                }
                5 => {
                    // Right stream, wrong base (one byte longer or shorter).
                    let mut b2 = base.to_vec();
                    if b2.is_empty() || rng.below(2) == 0 {
                        b2.push(rng.byte());
                    } else {
                        b2.pop();
                    }
                    self.apply("other_base", &b2, base, &s);
                    continue;
                }
                6 => {
                    let d = if rng.below(2) == 0 { 1 } else { u32::MAX };
                    set_u32(&mut s, 5, rl.wrapping_add(d));
                    "result_len"
                }
                7 => {
                    s.insert(at, 0);
                    "zero_op"
                }
                8 => {
                    let mut op = copy_op(0, 1);
                    op[0] = 0x81 + rng.byte() % 0x7f;
                    s.splice(at..at, op);
                    "reserved"
                }
                9 => {
                    s.splice(at..at, copy_op(rng.next() as u32, 0));
                    "zero_len_copy"
                }
                10 => {
                    // COPY ending 1..=4 bytes past the base; result_len adjusted.
                    let len = 1 + rng.below(8);
                    let past = 1 + rng.below(4);
                    let off = (base.len() + past).saturating_sub(len);
                    s.splice(at..at, copy_op(off as u32, len as u16));
                    set_u32(&mut s, 5, rl + len as u32);
                    "copy_past"
                }
                11 => {
                    s.splice(at..at, copy_op(u32::MAX - rng.below(3) as u32, u16::MAX));
                    "copy_huge"
                }
                12 => {
                    // In-bounds COPY, result_len adjusted or not.
                    if base.is_empty() {
                        continue;
                    }
                    let off = rng.below(base.len());
                    let len = 1 + rng.below(base.len() - off);
                    s.splice(at..at, copy_op(off as u32, len as u16));
                    if rng.below(2) == 0 {
                        set_u32(&mut s, 5, rl + len as u32);
                        "copy_ok"
                    } else {
                        "copy_overrun"
                    }
                }
                13 => {
                    let n = 1 + rng.below(127);
                    let mut ins = vec![u8::try_from(n).unwrap()];
                    ins.extend(rng.bytes(n, 0));
                    s.splice(at..at, ins);
                    if rng.below(2) == 0 {
                        set_u32(&mut s, 5, rl + n as u32);
                        "insert_ok"
                    } else {
                        "insert_overrun"
                    }
                }
                14 => {
                    // Drop one instruction and fix result_len: accepted, different bytes.
                    if bs.len() < 2 {
                        continue;
                    }
                    let k = rng.below(bs.len() - 1);
                    let (a, b) = (bs[k], bs[k + 1]);
                    let dropped = if s[a] & 0x80 != 0 {
                        u32::from(u16::from_le_bytes([s[a + 5], s[a + 6]]))
                    } else {
                        u32::from(s[a])
                    };
                    s.drain(a..b);
                    let rl2 = get_u32(&s, 5) - dropped;
                    set_u32(&mut s, 5, rl2);
                    "drop_instr"
                }
                15 => {
                    s.truncate(delta::HEADER_LEN);
                    let n = rng.below(24);
                    s.extend(rng.bytes(n, 0));
                    "random_tail"
                }
                _ => {
                    let n = rng.below(24);
                    s = rng.bytes(n, 0);
                    "random"
                }
            };
            self.apply(tag, base, base, &s);
        }
        self.0.push_str("END\n");
    }
}

/// A target derived from `base` by a few random edits.
fn edit(rng: &mut Rng, base: &[u8], alphabet: u8) -> Vec<u8> {
    let mut t = base.to_vec();
    for _ in 0..rng.below(6) {
        let p = rng.below(t.len() + 1);
        match rng.below(4) {
            0 => {
                let n = rng.below(300);
                let ins = rng.bytes(n, alphabet);
                t.splice(p..p, ins);
            }
            1 => {
                let e = (p + rng.below(200)).min(t.len());
                t.drain(p..e);
            }
            2 => {
                let e = (p + rng.below(64)).min(t.len());
                for b in &mut t[p..e] {
                    *b = b.wrapping_add(1);
                }
            }
            _ => {
                // Duplicate a chunk of the base elsewhere.
                let s = rng.below(base.len() + 1);
                let e = (s + rng.below(400)).min(base.len());
                t.splice(p..p, base[s..e].iter().copied());
            }
        }
    }
    t
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key).ok().map_or(default, |v| {
        let v = v.trim();
        v.strip_prefix("0x").map_or_else(
            || v.parse().unwrap(),
            |h| u64::from_str_radix(h, 16).unwrap(),
        )
    })
}

#[test]
#[ignore = "writes the Lean differential-test vectors; run via formal/lean/scripts/difftest-delta.sh"]
fn export_formal_delta_vectors() {
    let seed = env_u64("MKIT_FORMAL_SEED", 0x006d_6b69_742d_3235);
    let cases = env_u64("MKIT_FORMAL_DELTA_CASES", 400);
    let path = std::env::var("MKIT_FORMAL_DELTA_OUT").map_or_else(
        |_| PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("formal_delta_vectors.txt"),
        PathBuf::from,
    );
    let mut rng = Rng(seed);
    let mut out = Out(format!("MKIT-DELTA-VECTORS 1 seed={seed:#x}\n"));

    // Golden: SPEC-DELTA §8 vectors 1-3, empty sides, INSERT split points
    // (§3.2: 127-byte literals), and a COPY longer than u16::MAX (§3.1 cap).
    let pat: Vec<u8> = b"0123456789abcdef".repeat(4);
    out.case(&mut rng, "golden-identity", &pat, &pat, 40);
    out.case(&mut rng, "golden-pure-insert", b"aaa", b"zzz", 40);
    let p16: Vec<u8> = (0..16).collect();
    out.case(&mut rng, "golden-pure-copy", &p16, &p16, 40);
    out.case(&mut rng, "golden-empty-both", b"", b"", 20);
    out.case(&mut rng, "golden-empty-target", &p16, b"", 20);
    out.case(&mut rng, "golden-empty-base", b"", b"xyz", 20);
    for n in [126usize, 127, 128, 254, 255, 256, 381] {
        let t = rng.bytes(n, 0);
        out.case(&mut rng, &format!("golden-literal-{n}"), &p16, &t, 10);
    }
    let big = rng.bytes(70_000, 0);
    out.case(&mut rng, "golden-long-copy", &big, &big, 12);
    let mut big2 = big.clone();
    big2[35_000] ^= 0xff;
    big2.truncate(69_000);
    out.case(&mut rng, "golden-long-copy-edit", &big, &big2, 12);

    for c in 0..cases {
        let alphabet = [0u8, 0, 2, 4][rng.below(4)];
        let blen = rng.below(1500);
        let base = rng.bytes(blen, alphabet);
        let (kind, target) = match rng.below(5) {
            0 | 1 => ("edit", edit(&mut rng, &base, alphabet)),
            2 => {
                let n = rng.below(1500);
                ("fresh", rng.bytes(n, alphabet))
            }
            3 => ("same", base.clone()),
            _ => {
                // Rearranged 16-byte-aligned blocks of the base.
                let mut t = vec![];
                for _ in 0..rng.below(8) {
                    let s = rng.below(base.len() + 1);
                    let e = (s + rng.below(300)).min(base.len());
                    t.extend_from_slice(&base[s..e]);
                }
                ("shuffle", t)
            }
        };
        out.case(&mut rng, &format!("random-{c}-{kind}"), &base, &target, 12);
    }

    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).unwrap();
    }
    std::fs::write(&path, out.0).unwrap();
    eprintln!("wrote {}", path.display());
}
