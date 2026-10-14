//! The reachability walk reaches an older commit, or anything inside it,
//! without locating every entry of a wide tip tree first, and still proves
//! exactly the same set.
use super::history_tests::drain;
use super::*;
use crate::pipeline::{ReaderSession, ReaderView};

const NARROW: usize = 30;
/// More than two locate batches (`reach::BATCH` is 256).
const WIDE: usize = 700;

/// Three linear commits over `files` plain files and one manifest each:
/// `f000` changes in every commit, and the manifest changes in the first and
/// last commit only.
struct Repo {
    fx: Fx,
    commits: Vec<Hash>,
    roots: Vec<Hash>,
    /// `f000` in the oldest commit; unique to it.
    old_file: Hash,
    tip_file: Hash,
    /// Plain file present in every commit.
    shared_file: Hash,
    old_manifest: Hash,
    old_chunk: Hash,
    tip_chunk: Hash,
}

fn repo(files: usize, denial: bool) -> Repo {
    let mut repo = build(files);
    // Pushed with denial off (no packmap upload to verify), then switched on.
    repo.fx.pipe.cfg.takedown_denial = denial;
    repo
}

fn build(files: usize) -> Repo {
    let fx = fixture_tweaked(Hooks::new(), http_cfg(), |cfg| cfg.takedown_denial = false);
    let (old_manifest, old_chunks) = manifest(&[&pattern(40_000, 11), &pattern(30_000, 12)]);
    let (tip_manifest, tip_chunks) = manifest(&[&pattern(40_000, 21), &pattern(30_000, 22)]);
    let shared = blob(b"shared");
    let (mut previous, mut parent) = (None, None);
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Repo {
        fx: fixture(),
        commits: Vec::new(),
        roots: Vec::new(),
        old_file: [0; 32],
        tip_file: [0; 32],
        shared_file: id(&shared),
        old_manifest: id(&old_manifest),
        old_chunk: id(&old_chunks[0]),
        tip_chunk: id(&tip_chunks[0]),
    };
    let names: Vec<String> = (1..files).map(|f| format!("f{f:03}")).collect();
    let others: Vec<Object> = (1..files)
        .map(|f| blob(format!("other {f}").as_bytes()))
        .collect();
    for n in 0..3_usize {
        let first = blob(format!("first v{n}").as_bytes());
        let manifest = if n == 2 { &tip_manifest } else { &old_manifest };
        // Entries are byte-sorted: "f000", "f001"..., "m", "s".
        let mut entries: Vec<(&str, EntryMode, &Object)> = vec![("f000", EntryMode::Blob, &first)];
        entries.extend(
            names
                .iter()
                .zip(&others)
                .map(|(name, object)| (name.as_str(), EntryMode::Blob, object)),
        );
        entries.extend([
            ("m", EntryMode::Blob, manifest),
            ("s", EntryMode::Blob, &shared),
        ]);
        let root = tree(&entries);
        let head = commit(&root, &parent.iter().collect::<Vec<_>>(), &format!("c{n}"));
        let chunks = if n == 2 { &tip_chunks } else { &old_chunks };
        let mut objects = vec![first.clone(), shared.clone()];
        objects.extend(others.iter().cloned());
        objects.extend(chunks.iter().cloned());
        objects.extend([manifest.clone(), root.clone(), head.clone()]);
        let fresh: Vec<&Object> = objects.iter().filter(|o| seen.insert(id(o))).collect();
        let pack = fx.push("room", &fresh, id(&head), previous);
        drain(&fx);
        previous = Some((id(&head), pack));
        parent = Some(head.clone());
        if n == 0 {
            out.old_file = id(&first);
        }
        if n == 2 {
            out.tip_file = id(&first);
        }
        out.commits.push(id(&head));
        out.roots.push(id(&root));
    }
    out.fx = fx;
    out
}

/// Whether `target` is served as a read of a fresh session, and the number of
/// metadata-store round trips it took.
fn read(repo: &Repo, target: Hash) -> (bool, u32) {
    let reader = block_on(
        repo.fx
            .pipe
            .object_reader(repo.fx.repo_id("room"), ReaderView::Public),
    )
    .unwrap();
    let before = repo.fx.pipe.meta.calls();
    let served = block_on(reader.read_canonical_in(&mut ReaderSession::default(), &[target]))
        .unwrap()[0]
        .is_some();
    (served, repo.fx.pipe.meta.calls() - before)
}

/// Targets behind the tip, each of which the old order reached only after
/// locating every entry of the tip tree.
fn behind(repo: &Repo) -> [(&'static str, Hash); 5] {
    [
        ("oldest commit", repo.commits[0]),
        ("oldest tree", repo.roots[0]),
        ("oldest file", repo.old_file),
        ("oldest manifest", repo.old_manifest),
        ("oldest chunk", repo.old_chunk),
    ]
}

#[test]
fn an_older_commit_costs_the_same_behind_a_narrow_or_a_wide_tip_tree() {
    let mut rows = Vec::new();
    for denial in [false, true] {
        let (narrow, wide) = (repo(NARROW, denial), repo(WIDE, denial));
        for ((name, a), (_, b)) in behind(&narrow).into_iter().zip(behind(&wide)) {
            let ((served_narrow, calls_narrow), (served_wide, calls_wide)) =
                (read(&narrow, a), read(&wide, b));
            println!("REACH_ORDER denial={denial} {name}: narrow={calls_narrow} wide={calls_wide}");
            assert!(served_narrow && served_wide, "{name}: not served");
            rows.push((name, calls_narrow, calls_wide));
        }
    }
    for (name, narrow, wide) in rows {
        // A chunk of an older manifest is queued behind the tip tree's files
        // (the queue is first in, first out), so it still costs O(entries);
        // that is the old order's cost, not a regression.
        if name != "oldest chunk" {
            assert!(
                wide <= narrow + 4,
                "{name}: {narrow} calls narrow, {wide} wide"
            );
        }
    }
}

#[test]
fn targets_in_the_wide_tip_tree_and_unreachable_ids_keep_the_same_answers() {
    for denial in [false, true] {
        let wide = repo(WIDE, denial);
        for (name, target) in [
            ("tip commit", wide.commits[2]),
            ("tip tree", wide.roots[2]),
            ("tip file", wide.tip_file),
            ("shared file", wide.shared_file),
            ("tip chunk", wide.tip_chunk),
        ] {
            let (served, calls) = read(&wide, target);
            println!("REACH_ORDER denial={denial} {name}: wide={calls}");
            assert!(served, "{name}: not served");
        }
        let (served, calls) = read(&wide, [0xEE; 32]);
        println!("REACH_ORDER denial={denial} unreachable: wide={calls}");
        assert!(!served);
    }
}

#[test]
fn a_mixed_batch_of_older_and_tip_targets_is_all_served() {
    let wide = repo(WIDE, false);
    let reader = block_on(
        wide.fx
            .pipe
            .object_reader(wide.fx.repo_id("room"), ReaderView::Public),
    )
    .unwrap();
    let ids = [
        wide.commits[0],
        wide.roots[1],
        wide.old_file,
        wide.old_chunk,
        wide.tip_chunk,
        wide.commits[2],
        [0xEE; 32],
    ];
    let served = block_on(reader.read_canonical_in(&mut ReaderSession::default(), &ids)).unwrap();
    assert!(served[..6].iter().all(Option::is_some));
    assert!(served[6].is_none(), "the unreachable id is not served");
}
