//! Partition → Durable Object routing (D34): one Durable Object instance per
//! [`Partition`], one Durable Object class per shard kind.
//!
//! M0 serves one partition, `Partition::Namespace(root)`, from the
//! `REFSTORE` binding's `"root"` instance: the name vcs-worker's `RefStore`
//! already uses (planner default Q13), so no Durable Object migration is
//! needed. The other kinds are reserved for D34; WP-1.8 adds their
//! bindings, and WP-4.10a wires the content shards.

use mkit_server::{NamespaceKey, Partition, StoreError};

/// The M0 binding: vcs-worker's `RefStore` class.
pub const REFSTORE: &str = "REFSTORE";
/// D34 namespace coordinators (WP-1.8).
pub const NS_COORD: &str = "NS_COORD";
/// D34 ref shards (WP-1.8).
pub const REF_SHARD: &str = "REF_SHARD";
/// D34 repo and ref-name index shards (WP-1.8).
pub const REPO_INDEX: &str = "REPO_INDEX";
/// Global `ContentIndex` shards (WP-4.10a).
pub const CONTENT_INDEX: &str = "CONTENT_INDEX";

/// The instance name of the deployment-default namespace.
pub const ROOT_INSTANCE: &str = "root";

/// Where a partition lives: a Durable Object binding and an instance name
/// (`idFromName`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DoTarget {
    /// The Durable Object namespace binding.
    pub binding: &'static str,
    /// The instance name.
    pub name: String,
}

/// Where new Durable Objects are created. A Durable Object is pinned near
/// its first access; a hint or jurisdiction applies only then. M0 passes
/// none; WP-1.8 exposes it as a namespace-creation option.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Placement {
    /// A `locationHint` such as `"weur"`.
    pub location_hint: Option<String>,
    /// A jurisdiction such as `"eu"`: its instances run and store data only
    /// there.
    pub jurisdiction: Option<String>,
}

/// The Durable Object that holds `p`.
///
/// # Errors
/// [`StoreError::Invalid`] for a name component holding `\n` (the component
/// separator, so names stay injective); [`StoreError::Unsupported`] for a
/// partition kind this adapter does not know yet.
pub fn do_target(p: &Partition) -> Result<DoTarget, StoreError> {
    let target = |binding, name| Ok(DoTarget { binding, name });
    match p {
        Partition::Namespace(ns) if *ns == NamespaceKey::deployment_default() => {
            target(REFSTORE, ROOT_INSTANCE.to_owned())
        }
        Partition::Namespace(ns) => target(REFSTORE, join("n:", &[ns.as_str()])?),
        Partition::Coordinator(ns) => target(NS_COORD, join("c:", &[ns.as_str()])?),
        Partition::Ref {
            ns,
            repo,
            shard_ref,
        } => target(
            REF_SHARD,
            join("r:", &[ns.as_str(), repo.as_str(), shard_ref])?,
        ),
        Partition::RepoIndex { ns, repo, prefix } => target(
            REPO_INDEX,
            join("i:", &[ns.as_str(), repo.as_str(), &prefix.to_string()])?,
        ),
        Partition::RefIndex { ns, repo, bucket } => target(
            REPO_INDEX,
            join("x:", &[ns.as_str(), repo.as_str(), &bucket.to_string()])?,
        ),
        Partition::ContentShard(shard) => target(CONTENT_INDEX, format!("ci:{shard:03x}")),
        _ => Err(StoreError::Unsupported(
            "no Durable Object class for this partition kind".into(),
        )),
    }
}

/// `prefix` then the components joined by `\n`.
fn join(prefix: &str, parts: &[&str]) -> Result<String, StoreError> {
    if parts.iter().any(|part| part.contains('\n')) {
        return Err(StoreError::Invalid(
            "partition component contains a newline".into(),
        ));
    }
    Ok(format!("{prefix}{}", parts.join("\n")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(bytes: &[u8]) -> Partition {
        Partition::decode(bytes).unwrap()
    }

    fn target(p: &[u8]) -> (&'static str, String) {
        let t = do_target(&decode(p)).unwrap();
        (t.binding, t.name)
    }

    #[test]
    fn default_namespace_maps_to_root_and_others_are_prefixed() {
        let root = Partition::Namespace(NamespaceKey::deployment_default());
        assert_eq!(
            do_target(&root).unwrap(),
            DoTarget {
                binding: REFSTORE,
                name: "root".into()
            }
        );
        let cases: [(&[u8], &str, &str); 7] = [
            (b"nother\0", REFSTORE, "n:other"),
            (b"croot\0", NS_COORD, "c:root"),
            (
                b"rroot\0a\0refs/heads/main\0",
                REF_SHARD,
                "r:root\na\nrefs/heads/main",
            ),
            (b"iroot\0a\x004095\0", REPO_INDEX, "i:root\na\n4095"),
            (b"xroot\0a\x0015\0", REPO_INDEX, "x:root\na\n15"),
            (b"s7\0", CONTENT_INDEX, "ci:007"),
            (b"s4095\0", CONTENT_INDEX, "ci:fff"),
        ];
        for (encoded, binding, name) in cases {
            assert_eq!(target(encoded), (binding, name.to_owned()), "{encoded:?}");
        }
        // A namespace that merely looks like the instance name stays
        // prefixed: only the deployment default is "root".
        assert_eq!(target(b"nn:root\0").1, "n:n:root");
        let newline = decode(b"rroot\0a\0refs/heads/x\ny\0");
        assert!(matches!(do_target(&newline), Err(StoreError::Invalid(_))));
        assert_eq!(Placement::default().location_hint, None);
        assert_eq!(Placement::default().jurisdiction, None);
    }
}
