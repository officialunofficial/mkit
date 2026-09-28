// -*- mode: Bluespec; -*-
// Requested transport identities are checked before effects (Linear MKIT-26,
// epic MKIT-17, workstream quint-transport).
//
// INVARIANTS.md "Requested transport identities are checked before effects":
// fetched packs and metadata match their requested keys; shard manifests name
// the requested pack before reconstruction; a substituted response that is
// internally valid is never published. Spec: SPEC-PACK-SHARDS §2 (the
// requested PackKey is the root of trust: compare `manifest.pack_hash` with it
// before requesting any shard, verify the reconstructed pack against it), §3
// (shard hashes are checked against the manifest), §4.2 steps 2c and 5,
// §7 "A self-consistent substitute shard set is detected".
//
// Pipeline modelled, as of this branch (one fetch of one branch):
//   1. packlist node: `packmap::download_packlist_node` downloads the chain
//      head by key (`Transport::download_blob`) and checks
//      `requested.verify_bytes` BEFORE decoding; the decoded node names the
//      pack to fetch.
//   2. pack: `packmap::fetch_packs` calls `Transport::download_pack(key)`.
//      The server decides the delivery mode (HTTP: an `X-Pack-Shards`
//      advertisement, malformed -> monolithic re-issue; S3: a manifest,
//      `404` -> monolithic key), so the adversary chooses it:
//      - monolithic: the transport returns the body unchecked;
//      - sharded (`download_pack_via_shards`, HTTP and S3 alike): T1 compare
//        `manifest.pack_hash` with the requested key before any shard
//        request (shard URLs are derived from the requested key, not the
//        manifest); `download_shards`; then `decode_downloaded_pack`: T2 the
//        same manifest check again, the per-shard BLAKE3 check against the
//        manifest (§4.2 2c), reconstruction, step 5 (pack hashes to
//        `manifest.pack_hash`) and T3 `key.verify_bytes(&pack)`.
//   3. consumer: C1 `key.verify_bytes(&pack)` before staging; C2 the same
//      check again on the staged bytes in `unpack_downloaded_packs`, before
//      `PackReader::read` stores objects (the publication effect).
//
// Adversary: the server (or anything on the path) answers every request with
// any INTERNALLY VALID object of the universe: a real packlist node of another
// branch, a real pack under another key, a consistent manifest + shard set of
// another pack, a manifest naming the requested pack but committing to another
// pack's shards, or shards from a different set. BLAKE3 is abstracted to the
// identity on contents (collision resistance assumed): an object's key IS its
// name here. Malformed bytes are not modelled: decoders reject them before any
// identity question arises (Kani / fuzz / unit tests cover the codecs).
//
// Checks: ./check.sh (README.md lists each command and its expected outcome).
module identityCore {
  // Mutation switches: each removes one check of the pipeline above.
  type IFaults = {
    nodeNoVerify: bool,         // packlist node decoded without verify_bytes
    noManifestPrecheck: bool,   // T1 skipped: shards requested before the manifest check
    noDecodeManifestCheck: bool,// T2 skipped
    noPostDecodeCheck: bool,    // step 5 and T3 skipped
    consumerNoVerify: bool,     // C1 and C2 skipped
  }

  const FAULTS: IFaults

  pure val REQ_NODE: str = "nA"                       // the branch's packlist head (requested)
  pure val NODES: Set[str] = Set("nA", "nB")          // nB: a real node of another branch
  pure val PACKS: Set[str] = Set("pA", "pB", "pC")
  pure val LISTS: str -> str = Map("nA" -> "pA", "nB" -> "pB")  // the pack each node names
  // Everything reachable from the requested head, and nothing else.
  pure val CLOSURE: Set[str] = Set("nA", "pA")
  pure val NOFAULTS: IFaults = {
    nodeNoVerify: false, noManifestPrecheck: false, noDecodeManifestCheck: false,
    noPostDecodeCheck: false, consumerNoVerify: false,
  }

  // --------------------------------------------------------------- state
  var phase: str        // node | pack | shards | stage | unpack | done | rejected
  var decodedNode: str  // node whose listing the consumer followed ("" before)
  var packKey: str      // the pack key the consumer requested ("" before)
  var manifest: { ph: str, so: str }  // pack_hash; the pack whose shards/commitment it lists
  var got: str          // pack bytes currently held by the consumer
  var via: str          // mono | shards
  var published: Set[str]
  // ghosts: effect logs, each (requested key, what the effect was for)
  var shardReqs: Set[(str, str)]      // (key, manifest.pack_hash) when shards were requested
  var recons: Set[(str, str)]         // (key, manifest.pack_hash) when a pack was reconstructed
  var shardReturns: Set[(str, str)]   // (key, returned pack) from the sharded transport path
  var pubLog: Set[(str, str)]         // (key, published pack)
  var substituted: bool               // some response differed from the requested object
  var publishedVia: Set[str]
  var faults: IFaults
  var lastAction: str

  action initWith(f: IFaults): bool = all {
    phase' = "node", decodedNode' = "", packKey' = "", manifest' = { ph: "", so: "" },
    got' = "", via' = "", published' = Set(), shardReqs' = Set(), recons' = Set(),
    shardReturns' = Set(), pubLog' = Set(), substituted' = false, publishedVia' = Set(),
    faults' = f, lastAction' = "init",
  }
  action init = initWith(FAULTS)

  action keepLogs = all {
    shardReqs' = shardReqs, recons' = recons, shardReturns' = shardReturns, pubLog' = pubLog,
    published' = published, publishedVia' = publishedVia, faults' = faults,
  }

  // 1. The server answers the packlist-node request with node `c`.
  action serveNode(c: str): bool = all {
    phase == "node",
    val ok = faults.nodeNoVerify or c == REQ_NODE
    all {
      phase' = if (ok) "pack" else "rejected",
      decodedNode' = if (ok) c else "",
      packKey' = if (ok) LISTS.get(c) else "",
      substituted' = (substituted or (c != REQ_NODE)),
      manifest' = manifest, got' = got, via' = via, keepLogs, lastAction' = "serveNode",
    }
  }

  // 2a. Monolithic answer `c` (the transport returns it unchecked).
  action serveMono(c: str): bool = all {
    phase == "pack",
    phase' = "stage", got' = c, via' = "mono",
    substituted' = (substituted or (c != packKey)),
    decodedNode' = decodedNode, packKey' = packKey, manifest' = manifest, keepLogs,
    lastAction' = "serveMono",
  }

  // 2b. Shard mode: the manifest answer names pack `ph` and lists the shard
  // hashes / commitment of pack `so`. T1 runs before any shard request.
  action serveManifest(ph: str, so: str): bool = all {
    phase == "pack",
    val ok = faults.noManifestPrecheck or ph == packKey
    all {
      phase' = if (ok) "shards" else "rejected",
      manifest' = { ph: ph, so: so }, via' = "shards",
      substituted' = (substituted or (ph != packKey) or (so != packKey)),
      decodedNode' = decodedNode, packKey' = packKey, got' = got, keepLogs,
      lastAction' = "serveManifest",
    }
  }

  // 2b cont. Shards are requested (from URLs derived from the requested key)
  // and answered from shard set `s` ("mixed": not all from one set), then
  // decode_downloaded_pack runs T2, 2c, reconstruction, step 5 and T3.
  action serveShards(s: str): bool = all {
    phase == "shards",
    val t2 = faults.noDecodeManifestCheck or manifest.ph == packKey
    val hashesOk = s == manifest.so               // §4.2 2c against manifest.shard_hashes
    val pack = manifest.so                        // reconstruction yields the committed pack
    val step5 = faults.noPostDecodeCheck or pack == manifest.ph
    val t3 = faults.noPostDecodeCheck or pack == packKey
    val reconstructed = t2 and hashesOk
    val returned = reconstructed and step5 and t3
    all {
      shardReqs' = shardReqs.union(Set((packKey, manifest.ph))),
      recons' = if (reconstructed) recons.union(Set((packKey, manifest.ph))) else recons,
      shardReturns' = if (returned) shardReturns.union(Set((packKey, pack))) else shardReturns,
      phase' = if (returned) "stage" else "rejected",
      got' = if (returned) pack else "",
      substituted' = (substituted or (s != packKey)),
      decodedNode' = decodedNode, packKey' = packKey, manifest' = manifest, via' = via,
      published' = published, publishedVia' = publishedVia, pubLog' = pubLog, faults' = faults,
      lastAction' = "serveShards",
    }
  }

  // 3. C1 before staging.
  action stage: bool = all {
    phase == "stage",
    phase' = if (faults.consumerNoVerify or got == packKey) "unpack" else "rejected",
    decodedNode' = decodedNode, packKey' = packKey, manifest' = manifest, got' = got,
    via' = via, substituted' = substituted, keepLogs, lastAction' = "stage",
  }

  // 3. C2, then PackReader::read stores the objects (the publication effect).
  action unpack: bool = all {
    phase == "unpack",
    val ok = faults.consumerNoVerify or got == packKey
    all {
      phase' = if (ok) "done" else "rejected",
      published' = if (ok) published.union(Set(got)) else published,
      pubLog' = if (ok) pubLog.union(Set((packKey, got))) else pubLog,
      publishedVia' = if (ok) publishedVia.union(Set(via)) else publishedVia,
      decodedNode' = decodedNode, packKey' = packKey, manifest' = manifest, got' = got,
      via' = via, substituted' = substituted, shardReqs' = shardReqs, recons' = recons,
      shardReturns' = shardReturns, faults' = faults, lastAction' = "unpack",
    }
  }

  action step = any {
    { nondet c = NODES.oneOf() serveNode(c) },
    { nondet c = PACKS.oneOf() serveMono(c) },
    { nondet ph = PACKS.oneOf() nondet so = PACKS.oneOf() serveManifest(ph, so) },
    { nondet s = PACKS.union(Set("mixed")).oneOf() serveShards(s) },
    stage,
    unpack,
  }

  // --------------------------------------------------------------- safety
  // Metadata: the followed packlist node is the requested one.
  val NodeMatchesRequest: bool = decodedNode == "" or decodedNode == REQ_NODE
  // No shard is requested under a manifest that names another pack (T1).
  val ShardsOnlyForRequestedManifest: bool = shardReqs.forall(((k, ph)) => ph == k)
  // No reconstruction under a manifest that names another pack.
  val ReconstructOnlyForRequested: bool = recons.forall(((k, ph)) => ph == k)
  // The sharded transport returns only the requested pack (§2).
  val ShardPathReturnsRequested: bool = shardReturns.forall(((k, p)) => p == k)
  // Every published pack is the one requested for it.
  val PackMatchesRequest: bool = pubLog.forall(((k, p)) => p == k)
  // Nothing outside the requested head's closure is ever published.
  val PublishedWithinRequestedClosure: bool = published.subseteq(CLOSURE)
  val Safety: bool = and {
    NodeMatchesRequest, ShardsOnlyForRequestedManifest, ReconstructOnlyForRequested,
    ShardPathReturnsRequested, PackMatchesRequest, PublishedWithinRequestedClosure,
  }

  // --------------------------------------------------------------- canaries
  val CanaryNoPublish: bool = published == Set()
  val CanaryNoShardPublish: bool = not(publishedVia.contains("shards"))
  val CanaryNoMonoPublish: bool = not(publishedVia.contains("mono"))
  // A substitution happened and was rejected (fail closed: no retry exists,
  // so a substituted fetch never publishes anything).
  val CanaryNoSubstitutionRejected: bool = not(substituted and phase == "rejected")
  val CanaryNoReject: bool = phase != "rejected"
}

module identity {
  import identityCore(FAULTS = { nodeNoVerify: false, noManifestPrecheck: false,
    noDecodeManifestCheck: false, noPostDecodeCheck: false, consumerNoVerify: false }).*
}
module identity_nodeNoVerify {          // NodeMatchesRequest, PublishedWithinRequestedClosure
  import identityCore(FAULTS = { nodeNoVerify: true, noManifestPrecheck: false,
    noDecodeManifestCheck: false, noPostDecodeCheck: false, consumerNoVerify: false }).*
}
module identity_noManifestPrecheck {    // ShardsOnlyForRequestedManifest (reconstruction still guarded by T2)
  import identityCore(FAULTS = { nodeNoVerify: false, noManifestPrecheck: true,
    noDecodeManifestCheck: false, noPostDecodeCheck: false, consumerNoVerify: false }).*
}
module identity_noManifestChecks {      // ReconstructOnlyForRequested
  import identityCore(FAULTS = { nodeNoVerify: false, noManifestPrecheck: true,
    noDecodeManifestCheck: true, noPostDecodeCheck: false, consumerNoVerify: false }).*
}
module identity_noPostDecodeCheck {     // ShardPathReturnsRequested (publication still guarded by C1/C2)
  import identityCore(FAULTS = { nodeNoVerify: false, noManifestPrecheck: false,
    noDecodeManifestCheck: false, noPostDecodeCheck: true, consumerNoVerify: false }).*
}
module identity_consumerNoVerify {      // PackMatchesRequest, PublishedWithinRequestedClosure
  import identityCore(FAULTS = { nodeNoVerify: false, noManifestPrecheck: false,
    noDecodeManifestCheck: false, noPostDecodeCheck: false, consumerNoVerify: true }).*
}
module identity_noPackChecks {         // PackMatchesRequest via the shard path too (T3 and C1/C2 both off)
  import identityCore(FAULTS = { nodeNoVerify: false, noManifestPrecheck: false,
    noDecodeManifestCheck: false, noPostDecodeCheck: true, consumerNoVerify: true }).*
}
