// -*- mode: Bluespec; -*-
// Pinned interleavings for identity.qnt (run by check.sh: `quint test`).
module identity_test {
  import identityCore(FAULTS = { nodeNoVerify: false, noManifestPrecheck: false,
    noDecodeManifestCheck: false, noPostDecodeCheck: false, consumerNoVerify: false }).* from "./identity"

  run honestMonolithicTest =
    initWith(FAULTS).then(serveNode("nA")).then(serveMono("pA")).then(stage).then(unpack)
      .expect(published == Set("pA") and Safety)

  run honestShardedTest =
    initWith(FAULTS).then(serveNode("nA")).then(serveManifest("pA", "pA")).then(serveShards("pA"))
      .then(stage).then(unpack)
      .expect(published == Set("pA") and publishedVia == Set("shards") and Safety)

  // A packlist node of another branch (internally valid) is refused before decode.
  run substitutedNodeTest =
    initWith(FAULTS).then(serveNode("nB"))
      .expect(phase == "rejected" and packKey == "" and Safety)

  // A consistent manifest of ANOTHER pack: refused before any shard request.
  run foreignManifestBeforeShardsTest =
    initWith(FAULTS).then(serveNode("nA")).then(serveManifest("pB", "pB"))
      .expect(phase == "rejected" and shardReqs == Set() and Safety)

  // A manifest that names the requested pack but commits to another pack's
  // shards: the consistent shard set reconstructs pB, and step 5 / T3 refuse it.
  run manifestLiesAboutShardsTest =
    initWith(FAULTS).then(serveNode("nA")).then(serveManifest("pA", "pB")).then(serveShards("pB"))
      .expect(phase == "rejected" and shardReturns == Set() and published == Set() and Safety)

  // A real pack under another key, monolithic: C1 refuses it before staging.
  run substitutedMonolithicTest =
    initWith(FAULTS).then(serveNode("nA")).then(serveMono("pB")).then(stage)
      .expect(phase == "rejected" and published == Set() and Safety)
}

module identity_mutants_test {
  import identityCore(FAULTS = { nodeNoVerify: false, noManifestPrecheck: false,
    noDecodeManifestCheck: false, noPostDecodeCheck: false, consumerNoVerify: false }).* from "./identity"

  pure val NO_T1: IFaults = { ...NOFAULTS, noManifestPrecheck: true }
  pure val NO_POST: IFaults = { ...NOFAULTS, noPostDecodeCheck: true }
  pure val NO_NODE: IFaults = { ...NOFAULTS, nodeNoVerify: true }

  // Without T1 shards are requested under a foreign manifest; T2 still
  // refuses to reconstruct.
  run noPrecheckRequestsShardsTest =
    initWith(NO_T1).then(serveNode("nA")).then(serveManifest("pB", "pB")).then(serveShards("pB"))
      .expect(not(ShardsOnlyForRequestedManifest) and ReconstructOnlyForRequested and phase == "rejected")

  // Without step 5 / T3 the sharded transport returns pB for pA; C1 refuses it.
  run noPostDecodeReturnsForeignTest =
    initWith(NO_POST).then(serveNode("nA")).then(serveManifest("pA", "pB")).then(serveShards("pB"))
      .expect(not(ShardPathReturnsRequested))
      .then(stage).expect(phase == "rejected" and PackMatchesRequest)

  // Without the node check the fetch follows another branch's chain and
  // publishes a pack that every per-pack check accepts.
  run noNodeVerifyPublishesForeignChainTest =
    initWith(NO_NODE).then(serveNode("nB")).then(serveMono("pB")).then(stage).then(unpack)
      .expect(published == Set("pB") and PackMatchesRequest and not(PublishedWithinRequestedClosure))
}
