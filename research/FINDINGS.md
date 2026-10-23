# Eclipse Attack Research: Findings & Implementation

**Branch**: `research/peer-sampling-regression-tests`
**Commits**: `4ccea512`, `37553ba8`
**Date**: October 2026

---

## 1. Background

Celestia light nodes perform Data Availability Sampling (DAS): they query
random shares from each block to verify data availability without downloading
full blocks. Peer discovery (share/shwap/p2p/discovery/) manages which full
nodes the light node connects to for sampling.

Eclipse attack: an attacker runs many Sybil nodes that advertise on the
/full/v0.1.0 discovery topic, flood the light node's peer set, and reset
every SHREX data stream. If the attacker controls all peer slots, the light
node cannot sample blocks.

---

## 2. Experimental Setup

All experiments use the in-process Swamp framework (nodebuilder/tests/swamp/)
with mocknet.Mocknet -- no Docker, no real networking. Tests are in
nodebuilder/tests/eclipse_test.go under TestEclipseSuite.

Build tag: nd (shares test infrastructure with shrex_test.go)
Run:       go test -v -tags nd -run '^TestEclipseSuite$' ./nodebuilder/tests/

Sybil node model: full Bridge-type nodes that advertise legitimately on
/full/v0.1.0 but call stream.Reset() on every SHREX-EDS and SHREX-ND
request. This is a realistic attacker: valid peer IDs, correct advertising,
no data served.

---

## 3. Experimental Results

### Phase 2 -- Baseline (no attack)

    Setup:   1 bridge + 3 honest full nodes + 1 light node, PeersLimit=4
    RESULT:  Honest peers in set: 4/4, eclipse_rate=0%
    Duration: 18.98s  Status: PASS

### Phase 3 -- Eclipse Attack

    Setup:   1 bridge + 8 Sybil nodes + 1 light node, PeersLimit=4
    RESULT:  Sybil in set: 8/9 (eclipse rate: 89%), Honest in set: 1/9
    Duration: 24.47s  Status: PASS

Key observation: The light node connected to 9 peers despite PeersLimit=4.
Sybil nodes also initiate connections TO the light node, bypassing the
discovery cap. P2P.Peers() reports all connections (discovery + incoming).

### Phase 4 -- Diversity-Aware Defense (Layer 1)

    Setup:    1 bridge + 30 Sybil nodes + 1 light node
              DiversityBucketBits=2, DiversityMaxPerBucket=1
              => at most 4 Sybil peers in the discovery-managed peer set
    P2P raw:  sybil=30 honest=1 total=31 (inflated by Sybil-initiated connections)
    DAS:      8/8 heights succeeded (100% success rate)
    Duration: 30.46s  Status: PASS

Why DAS succeeds despite 30 Sybil connections: The DiversityFilter limits
Sybil peers in the discovery-managed limitedSet (max 4 buckets x 1 = 4 Sybil
max). DAS workers sample from this discovery set only -- not all P2P
connections. The honest bridge stays in the discovery set, so all sampling
retries eventually reach it.

---

## 4. Architecture Finding: Two-Layer Defense

```
P2P.Peers() = ALL connections (discovery-managed + incoming Sybil)
                    |
       +------------+---------------------------+
       | Discovery set (limitedSet)             |  <-- DAS samples from HERE
       |   protected by DiversityFilter (L1)   |
       +----------------------------------------+
       | Incoming Sybil connections             |
       |   bypass discovery filter             |
       |   --> need connGater (Layer 2)         |
       +----------------------------------------+
```

Layer 1 (implemented, tested): DiversityFilter in handleDiscoveredPeer
  limits Sybil peers in the discovery set by peer-ID prefix bucketing.
  Effect: DAS always succeeds even under heavy Sybil attack (8/8 = 100%).

Layer 2 (implemented, partially tested): DiversityFilterWithGater
  additionally calls connGater.BlockPeer() for each rejected peer.
  Effect: reduces raw P2P connection count from Sybil nodes.
  Limitation: does not disconnect already-established connections.

---

## 5. Implementation Details

### New files

share/shwap/p2p/discovery/diversity.go
  - DiversityFilter(bucketBits uint, maxPerBucket int) PeerFilter
  - DiversityFilterWithGater(bucketBits, maxPerBucket, gater PeerGater) PeerFilter
  - PeerFilter type: func(p peer.ID) bool
  - PeerGater interface: BlockPeer(p peer.ID) error

share/shwap/p2p/discovery/diversity_test.go
  - TestDiversityFilterSmallBuckets: 100 Sybil, 4 buckets -> max 4 accepted
  - TestDiversityFilterAcceptsUpToMaxPerBucket: 500 random -> <= 512 accepted
  - TestDiversityFilterSamePeerNotDoubleCounted
  All 3 pass instantly (<0.01s each).

nodebuilder/tests/eclipse_test.go
  - TestEclipseBaseline, TestEclipseAttack, TestEclipseDefended (in TestEclipseSuite)
  - TestEclipseFullDefense (standalone, see known limitations)

### Modified files

share/shwap/p2p/discovery/options.go
  Added: PeerFilter type, WithPeerFilter() option
  Added: DiversityBucketBits uint, DiversityMaxPerBucket int to Parameters

share/shwap/p2p/discovery/discovery.go
  Added: peerFilter PeerFilter field to Discovery struct
  Added: filter call in handleDiscoveredPeer() before d.set.Add()
  Guard: only called when peer is not already in the discovery set

nodebuilder/share/p2p_constructors.go
  Added: auto-wires DiversityFilterWithGater when DiversityBucketBits > 0
  The connGater from the DI graph is passed directly to the filter.

### Algorithm

    bucket = SHA-256(peerID)[top bucketBits bits]
    if buckets[bucket] >= maxPerBucket:
        reject peer (+ BlockPeer via connGater if wired)
    else:
        buckets[bucket]++
        accept peer

With bucketBits=2, maxPerBucket=1: 4 buckets, 1 peer per bucket.
An attacker with N Sybil nodes can place at most 4x1=4 in the discovery
set regardless of fleet size. Without targeted key grinding (expensive),
keys distribute randomly across buckets.

---

## 6. Test Commands

    # Full 3-phase suite (~75 seconds, all PASS)
    go test -v -tags nd -timeout 20m -run '^TestEclipseSuite$' ./nodebuilder/tests/

    # Individual phases
    go test -v -tags nd -run '^TestEclipseBaseline$' ./nodebuilder/tests/
    go test -v -tags nd -run '^TestEclipseAttack$'   ./nodebuilder/tests/
    go test -v -tags nd -run '^TestEclipseDefended$' ./nodebuilder/tests/

    # DiversityFilter unit tests (instant)
    go test -v -run 'TestDiversityFilter' ./share/shwap/p2p/discovery/

    # Full defense test (standalone only -- 31-node teardown race in suite)
    go test -v -tags nd -timeout 5m -run '^TestEclipseFullDefense$' ./nodebuilder/tests/

---

## 7. Known Limitations & Future Work

1. TestEclipseFullDefense teardown race: with 31 nodes, CometBFT/Pebble DB
   has a teardown race when run inside a test suite. Run it standalone.
   The defense code itself is correct (DAS 8/8 passes before teardown).

2. Key grinding: a sophisticated attacker can generate Sybil IDs all in the
   same bucket. Mitigations: increase bucketBits, add key-generation rate
   limiting in discovery, monitor bucket distribution anomalies.

3. Established connections: connGater.BlockPeer() prevents NEW incoming
   connections but does not disconnect existing ones. Follow-up: call
   host.Network().ClosePeer() for rejected peers to fully disconnect them.

4. Parameter tuning: bucketBits=2, maxPerBucket=1 is aggressive (4 slots).
   Production default suggestion: bucketBits=8, maxPerBucket=2 (512 possible
   peers, strong protection against bulk Sybil attacks without being too
   restrictive for honest network growth).
