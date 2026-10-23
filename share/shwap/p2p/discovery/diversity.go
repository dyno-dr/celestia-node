package discovery

import (
	"crypto/sha256"
	"encoding/binary"
	"sync"

	"github.com/libp2p/go-libp2p/core/peer"
)

// PeerFilter decides whether a discovered peer may enter the discovery set.
// Return true to accept the peer, false to reject it.
// It is called inside handleDiscoveredPeer, before d.set.Add().
type PeerFilter func(p peer.ID) bool

// PeerGater is implemented by any type that can block a peer at the
// connection level (e.g. *conngater.BasicConnectionGater).
// Using an interface keeps the discovery package free of a hard conngater dep.
type PeerGater interface {
	BlockPeer(p peer.ID) error
}

// DiversityFilter returns a PeerFilter that limits how many peers from the
// same ID-prefix bucket can enter the discovery set simultaneously.
//
// Algorithm:
//  1. Hash the peer ID with SHA-256.
//  2. Take the top `bucketBits` bits of the hash as the bucket number.
//  3. Count current set members per bucket.
//  4. Reject if bucket >= maxPerBucket.
//
// Defense rationale:
//  An attacker generating random peer IDs spreads across buckets naturally.
//  With bucketBits=2 (4 buckets) and maxPerBucket=1, the filter allows at
//  most 4 Sybil peers into the discovery set regardless of fleet size.
func DiversityFilter(bucketBits uint, maxPerBucket int) PeerFilter {
	var mu sync.Mutex
	buckets := make(map[uint64]int)

	assignBucket := func(p peer.ID) uint64 {
		h := sha256.Sum256([]byte(p))
		raw := binary.BigEndian.Uint64(h[:8])
		if bucketBits >= 64 {
			return raw
		}
		return raw >> (64 - bucketBits)
	}

	return func(p peer.ID) bool {
		bucket := assignBucket(p)
		mu.Lock()
		defer mu.Unlock()
		if buckets[bucket] >= maxPerBucket {
			return false // reject: bucket full
		}
		buckets[bucket]++
		return true
	}
}

// DiversityFilterWithGater is like DiversityFilter but additionally blocks
// rejected peers at the connection layer via gater.BlockPeer().
// This prevents Sybil nodes from establishing incoming connections to the
// local node even if they were not discovered via the active discovery loop.
//
// This completes the two-layer eclipse defense:
//   Layer 1 (DiversityFilter):         limits peers in the discovery set
//   Layer 2 (DiversityFilterWithGater): also blocks incoming Sybil connections
func DiversityFilterWithGater(bucketBits uint, maxPerBucket int, gater PeerGater) PeerFilter {
	inner := DiversityFilter(bucketBits, maxPerBucket)

	return func(p peer.ID) bool {
		if inner(p) {
			return true
		}
		// Peer was rejected by the diversity filter.
		// Block it at the connection layer so it cannot connect from its side.
		if gater != nil {
			_ = gater.BlockPeer(p) // best-effort; log errors in the caller
		}
		return false
	}
}
