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

// DiversityFilter returns a PeerFilter that limits how many peers from the
// same ID-prefix bucket can enter the discovery set simultaneously.
//
// Algorithm:
//  1. Hash the peer ID with SHA-256.
//  2. Take the top `bucketBits` bits of the hash as the bucket number.
//  3. Count how many current set members belong to each bucket.
//  4. Reject the peer if its bucket already has >= maxPerBucket members.
//
// Defense rationale:
//  An attacker generating many peer IDs at random will spread across buckets
//  naturally. With bucketBits=8 (256 buckets) and maxPerBucket=2, the attacker
//  can place at most 2 peers per bucket. To fill a PeersLimit=4 set, the
//  attacker needs keys in at least 2 different buckets -- which is still
//  possible but limits the eclipse rate. A targeted key-grinding attack
//  (generating keys all in the same bucket) is computationally expensive and
//  detectable.
func DiversityFilter(bucketBits uint, maxPerBucket int) PeerFilter {
	var mu sync.Mutex
	buckets := make(map[uint64]int)

	assignBucket := func(p peer.ID) uint64 {
		h := sha256.Sum256([]byte(p))
		raw := binary.BigEndian.Uint64(h[:8])
		if bucketBits >= 64 {
			return raw
		}
		// keep only the top bucketBits bits
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
