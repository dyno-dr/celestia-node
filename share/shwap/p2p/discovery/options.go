package discovery

import (
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

// Parameters is the set of Parameters that must be configured for the Discovery module
type Parameters struct {
	// PeersLimit defines the soft limit of FNs to connect to via discovery.
	// Node defaults derive this from the DASer's ConcurrencyLimit so that
	// parallel sampling workers are not bottlenecked on a small peer set.
	// Set 0 to disable.
	PeersLimit uint
	// AdvertiseInterval is a interval between advertising sessions.
	// NOTE: only full and bridge can advertise themselves.
	AdvertiseInterval time.Duration
	// DiversityBucketBits controls the peer-ID prefix bucketing for
	// eclipse-resistance. Peers are bucketed by the top DiversityBucketBits
	// bits of SHA-256(peerID). Set to 0 to disable diversity filtering.
	DiversityBucketBits uint
	// DiversityMaxPerBucket is the maximum number of peers allowed from the
	// same ID-prefix bucket in the discovery set. Only used when
	// DiversityBucketBits > 0.
	DiversityMaxPerBucket int
}

// options is the set of options that can be configured for the Discovery module
type options struct {
	// onUpdatedPeers will be called on peer set changes
	onUpdatedPeers OnUpdatedPeers
	// advertise indicates whether the node should also
	// advertise to the discovery instance's topic
	advertise bool
	// peerFilter, if non-nil, is called before adding a peer to the set.
	// Returning false rejects the peer (e.g. for diversity enforcement).
	peerFilter PeerFilter
}

// Option is a function that configures Discovery Parameters
type Option func(*options)

// DefaultParameters returns the default Parameters' configuration values
// for the Discovery module
func DefaultParameters() *Parameters {
	return &Parameters{
		PeersLimit:        10,
		AdvertiseInterval: time.Hour,
	}
}

// Validate validates the values in Parameters
func (p *Parameters) Validate() error {
	if p.PeersLimit <= 0 {
		return fmt.Errorf("discovery: peers limit cannot be zero or negative")
	}

	if p.AdvertiseInterval <= 0 {
		return fmt.Errorf("discovery: advertise interval cannot be zero or negative")
	}
	return nil
}

// WithOnPeersUpdate chains OnPeersUpdate callbacks on every update of discovered peers list.
func WithOnPeersUpdate(f OnUpdatedPeers) Option {
	return func(p *options) {
		p.onUpdatedPeers = p.onUpdatedPeers.add(f)
	}
}

func WithAdvertise() Option {
	return func(p *options) {
		p.advertise = true
	}
}

// WithPeerFilter sets a filter called before each discovered peer is added
// to the set. Return false to reject the peer. Use DiversityFilter() to
// create a bucket-based filter that limits Sybil eclipse attacks.
func WithPeerFilter(f PeerFilter) Option {
	return func(p *options) {
		p.peerFilter = f
	}
}

func newOptions(opts ...Option) *options {
	defaults := &options{
		onUpdatedPeers: func(peer.ID, bool) {},
		advertise:      false,
		peerFilter:     nil,
	}

	for _, opt := range opts {
		opt(defaults)
	}
	return defaults
}
