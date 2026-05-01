package clatter

import "sync/atomic"

// DummyRng is a deterministic counter-based RNG for test vector generation.
// It matches Rust Clatter's DummyRng exactly: AtomicU64 counter,
// each byte = (counter.fetch_add(1) % 256).
//
// For interop vectors, the counter MUST start at 0xdeadbeef and advance
// identically to the Rust implementation.
type DummyRng struct {
	counter atomic.Uint64
}

// NewDummyRng creates a DummyRng with the given seed value.
// Standard seed for Clatter test vectors: 0xdeadbeef.
func NewDummyRng(seed uint64) *DummyRng {
	d := &DummyRng{}
	d.counter.Store(seed)
	return d
}

// Read fills p with deterministic bytes, advancing the counter per byte.
func (d *DummyRng) Read(p []byte) (int, error) {
	for i := range p {
		val := d.counter.Add(1) - 1 // fetch_add returns old value in Rust
		p[i] = byte(val % 256)
	}
	return len(p), nil
}
