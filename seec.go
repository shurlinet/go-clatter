package clatter

import (
	"fmt"
	"io"
	"sync"

	"github.com/shurlinet/go-clatter/internal/entropy"
)

// SEEC is the seam for Static-Ephemeral Entropy Combination (PQNoise paper,
// eprint 2022/539, Definition 14 / Appendix C). Implementations mix a
// long-lived secret with fresh entropy so handshake coins stay unpredictable
// if EITHER the secret or the entropy source is uncompromised.
//
// Mapping to the paper's definitions:
//
//	GenKey(1^λ) -> sk      ≈ the consumer generating and storing a 32-byte
//	                         secret, then constructing an implementation
//	                         (e.g. NewSEECPRF) from it.
//	GenRand(sk, r)         ≈ GenRand(rng, purpose, n), where r is drawn
//	                         fresh from rng on every call.
//	"(potentially updated) sk" ≈ implementations may be stateful; a stateful
//	                         implementation shared across handshakes must
//	                         handle its own synchronization.
//
// Contract for implementations:
//
//   - MUST be safe for concurrent use when shared across handshakes.
//   - MUST draw fresh entropy from rng on every call - never cache or
//     replay r. Coin freshness under a healthy rng depends on it.
//   - MUST fail closed: any rng failure returns an error, never
//     degraded or deterministic output.
//   - MUST return exactly n bytes on success.
//
// SEEC hedges coin SECRECY, never coin FRESHNESS: under a repeating or
// dead rng, the same r produces the same output. That is the model
// (the paper requires fresh-but-possibly-known coins), not a defect.
type SEEC interface {
	// GenRand returns n pseudorandom bytes for the given purpose,
	// mixing the long-lived secret with fresh entropy from rng.
	// n must be in [1, 255].
	GenRand(rng io.Reader, purpose SEECPurpose, n int) ([]byte, error)
}

// SEECPurpose domain-separates SEEC output contexts so that identical
// (secret, r) pairs never produce identical coins across different uses
// (e.g. a keygen seed and an encapsulation coin of the same width under
// an rng rollback). This is a deliberate strengthening over the paper
// and the nyquist reference, which separate nothing.
type SEECPurpose uint8

// Defined purposes. The values are opaque pass-through to implementations:
// SEECPRF accepts any SEECPurpose value without validation, so consumers
// composing their own draw contexts may define additional values.
const (
	// SEECKeygen labels ephemeral keypair seed draws (DH and KEM).
	SEECKeygen SEECPurpose = 1
	// SEECEncaps labels KEM encapsulation coin draws.
	SEECEncaps SEECPurpose = 2
)

// seecPRFLabel is the fixed Extract salt binding the construction to this
// library and version. It deliberately does not encode the hash function:
// the 32-byte secret is SEEC-dedicated (see NewSEECPRF), so no cross-use
// collision surface exists.
const seecPRFLabel = "go-clatter/seec/v1/prf"

// maxSEECOutputLen is the maximum bytes per GenRand call. The requested
// length is bound into the HKDF-Expand info as a single byte, so requests
// are capped at 255; larger draws are composed from multiple calls (each
// with fresh r) by the caller.
const maxSEECOutputLen = 255

// SEECPRF is the built-in software SEEC instantiation: an RFC 5869-shaped
// Extract-then-Expand PRF over the library's HMAC construction.
//
// Construction (verified against RFC 5869 test vectors and two independent
// HKDF oracles):
//
//	prk = HMAC(key = "go-clatter/seec/v1/prf", msg = secret)   at construction
//	per call:
//	  r    = 32 fresh bytes from rng (fail closed on any rng anomaly)
//	  k_r  = HMAC(prk, r)                  re-key: r is the entire message
//	  out  = HKDF-Expand(k_r, info = purpose || uint8(n), n)
//
// The per-call re-key makes both security directions rest on named,
// studied assumptions: with the secret uncompromised, HMAC(prk, ·) is a
// standard PRF; with the secret revealed but coins good, HMAC keyed by a
// public prk over a full-message uniform r is the proven dual-PRF (swap)
// case. Burying r inside Expand info would not be theorem-backed.
//
// A SEECPRF is safe for concurrent use by multiple handshakes. The
// long-lived secret is the paper's model: one shared instance per process
// or identity, reused across many handshakes. The instance lives in
// process memory; it hedges revealed or predictable RNG output, NOT host
// compromise (an attacker reading process memory reads the secret too).
// Zeroing on Destroy is best-effort: the Go runtime may have copied the
// underlying memory.
type SEECPRF struct {
	h  HashFunc
	mu sync.RWMutex
	// prk is mutated only by Destroy, which holds the write lock;
	// GenRand reads it under the read lock.
	prk       []byte
	destroyed bool
}

// Compile-time check: SEECPRF implements SEEC.
var _ SEEC = (*SEECPRF)(nil)

// NewSEECPRF constructs the built-in software SEEC from a 32-byte secret.
//
// The secret MUST be exactly 32 bytes, not all zero, and SEEC-dedicated:
// generate it once from a trusted source, store it with the same
// protection as a static identity key, and never reuse it as a key
// anywhere else. The constructor copies the secret, derives the internal
// PRF key, and zeroes its copy immediately; callers should zero their own
// copy after this returns.
//
// The all-zero secret is rejected as a deliberate strengthening: an
// unfilled buffer passed by mistake must fail loudly, not silently
// produce a hedge keyed by zeros.
func NewSEECPRF(h HashFunc, secret []byte) (*SEECPRF, error) {
	if h == nil {
		return nil, fmt.Errorf("%w: nil HashFunc", ErrSEEC)
	}
	if hl, bl := h.HashLen(), h.BlockLen(); hl <= 0 || bl <= 0 || hl > bl {
		// The per-call re-key uses prk (HashLen bytes) as an HMAC key,
		// which hmacHash rejects above BlockLen. Surface impossible
		// geometry at construction, not on the first handshake draw.
		return nil, fmt.Errorf("%w: HashFunc geometry unusable: hash length %d, block length %d (re-keying requires 0 < hash length <= block length)",
			ErrSEEC, hl, bl)
	}
	if len(secret) != 32 {
		return nil, fmt.Errorf("%w: secret must be exactly 32 bytes, got %d", ErrSEEC, len(secret))
	}
	var acc byte
	for _, b := range secret {
		acc |= b
	}
	if acc == 0 {
		return nil, fmt.Errorf("%w: secret is all zero", ErrSEEC)
	}

	sec := make([]byte, 32)
	copy(sec, secret)
	defer zeroSlice(sec)

	// RFC 5869 Extract with the fixed label as salt (salt is the HMAC key).
	prk, err := hmacHash(h, []byte(seecPRFLabel), sec)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSEEC, err)
	}
	if len(prk) != h.HashLen() {
		zeroSlice(prk)
		return nil, fmt.Errorf("%w: HashFunc returned %d-byte HMAC output for declared hash length %d",
			ErrSEEC, len(prk), h.HashLen())
	}

	return &SEECPRF{h: h, prk: prk}, nil
}

// GenRand implements SEEC. It draws 32 bytes of fresh entropy from rng,
// re-keys the PRF with them, and expands to n bytes bound to purpose and n.
// n must be in [1, 255].
//
// Any rng anomaly (short source, error alongside a full read, EOF, nil
// rng) fails closed with an error wrapping ErrSEEC. After Destroy, the
// returned error wraps both ErrSEEC and ErrDestroyed; note that the
// fresh draw happens before the destroyed check (drawing must not hold
// the lock), so a destroyed instance still consumes 32 bytes from rng
// before returning the error.
func (s *SEECPRF) GenRand(rng io.Reader, purpose SEECPurpose, n int) ([]byte, error) {
	if rng == nil {
		return nil, fmt.Errorf("%w: nil rng", ErrSEEC)
	}
	if n < 1 || n > maxSEECOutputLen {
		return nil, fmt.Errorf("%w: output length %d outside [1, %d]", ErrSEEC, n, maxSEECOutputLen)
	}

	// Draw r OUTSIDE the lock: a custom reader may block indefinitely,
	// and a blocked reader must never wedge Destroy or starve other
	// handshakes behind a pending writer.
	var r [32]byte
	defer zeroSlice(r[:])
	if err := entropy.Fill(rng, r[:]); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSEEC, err)
	}

	// Read-lock scope: the destroyed check plus the single HMAC over prk.
	// Destroy mutates prk under the write lock; computing the re-key under
	// the read lock is what prevents HMAC-over-half-zeroed-prk torn coins.
	s.mu.RLock()
	if s.destroyed {
		s.mu.RUnlock()
		return nil, fmt.Errorf("%w: %w", ErrSEEC, ErrDestroyed)
	}
	kr, err := hmacHash(s.h, s.prk, r[:])
	s.mu.RUnlock()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSEEC, err)
	}
	defer zeroSlice(kr)

	info := [2]byte{byte(purpose), byte(n)}
	out, err := hkdfExpand(s.h, kr, info[:], n)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSEEC, err)
	}
	return out, nil
}

// Destroy zeroes the internal PRF key and permanently disables the
// instance. Idempotent. In-flight GenRand calls that already passed the
// destroyed check complete normally (Destroy waits for their read locks);
// subsequent calls fail with an error wrapping both ErrSEEC and
// ErrDestroyed.
//
// The consumer owns the instance lifecycle: a handshake configured with a
// SEEC instance borrows it and never destroys it.
func (s *SEECPRF) Destroy() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.destroyed {
		return
	}
	zeroSlice(s.prk)
	s.prk = nil
	s.destroyed = true
}

// hkdfExpand is RFC 5869 section 2.3 HKDF-Expand on the library's HMAC
// construction:
//
//	T(1) = HMAC(prk, info || 0x01)
//	T(i) = HMAC(prk, T(i-1) || info || byte(i))
//	out  = first n bytes of T(1) || T(2) || ...
//
// It accepts arbitrary info so RFC 5869 test vectors drive it directly;
// SEECPRF.GenRand passes info = purpose || uint8(n). All intermediate
// blocks, including the unreturned tail of the last block, are zeroed
// before returning.
func hkdfExpand(h HashFunc, prk, info []byte, n int) ([]byte, error) {
	hashLen := h.HashLen()
	if hashLen <= 0 {
		return nil, fmt.Errorf("%w: invalid hash length %d", ErrSEEC, hashLen)
	}
	if n < 1 {
		return nil, fmt.Errorf("%w: expand length %d below 1", ErrSEEC, n)
	}
	// Overflow-free ceiling division: (n + hashLen - 1) would wrap negative
	// for n near MaxInt, slip past the block-count check, and panic in make
	// with a negative capacity. (n-1)/hashLen involves no addition, and
	// comparing block COUNTS avoids 255*hashLen, which a hostile HashFunc
	// declaring a huge HashLen could overflow too.
	blocks := (n-1)/hashLen + 1
	if blocks > 255 {
		return nil, fmt.Errorf("%w: expand length %d exceeds the RFC 5869 limit of 255 blocks of %d bytes",
			ErrSEEC, n, hashLen)
	}

	// Compute T(1) BEFORE allocating the chain buffer: the buffer is sized
	// from the declared hashLen, and a buggy HashFunc declaring an absurd
	// length would otherwise drive make into an unallocatable capacity
	// (runtime panic). Validating the declaration against an ACTUAL HMAC
	// output first means the allocation below is sized by proven reality.
	// (A HashFunc is a consumer-chosen component; these guards fail closed
	// on BUGGY implementations - wrong constants, truncated sums - which
	// is the realistic class.)
	t, err := hmacHash(h, prk, info, []byte{1})
	if err != nil {
		return nil, err
	}
	if len(t) != hashLen {
		zeroSlice(t)
		return nil, fmt.Errorf("%w: HMAC returned %d-byte block for declared hash length %d",
			ErrSEEC, len(t), hashLen)
	}

	buf := make([]byte, 0, blocks*hashLen)
	buf = append(buf, t...)
	prev := t
	for i := 2; i <= blocks; i++ {
		t, err := hmacHash(h, prk, prev, info, []byte{byte(i)})
		if err != nil {
			zeroSlice(prev)
			zeroSlice(buf)
			return nil, err
		}
		if len(t) != hashLen {
			// The HMACWriter changed output size mid-chain; the chain
			// accounting (and buf's no-realloc zeroing guarantee) no
			// longer holds. Fail closed.
			zeroSlice(t)
			zeroSlice(prev)
			zeroSlice(buf)
			return nil, fmt.Errorf("%w: HMAC returned %d-byte block for declared hash length %d",
				ErrSEEC, len(t), hashLen)
		}
		buf = append(buf, t...)
		zeroSlice(prev)
		prev = t
	}
	zeroSlice(prev)

	out := make([]byte, n)
	copy(out, buf)
	zeroSlice(buf)
	return out, nil
}
