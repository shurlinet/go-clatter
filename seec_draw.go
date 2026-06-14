package clatter

import (
	"fmt"
	"reflect"
)

// seecDrawer is the single hardened draw helper between a handshake and
// its SEEC implementation. Every SEEC-hedged byte - DH keygen seeds, KEM
// keygen seeds, and KEM encapsulation coins - flows through draw, which
// enforces the SEEC output contract on behalf of the handshake:
//
//   - exactly the requested number of bytes (a short, long, or nil return
//     from a third-party implementation is an error, never a partially
//     filled seed - the nyquist reference panics on this exact violation)
//   - the implementation's returned slice is zeroed after copying
//   - requests wider than 255 bytes are chunked into independent draws
//
// It implements io.Reader so keygen paths can pass it to the UNCHANGED
// GenerateKeypair(rng) adapter signature.
type seecDrawer struct {
	seec    SEEC
	rng     RNG
	purpose SEECPurpose
}

// Read implements io.Reader for keygen paths. Each call fills p entirely
// via draw. A zero-length read is a (0, nil) no-op that never invokes the
// SEEC implementation.
func (d *seecDrawer) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := d.draw(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// maxSEECDrawLen bounds a single logical draw (a keygen seed or one
// encapsulation's coins). It exists so a buggy or hostile KEM declaring an
// absurd EncapsCoinsLen drives a clean error instead of an unallocatable
// make (the same declared-vs-reality allocation class hkdfExpand guards).
// 64 KiB is far above any real KEM's seed or coin width (built-ins use
// 32-64 bytes; the largest post-quantum KEM coins are well under 1 KiB)
// while still being a trivial allocation.
const maxSEECDrawLen = 65536

// draw fills out with SEEC-hedged bytes. Requests up to 255 bytes are a
// single GenRand call; wider requests are chunked into independent calls,
// each with its own fresh r. For the built-in SEECPRF, each chunk's info
// additionally binds the draw's total width and the chunk's byte offset
// (genRandChunk), so even under a dead rng no two chunks - within one
// draw or across draws of different widths - can be byte-identical. For
// third-party SEEC implementations the chunks are plain GenRand calls:
// their per-chunk separation rests on fresh r alone, which is part of the
// documented SEEC contract (and under a dead rng, equal-size chunks of a
// single draw may repeat - a custom implementation that needs positional
// separation must bind context itself).
func (d *seecDrawer) draw(out []byte) error {
	if len(out) == 0 {
		return nil
	}
	if len(out) > maxSEECDrawLen {
		return fmt.Errorf("%w: draw of %d bytes exceeds the %d-byte limit for a single seed or coin request",
			ErrSEEC, len(out), maxSEECDrawLen)
	}

	if len(out) <= maxSEECOutputLen {
		coins, err := d.seec.GenRand(d.rng, d.purpose, len(out))
		if err != nil {
			return err
		}
		// takeCoins validates length BEFORE it copies, so on a
		// length-violating return out is left untouched (no partial seed) -
		// the single-call analogue of the chunked path's explicit
		// out[:off] zeroing below. If takeCoins is ever changed to copy
		// before validating, this path must zero out on error too.
		return takeCoins(out, coins)
	}

	// Chunked path: only reachable for custom KEMs with seeds or coins
	// wider than 255 bytes. Every built-in width (32..64) fits above.
	prf, isPRF := d.seec.(*SEECPRF)
	total := uint32(len(out))
	for off := 0; off < len(out); {
		n := len(out) - off
		if n > maxSEECOutputLen {
			n = maxSEECOutputLen
		}

		var coins []byte
		var err error
		if isPRF {
			coins, err = prf.genRandChunk(d.rng, d.purpose, n, total, uint32(off))
		} else {
			coins, err = d.seec.GenRand(d.rng, d.purpose, n)
		}
		if err != nil {
			zeroSlice(out[:off])
			return err
		}
		if err := takeCoins(out[off:off+n], coins); err != nil {
			zeroSlice(out[:off])
			return err
		}
		off += n
	}
	return nil
}

// takeCoins validates the SEEC return length against the request, copies
// the coins into dst, and zeroes the implementation's slice. The exact
// length check is the house != reject pattern: a partial seed must never
// reach a key generator or encapsulator.
func takeCoins(dst, coins []byte) error {
	defer zeroSlice(coins)
	if len(coins) != len(dst) {
		return fmt.Errorf("%w: SEEC implementation returned %d bytes for a %d-byte request",
			ErrSEEC, len(coins), len(dst))
	}
	copy(dst, coins)
	return nil
}

// keygenRNG returns the RNG for ephemeral key generation: the raw
// handshake rng by default, or the SEEC-hedged drawer when SEEC is
// enabled. With SEEC absent this returns h.rng itself, leaving the
// default path's rng byte stream untouched.
func (h *HandshakeInternals) keygenRNG() RNG {
	if h.seec == nil {
		return h.rng
	}
	return &seecDrawer{seec: h.seec, rng: h.rng, purpose: SEECKeygen}
}

// encapsulateKEM performs KEM encapsulation for a handshake token. With
// SEEC absent it is exactly the v0.5.0 call: k.Encapsulate(pk, h.rng)
// (production adapters ignore rng and use their internal CSPRNG; testing
// adapters read coins from rng). With SEEC enabled, the coins come from
// the SEEC draw helper and enter the KEM through the derandomized
// CoinsEncapsulator interface - the FIPS 203 Encaps with caller-supplied
// m, per the PQNoise paper's Algorithm 1.
func (h *HandshakeInternals) encapsulateKEM(k KEM, pk []byte) (ct, ss []byte, err error) {
	if h.seec == nil {
		ct, ss, err = k.Encapsulate(pk, h.rng)
	} else {
		ct, ss, err = h.encapsulateWithSEEC(k, pk)
	}
	if err != nil {
		return nil, nil, err
	}
	// Validate the returned geometry at the single handshake-side choke
	// point through which every encapsulation flows, BEFORE the caller
	// copies ct onto the wire. The built-in coins path self-checks
	// (encapsWithCoins), but the built-in production path does not, and a
	// third-party KEM or CoinsEncapsulator is wholly untrusted: a ct
	// longer/shorter than the declared CiphertextLen would be silently
	// truncated or zero-padded by the token writer's copy(out, ct) (out is
	// sized from CiphertextLen), putting a corrupt ciphertext on the wire
	// while the full ss is mixed into the transcript - an opaque,
	// hard-to-diagnose failure. Fail closed with a clear error instead.
	if len(ct) != k.CiphertextLen() || len(ss) != k.SharedSecretLen() {
		zeroSlice(ss)
		return nil, nil, fmt.Errorf("%w: KEM %s returned %d-byte ciphertext and %d-byte shared secret (want %d and %d)",
			ErrKEM, k.Name(), len(ct), len(ss), k.CiphertextLen(), k.SharedSecretLen())
	}
	return ct, ss, nil
}

// encapsulateWithSEEC performs the SEEC-hedged encapsulation: draw coins
// from the SEEC instance and feed them through the derandomized
// CoinsEncapsulator interface.
func (h *HandshakeInternals) encapsulateWithSEEC(k KEM, pk []byte) (ct, ss []byte, err error) {
	ce, ok := k.(CoinsEncapsulator)
	if !ok {
		// Constructors validate this with WithSEEC; this guards direct
		// embedders of HandshakeInternals. Fail closed - never silently
		// downgrade to unhedged encapsulation.
		return nil, nil, fmt.Errorf("%w: KEM %s does not support SEEC-hedged encapsulation (no CoinsEncapsulator)",
			ErrSEEC, k.Name())
	}
	// Re-validated at use (not only at construction): a KEM whose
	// EncapsCoinsLen drifts between calls must fail closed here, never
	// reach make with a hostile size.
	n := ce.EncapsCoinsLen()
	if n <= 0 || n > maxSEECDrawLen {
		return nil, nil, fmt.Errorf("%w: KEM %s declares invalid encapsulation coin length %d (must be in [1, %d])",
			ErrSEEC, k.Name(), n, maxSEECDrawLen)
	}

	coins := make([]byte, n)
	defer zeroSlice(coins)
	d := &seecDrawer{seec: h.seec, rng: h.rng, purpose: SEECEncaps}
	if err := d.draw(coins); err != nil {
		return nil, nil, err
	}
	return ce.EncapsulateWithCoins(pk, coins)
}

// validateSEECOption rejects a WithSEEC option carrying nil: both the
// untyped nil interface and a typed-nil (a non-nil interface holding a nil
// pointer, e.g. WithSEEC((*SEECPRF)(nil))), which would pass a plain ==
// nil check and panic mid-handshake. The reflect check switches on kind
// first because Value.IsNil panics on non-nilable kinds (struct values
// are valid SEEC implementations).
func validateSEECOption(ho *handshakeOptions) error {
	if !ho.seecSet {
		return nil
	}
	if ho.seec == nil {
		return fmt.Errorf("%w: WithSEEC(nil): pass a SEEC implementation or omit the option", ErrSEEC)
	}
	v := reflect.ValueOf(ho.seec)
	switch v.Kind() {
	case reflect.Ptr, reflect.Map, reflect.Chan, reflect.Func, reflect.Slice, reflect.UnsafePointer:
		if v.IsNil() {
			return fmt.Errorf("%w: WithSEEC received a typed-nil %T: pass a constructed SEEC implementation or omit the option",
				ErrSEEC, ho.seec)
		}
	}
	return nil
}

// validateSEECKEMCapability checks that a KEM used with WithSEEC supports
// coins-driven encapsulation. role names the failing suite field in the
// constructor error.
func validateSEECKEMCapability(k KEM, role string) error {
	ce, ok := k.(CoinsEncapsulator)
	if !ok {
		return fmt.Errorf("%w: %s %s does not support SEEC-hedged encapsulation: it does not implement CoinsEncapsulator (SEEC never downgrades to keygen-only hedging)",
			ErrSEEC, role, k.Name())
	}
	if n := ce.EncapsCoinsLen(); n <= 0 || n > maxSEECDrawLen {
		return fmt.Errorf("%w: %s %s declares invalid encapsulation coin length %d (must be in [1, %d])",
			ErrSEEC, role, k.Name(), n, maxSEECDrawLen)
	}
	return nil
}
