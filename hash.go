package clatter

import "fmt"

// Manual HKDF implementation matching Noise spec and Rust Clatter exactly.
//
// This is NOT RFC 5869 HKDF. Noise's HKDF has no salt/extract separation;
// the chaining key IS the HMAC key directly. Do NOT substitute Go's
// x/crypto/hkdf package, which implements RFC 5869 and would silently
// produce wrong output.
//
// Counter bytes are raw byte values (0x01, 0x02, 0x03), not ASCII digits.
// Multiple data slices are fed via sequential HMAC Write calls (equivalent
// to concatenation). The caller must copy ck before passing if ck might
// alias the output buffer.
//
// HMAC key length is validated: key must be <= block_len. The Noise protocol
// guarantees this invariant (ck is always hashLen, hashLen <= blockLen), but
// defense in depth catches corrupt state before it produces silent interop
// divergence (Go's crypto/hmac auto-hashes oversized keys per RFC 2104,
// producing valid but different-from-Clatter output).

// hmacHash computes HMAC(key, data...) using the given hash function.
// Multiple data slices are written sequentially (equivalent to concatenation),
// matching Clatter's hmac_many(key, &[out1, &[2u8]]) pattern.
// Returns error if key exceeds the hash block length.
func hmacHash(h HashFunc, key []byte, data ...[]byte) ([]byte, error) {
	if len(key) > h.BlockLen() {
		return nil, fmt.Errorf("%w: HMAC key length %d exceeds block length %d",
			ErrCipher, len(key), h.BlockLen())
	}
	mac := h.NewHMAC(key)
	for _, d := range data {
		mac.Write(d)
	}
	return mac.Sum(), nil
}

// HKDF2 performs Noise's 2-output HKDF: returns (output1, output2).
//
// Algorithm (Noise spec section 4, Clatter symmetricstate.rs):
//
//	temp_key = HMAC(ck, input_key_material)
//	output1  = HMAC(temp_key, [0x01])
//	output2  = HMAC(temp_key, output1 || [0x02])
//
// Empty ikm is valid (used by Split). Caller must copy ck before passing
// if ck might alias the output.
func HKDF2(h HashFunc, ck, ikm []byte) (out1, out2 []byte, err error) {
	hashLen := h.HashLen()

	// temp_key = HMAC(ck, ikm)
	tempKey, err := hmacHash(h, ck, ikm)
	if err != nil {
		return nil, nil, fmt.Errorf("HKDF2 extract: %w", err)
	}
	defer zeroSlice(tempKey)

	// output1 = HMAC(temp_key, [0x01])
	out1, err = hmacHash(h, tempKey, []byte{0x01})
	if err != nil {
		return nil, nil, fmt.Errorf("HKDF2 expand1: %w", err)
	}

	// output2 = HMAC(temp_key, output1 || [0x02])
	out2, err = hmacHash(h, tempKey, out1, []byte{0x02})
	if err != nil {
		zeroSlice(out1)
		return nil, nil, fmt.Errorf("HKDF2 expand2: %w", err)
	}

	// Truncate to hashLen
	if len(out1) > hashLen {
		out1 = out1[:hashLen]
	}
	if len(out2) > hashLen {
		out2 = out2[:hashLen]
	}

	return out1, out2, nil
}

// HKDF3 performs Noise's 3-output HKDF: returns (output1, output2, output3).
//
// Algorithm:
//
//	temp_key = HMAC(ck, input_key_material)
//	output1  = HMAC(temp_key, [0x01])
//	output2  = HMAC(temp_key, output1 || [0x02])
//	output3  = HMAC(temp_key, output2 || [0x03])
//
// Used by MixKeyAndHash.
func HKDF3(h HashFunc, ck, ikm []byte) (out1, out2, out3 []byte, err error) {
	hashLen := h.HashLen()

	tempKey, err := hmacHash(h, ck, ikm)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("HKDF3 extract: %w", err)
	}
	defer zeroSlice(tempKey)

	out1, err = hmacHash(h, tempKey, []byte{0x01})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("HKDF3 expand1: %w", err)
	}

	out2, err = hmacHash(h, tempKey, out1, []byte{0x02})
	if err != nil {
		zeroSlice(out1)
		return nil, nil, nil, fmt.Errorf("HKDF3 expand2: %w", err)
	}

	out3, err = hmacHash(h, tempKey, out2, []byte{0x03})
	if err != nil {
		zeroSlice(out1)
		zeroSlice(out2)
		return nil, nil, nil, fmt.Errorf("HKDF3 expand3: %w", err)
	}

	if len(out1) > hashLen {
		out1 = out1[:hashLen]
	}
	if len(out2) > hashLen {
		out2 = out2[:hashLen]
	}
	if len(out3) > hashLen {
		out3 = out3[:hashLen]
	}

	return out1, out2, out3, nil
}

// zeroSlice zeros all bytes in b.
func zeroSlice(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// copyBytes returns a fresh copy of b. Returns nil if b is nil.
func copyBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
