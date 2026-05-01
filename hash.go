package clatter

import "fmt"

// Manual HKDF implementation matching Noise spec and Rust Clatter exactly.
//
// F53: Do NOT use Go's x/crypto/hkdf - Noise's HKDF differs from RFC 5869
//      (no salt/extract separation, chaining key IS the HMAC key directly).
// F106: Use Go's crypto/hmac via HashFunc.NewHMAC - correct, audited impl.
// F107: Counter bytes are raw 0x01, 0x02, 0x03 - NOT ASCII "1", "2", "3".
// F105: HMAC feeds multiple slices via sequential Write calls.
// F118: Copy ck to local before HKDF to prevent aliasing corruption.
// F108: split() calls HKDF with empty IKM - tested explicitly.
// F110: Temp keys zeroed after creating CipherStates.
// F56: HMAC key length validated: key must be <= block_len. Clatter asserts
//      this and panics. go-clatter returns error. Noise guarantees the
//      invariant (ck is always hashLen, hashLen <= blockLen), but defense
//      in depth catches corrupt state before it produces silent interop
//      divergence (Go's crypto/hmac auto-hashes oversized keys per RFC 2104,
//      producing valid but different-from-Clatter output).
// F125: Single-write HMAC == multi-write HMAC (confirmed empirically).
// F126: sha256.Sum256 returns [32]byte - fixed array matches F2.
// F173: Clatter manual HMAC = RFC 2104. Go crypto/hmac = same RFC. Equivalent.

// hmacHash computes HMAC(key, data...) using the given hash function.
// Multiple data slices are written sequentially (equivalent to concatenation).
// F105: counter bytes are written as separate Write calls, matching Clatter's
// hmac_many(key, &[out1, &[2u8]]) pattern.
// F56: Returns error if key exceeds the hash block length.
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
//   temp_key = HMAC(ck, input_key_material)
//   output1  = HMAC(temp_key, [0x01])
//   output2  = HMAC(temp_key, output1 || [0x02])
//
// F53: This is NOT RFC 5869. No salt/extract separation.
// F107: Counter bytes are 0x01 and 0x02, not ASCII "1" and "2".
// F118: Caller must copy ck before passing if ck might alias output.
// F108: Empty ikm is valid (used by split()).
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
//   temp_key = HMAC(ck, input_key_material)
//   output1  = HMAC(temp_key, [0x01])
//   output2  = HMAC(temp_key, output1 || [0x02])
//   output3  = HMAC(temp_key, output2 || [0x03])
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
