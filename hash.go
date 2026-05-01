package clatter

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
// F56: HMAC key length assertion: key <= block_len.
// F125: Single-write HMAC == multi-write HMAC (confirmed empirically).
// F126: sha256.Sum256 returns [32]byte - fixed array matches F2.
// F173: Clatter manual HMAC = RFC 2104. Go crypto/hmac = same RFC. Equivalent.

// hmacHash computes HMAC(key, data...) using the given hash function.
// Multiple data slices are written sequentially (equivalent to concatenation).
// F105: counter bytes are written as separate Write calls, matching Clatter's
// hmac_many(key, &[out1, &[2u8]]) pattern.
func hmacHash(h HashFunc, key []byte, data ...[]byte) []byte {
	mac := h.NewHMAC(key)
	for _, d := range data {
		mac.Write(d)
	}
	return mac.Sum()
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
func HKDF2(h HashFunc, ck, ikm []byte) (out1, out2 []byte) {
	hashLen := h.HashLen()

	// temp_key = HMAC(ck, ikm)
	tempKey := hmacHash(h, ck, ikm)
	defer zeroSlice(tempKey)

	// output1 = HMAC(temp_key, [0x01])
	out1 = hmacHash(h, tempKey, []byte{0x01})

	// output2 = HMAC(temp_key, output1 || [0x02])
	out2 = hmacHash(h, tempKey, out1, []byte{0x02})

	// Truncate to hashLen (both outputs are full HMAC output, could be > hashLen
	// for some hash-HMAC combos, but in practice HMAC output == hash output).
	if len(out1) > hashLen {
		out1 = out1[:hashLen]
	}
	if len(out2) > hashLen {
		out2 = out2[:hashLen]
	}

	return out1, out2
}

// HKDF3 performs Noise's 3-output HKDF: returns (output1, output2, output3).
//
// Algorithm:
//   temp_key = HMAC(ck, input_key_material)
//   output1  = HMAC(temp_key, [0x01])
//   output2  = HMAC(temp_key, output1 || [0x02])
//   output3  = HMAC(temp_key, output2 || [0x03])
//
// Used by mixKeyAndHash.
func HKDF3(h HashFunc, ck, ikm []byte) (out1, out2, out3 []byte) {
	hashLen := h.HashLen()

	tempKey := hmacHash(h, ck, ikm)
	defer zeroSlice(tempKey)

	out1 = hmacHash(h, tempKey, []byte{0x01})
	out2 = hmacHash(h, tempKey, out1, []byte{0x02})
	out3 = hmacHash(h, tempKey, out2, []byte{0x03})

	if len(out1) > hashLen {
		out1 = out1[:hashLen]
	}
	if len(out2) > hashLen {
		out2 = out2[:hashLen]
	}
	if len(out3) > hashLen {
		out3 = out3[:hashLen]
	}

	return out1, out2, out3
}

// zeroSlice zeros all bytes in b.
func zeroSlice(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
