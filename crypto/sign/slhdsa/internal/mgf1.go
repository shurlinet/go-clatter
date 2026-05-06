// Originally from github.com/trailofbits/go-slh-dsa
// Commit: 15ed0951bd833dd5699dcceddaf614826e3fcb14 (2026-02-13)
// License: BSD-3-Clause
// Copyright (c) 2025 Trail of Bits. All rights reserved.
//
// Modifications by go-clatter authors:
// - Package path changed to crypto/sign/slhdsa/internal

package internal

import (
	"encoding/binary"
	"hash"
	"math"
)

// MGF1 implements the Mask Generation Function (MGF1) as defined in PKCS #1 v2.1
// and required for SLH-DSA (FIPS 205).
//
// MGF1 is used in padding schemes such as OAEP and PSS. It's based on a hash function
// to generate an arbitrary-length mask from a fixed-length seed.
//
// Parameters:
// - seed: the seed from which the mask is generated
// - length: the intended length of the mask in bytes
// - hash: the hash function to use (typically SHA-256 or SHA-512 for SLH-DSA)
//
// Returns a slice of bytes of the requested length.
func MGF1(seed []byte, length uint32, h hash.Hash) []byte {
	// Initialize the output buffer
	mask := make([]byte, length)

	// Calculate how many hash outputs we need
	hashSize := uint32(h.Size())
	iterations := uint32(math.Ceil(float64(length) / float64(hashSize)))

	// Buffer for the counter
	counter := make([]byte, 4)

	// For each required hash output
	for i := range iterations {
		// Reset the hash for the next operation
		h.Reset()

		// Convert counter to big-endian byte representation
		binary.BigEndian.PutUint32(counter, uint32(i))

		// Write seed and counter to hash
		h.Write(seed)
		h.Write(counter)

		// Calculate hash
		digest := h.Sum(nil)

		// Copy to output buffer, ensuring we don't go beyond its end
		offset := i * hashSize
		remaining := length - offset
		if remaining >= hashSize {
			copy(mask[offset:offset+hashSize], digest)
		} else {
			copy(mask[offset:], digest[:remaining])
			break
		}
	}

	return mask
}
