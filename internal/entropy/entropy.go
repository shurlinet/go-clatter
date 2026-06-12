// Package entropy provides the shared fail-closed RNG read helper used by
// every entropy consumer in go-clatter (DH adapters, KEM adapters, SEEC).
package entropy

import (
	"fmt"
	"io"
)

// Fill reads exactly len(buf) bytes from rng into buf, failing closed on
// every anomaly an io.Reader can legally or illegally produce:
//
//   - Short read with nil error: the loop continues reading (a chunked but
//     alive reader succeeds with a correctly, fully filled buffer).
//   - Any non-nil error, even alongside a full read: rejected. io.ReadFull
//     would silently accept (len(buf), err) because io.ReadAtLeast clears
//     the error once n >= min; a reader reporting "entropy health failed"
//     next to full bytes must NOT be trusted as a seed source.
//   - io.EOF in any position, including exactly at the final byte: rejected.
//   - Zero bytes with nil error: rejected rather than spinning forever on a
//     wedged source (io.ReadFull would loop indefinitely).
//   - A count outside [0, len(remaining)]: rejected (hostile or broken
//     reader violating the io.Reader contract).
//
// A nil rng is rejected. A zero-length buf succeeds without calling Read.
// The returned error wraps the reader's own error so it stays reachable
// via errors.Is through callers' wrap chains.
func Fill(rng io.Reader, buf []byte) error {
	if rng == nil {
		return fmt.Errorf("entropy: nil rng")
	}
	for off := 0; off < len(buf); {
		n, err := rng.Read(buf[off:])
		if n < 0 || n > len(buf)-off {
			return fmt.Errorf("entropy: rng returned invalid read count %d for %d-byte request",
				n, len(buf)-off)
		}
		off += n
		if err != nil {
			return fmt.Errorf("entropy: rng read failed after %d of %d bytes: %w",
				off, len(buf), err)
		}
		if n == 0 {
			return fmt.Errorf("entropy: rng returned no data and no error after %d of %d bytes",
				off, len(buf))
		}
	}
	return nil
}
