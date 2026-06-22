package clatter_test

import (
	"errors"
	"testing"

	clatter "github.com/shurlinet/go-clatter"
)

// A non-corrupting API-misuse error from a delegated sub-handshake (here
// ErrBufferTooSmall, raised by the outer NqHandshake's own buffer pre-check
// before it mutates any state) must NOT tear down the dual-layer. The
// single-layer leaves such an error retryable (and the dual-layer's own
// pre-flight buffer checks do too), so the wrap-constructor must mirror that:
// it returns the error verbatim and the caller can retry with an adequate
// buffer.
//
// This pins the fix for the regression where the dual-layer routed EVERY
// delegated sub-handshake error through fail()/failAndZero, permanently
// destroying the handshake (and firing OnError, contrary to the documented
// observer contract) on a benign too-small output buffer. Pre-fix, the retry
// below returned ErrAlreadyFinished; genuinely fatal errors still route through
// fail() and remain terminal.
func TestDualLayer_RetryableSubErrorDoesNotDestroy(t *testing.T) {
	nqSuite := nqSuiteDualLayer()
	pqSuite := pqSuiteDualLayer()

	for _, hybrid := range []bool{false, true} {
		name := "DualLayer"
		if hybrid {
			name = "HybridDualLayer"
		}
		t.Run(name, func(t *testing.T) {
			outer, err := clatter.NewNqHandshake(clatter.PatternNN, true, nqSuite)
			if err != nil {
				t.Fatalf("outer: %v", err)
			}
			inner, err := clatter.NewPqHandshake(clatter.PatternPqNN, true, pqSuite)
			if err != nil {
				t.Fatalf("inner: %v", err)
			}

			var hs clatter.Handshaker
			if hybrid {
				hs, err = clatter.NewHybridDualLayerHandshake(outer, inner, 8192)
			} else {
				hs, err = clatter.NewDualLayerHandshake(outer, inner, 8192)
			}
			if err != nil {
				t.Fatalf("construct: %v", err)
			}
			defer hs.Destroy()

			// Outer-phase first WriteMessage with a too-small output buffer: the
			// outer NqHandshake's own buffer check returns ErrBufferTooSmall
			// without mutating its state.
			tiny := make([]byte, 4)
			if _, werr := hs.WriteMessage(nil, tiny); !errors.Is(werr, clatter.ErrBufferTooSmall) {
				t.Fatalf("tiny-buffer write: want ErrBufferTooSmall, got %v", werr)
			}

			// The handshake must NOT have been destroyed: a retry with an adequate
			// buffer succeeds. Pre-fix this returned ErrAlreadyFinished.
			big := make([]byte, 16384)
			n, werr := hs.WriteMessage(nil, big)
			if errors.Is(werr, clatter.ErrAlreadyFinished) {
				t.Fatal("retryable error destroyed the handshake (regression)")
			}
			if werr != nil {
				t.Fatalf("retry after retryable error: want success, got %v", werr)
			}
			if n <= 0 {
				t.Fatalf("retry wrote %d bytes, want > 0", n)
			}
		})
	}
}
