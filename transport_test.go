package clatter

import (
	"errors"
	"sync"
	"testing"
)

// newTestTransportPair builds an initiator/responder TransportState pair
// sharing directional keys, using the in-package test cipher.
func newTestTransportPair(t *testing.T) (*TransportState, *TransportState) {
	t.Helper()
	k1 := make([]byte, KeyLen)
	k2 := make([]byte, KeyLen)
	for i := range k1 {
		k1[i] = byte(i)
		k2[i] = byte(255 - i)
	}
	mk := func() (*CipherState, *CipherState) {
		cs1, err := NewCipherState(&testCipher{}, k1)
		if err != nil {
			t.Fatalf("cs1: %v", err)
		}
		cs2, err := NewCipherState(&testCipher{}, k2)
		if err != nil {
			t.Fatalf("cs2: %v", err)
		}
		return cs1, cs2
	}
	aCs1, aCs2 := mk()
	bCs1, bCs2 := mk()
	h := []byte("test-handshake-hash-32-bytes-pad")
	alice := newTransportState(aCs1, aCs2, PatternNN, append([]byte{}, h...), true, MaxMessageLen)
	bob := newTransportState(bCs1, bCs2, PatternNN, append([]byte{}, h...), false, MaxMessageLen)
	return alice, bob
}

// TestTransportState_ConcurrentUseGuards deterministically verifies that
// every direction-mutating method rejects concurrent use of its direction
// with ErrConcurrentUse while the guard is held, and works again after
// release.
func TestTransportState_ConcurrentUseGuards(t *testing.T) {
	alice, _ := newTestTransportPair(t)
	defer alice.Destroy()

	buf := make([]byte, 1024)

	// Hold the send guard: all send-side ops must fail loudly.
	alice.sendInUse.Store(1)
	if _, err := alice.Send([]byte("x"), buf); !errors.Is(err, ErrConcurrentUse) {
		t.Errorf("Send under held guard: got %v, want ErrConcurrentUse", err)
	}
	copy(buf, "x")
	if _, err := alice.SendInPlace(buf, 1); !errors.Is(err, ErrConcurrentUse) {
		t.Errorf("SendInPlace under held guard: got %v, want ErrConcurrentUse", err)
	}
	if err := alice.RekeySender(); !errors.Is(err, ErrConcurrentUse) {
		t.Errorf("RekeySender under held guard: got %v, want ErrConcurrentUse", err)
	}
	// Receive side is independent: must NOT be affected by the send guard.
	if _, err := alice.Receive(make([]byte, TagLen), buf); errors.Is(err, ErrConcurrentUse) {
		t.Error("Receive blocked by send guard: directions must be independent")
	}
	alice.sendInUse.Store(0)

	// Hold the receive guard: all receive-side ops must fail loudly.
	alice.recvInUse.Store(1)
	if _, err := alice.Receive(make([]byte, TagLen), buf); !errors.Is(err, ErrConcurrentUse) {
		t.Errorf("Receive under held guard: got %v, want ErrConcurrentUse", err)
	}
	if _, err := alice.ReceiveInPlace(make([]byte, TagLen), TagLen); !errors.Is(err, ErrConcurrentUse) {
		t.Errorf("ReceiveInPlace under held guard: got %v, want ErrConcurrentUse", err)
	}
	if err := alice.RekeyReceiver(); !errors.Is(err, ErrConcurrentUse) {
		t.Errorf("RekeyReceiver under held guard: got %v, want ErrConcurrentUse", err)
	}
	if err := alice.SetReceivingNonce(7); !errors.Is(err, ErrConcurrentUse) {
		t.Errorf("SetReceivingNonce under held guard: got %v, want ErrConcurrentUse", err)
	}
	// Send side unaffected by the receive guard.
	if _, err := alice.Send([]byte("x"), buf); err != nil {
		t.Errorf("Send blocked by receive guard: %v", err)
	}
	alice.recvInUse.Store(0)

	// After release everything works again.
	if _, err := alice.Send([]byte("y"), buf); err != nil {
		t.Errorf("Send after release: %v", err)
	}
	if err := alice.SetReceivingNonce(0); err != nil {
		t.Errorf("SetReceivingNonce after release: %v", err)
	}
}

// TestTransportState_ConcurrentSendNonceIntegrity hammers Send from many
// goroutines. Every call must either succeed or return ErrConcurrentUse,
// and the nonce counter must advance exactly once per success: a nonce
// reused across two ciphertexts is a complete AEAD break, which is exactly
// what the guard exists to prevent.
func TestTransportState_ConcurrentSendNonceIntegrity(t *testing.T) {
	alice, _ := newTestTransportPair(t)
	defer alice.Destroy()

	const goroutines = 64
	var wg sync.WaitGroup
	results := make([]error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			buf := make([]byte, 1024)
			_, err := alice.Send([]byte("payload"), buf)
			results[idx] = err
		}(i)
	}
	wg.Wait()

	successes := 0
	for i, err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrConcurrentUse):
			// expected under contention
		default:
			t.Fatalf("goroutine %d: unexpected error %v", i, err)
		}
	}
	if successes == 0 {
		t.Fatal("no Send succeeded")
	}
	if got := alice.SendingNonce(); got != uint64(successes) {
		t.Fatalf("nonce advanced %d times for %d successes: nonce reuse or skip", got, successes)
	}
}

// TestTransportState_FullDuplex verifies the documented contract: one
// sender and one receiver may run concurrently (independent directions).
func TestTransportState_FullDuplex(t *testing.T) {
	alice, bob := newTestTransportPair(t)
	defer alice.Destroy()
	defer bob.Destroy()

	const rounds = 100
	var wg sync.WaitGroup
	wg.Add(2)

	errA := make(chan error, 1)
	errB := make(chan error, 1)

	// Alice sends, Bob receives - while Bob sends, Alice receives.
	a2b := make(chan []byte, rounds)
	b2a := make(chan []byte, rounds)

	go func() {
		defer wg.Done()
		buf := make([]byte, 1024)
		out := make([]byte, 1024)
		for i := 0; i < rounds; i++ {
			n, err := alice.Send([]byte("from alice"), buf)
			if err != nil {
				errA <- err
				return
			}
			a2b <- append([]byte{}, buf[:n]...)
			ct := <-b2a
			if _, err := alice.Receive(ct, out); err != nil {
				errA <- err
				return
			}
		}
		errA <- nil
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 1024)
		out := make([]byte, 1024)
		for i := 0; i < rounds; i++ {
			n, err := bob.Send([]byte("from bob"), buf)
			if err != nil {
				errB <- err
				return
			}
			b2a <- append([]byte{}, buf[:n]...)
			ct := <-a2b
			if _, err := bob.Receive(ct, out); err != nil {
				errB <- err
				return
			}
		}
		errB <- nil
	}()
	wg.Wait()

	if err := <-errA; err != nil {
		t.Fatalf("alice: %v", err)
	}
	if err := <-errB; err != nil {
		t.Fatalf("bob: %v", err)
	}
}

// TestTransportState_SetReceivingNonceErrors verifies the new error
// returns: ErrDestroyed after Destroy, nil on success.
func TestTransportState_SetReceivingNonceErrors(t *testing.T) {
	alice, _ := newTestTransportPair(t)

	if err := alice.SetReceivingNonce(42); err != nil {
		t.Fatalf("SetReceivingNonce live: %v", err)
	}
	if got := alice.ReceivingNonce(); got != 42 {
		t.Fatalf("ReceivingNonce: got %d, want 42", got)
	}

	alice.Destroy()
	if err := alice.SetReceivingNonce(7); !errors.Is(err, ErrDestroyed) {
		t.Fatalf("SetReceivingNonce after Destroy: got %v, want ErrDestroyed", err)
	}
}
