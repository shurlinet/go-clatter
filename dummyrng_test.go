package clatter

import "testing"

func TestDummyRng_MatchesRust(t *testing.T) {
	rng := NewDummyRng(0xdeadbeef)

	// First byte: 0xdeadbeef % 256 = 0xef = 239
	// Second byte: 0xdeadbef0 % 256 = 0xf0 = 240
	// Third byte: 0xdeadbef1 % 256 = 0xf1 = 241
	buf := make([]byte, 4)
	n, err := rng.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 {
		t.Fatalf("expected 4 bytes, got %d", n)
	}

	expected := []byte{0xef, 0xf0, 0xf1, 0xf2}
	for i, b := range buf {
		if b != expected[i] {
			t.Fatalf("byte %d: expected %02x, got %02x", i, expected[i], b)
		}
	}
}

func TestDummyRng_CounterWraps(t *testing.T) {
	// Verify byte-level wrapping at 256 boundary
	rng := NewDummyRng(0xfe) // starts at 254
	buf := make([]byte, 4)
	rng.Read(buf)

	expected := []byte{0xfe, 0xff, 0x00, 0x01}
	for i, b := range buf {
		if b != expected[i] {
			t.Fatalf("byte %d: expected %02x, got %02x", i, expected[i], b)
		}
	}
}

func TestDummyRng_ConsecutiveCalls(t *testing.T) {
	rng := NewDummyRng(0)
	buf1 := make([]byte, 2)
	buf2 := make([]byte, 2)
	rng.Read(buf1) // consumes counter 0, 1
	rng.Read(buf2) // consumes counter 2, 3

	if buf1[0] != 0 || buf1[1] != 1 {
		t.Fatalf("first read: %v", buf1)
	}
	if buf2[0] != 2 || buf2[1] != 3 {
		t.Fatalf("second read: %v", buf2)
	}
}
