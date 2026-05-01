package clatter

import (
	"bytes"
	"testing"
)

func TestSecretKey32_NewAndBytes(t *testing.T) {
	data := make([]byte, 32)
	for i := range data {
		data[i] = byte(i)
	}
	k, err := NewSecretKey32(data)
	if err != nil {
		t.Fatal(err)
	}
	got := k.Bytes()
	if !bytes.Equal(got[:], data) {
		t.Fatalf("Bytes() mismatch")
	}
}

func TestSecretKey32_InvalidLength(t *testing.T) {
	_, err := NewSecretKey32(make([]byte, 16))
	if err != ErrInvalidKeyLength {
		t.Fatalf("expected ErrInvalidKeyLength, got %v", err)
	}
}

func TestSecretKey32_Destroy(t *testing.T) {
	data := make([]byte, 32)
	for i := range data {
		data[i] = 0xff
	}
	k, _ := NewSecretKey32(data)
	k.Destroy()

	if !k.IsDestroyed() {
		t.Fatal("expected destroyed")
	}
	// Verify all bytes zeroed
	for i, b := range k.key {
		if b != 0 {
			t.Fatalf("byte %d not zeroed: %02x", i, b)
		}
	}
}

func TestSecretKey32_DestroyedPanics(t *testing.T) {
	k, _ := NewSecretKey32(make([]byte, 32))
	k.Destroy()

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on Bytes() after Destroy()")
		}
	}()
	_ = k.Bytes()
}

func TestSecretKey32_Equal(t *testing.T) {
	a, _ := NewSecretKey32(bytes.Repeat([]byte{0x42}, 32))
	b, _ := NewSecretKey32(bytes.Repeat([]byte{0x42}, 32))
	c, _ := NewSecretKey32(bytes.Repeat([]byte{0x43}, 32))

	if !a.Equal(&b) {
		t.Fatal("equal keys should be equal")
	}
	if a.Equal(&c) {
		t.Fatal("different keys should not be equal")
	}

	a.Destroy()
	if a.Equal(&b) {
		t.Fatal("destroyed key should not equal anything")
	}
}

func TestSecretKey64_Lifecycle(t *testing.T) {
	data := make([]byte, 64)
	for i := range data {
		data[i] = byte(i)
	}
	k, err := NewSecretKey64(data)
	if err != nil {
		t.Fatal(err)
	}
	got := k.Bytes()
	if !bytes.Equal(got[:], data) {
		t.Fatal("Bytes() mismatch")
	}

	k.Destroy()
	if !k.IsDestroyed() {
		t.Fatal("expected destroyed")
	}
	for i, b := range k.key {
		if b != 0 {
			t.Fatalf("byte %d not zeroed", i)
		}
	}
}

func TestSecretKey64_DestroyedPanicsBytes(t *testing.T) {
	k, _ := NewSecretKey64(make([]byte, 64))
	k.Destroy()

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on Bytes() after Destroy()")
		}
	}()
	_ = k.Bytes()
}

func TestSecretKey64_DestroyedPanicsSlice(t *testing.T) {
	k, _ := NewSecretKey64(make([]byte, 64))
	k.Destroy()

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on Slice() after Destroy()")
		}
	}()
	_ = k.Slice()
}

func TestSecretKey32_DestroyedPanicsSlice(t *testing.T) {
	k, _ := NewSecretKey32(make([]byte, 32))
	k.Destroy()

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on Slice() after Destroy()")
		}
	}()
	_ = k.Slice()
}

func TestSecretKey64_Equal(t *testing.T) {
	a, _ := NewSecretKey64(bytes.Repeat([]byte{0x42}, 64))
	b, _ := NewSecretKey64(bytes.Repeat([]byte{0x42}, 64))
	c, _ := NewSecretKey64(bytes.Repeat([]byte{0x43}, 64))

	if !a.Equal(&b) {
		t.Fatal("equal keys should be equal")
	}
	if a.Equal(&c) {
		t.Fatal("different keys should not be equal")
	}

	a.Destroy()
	if a.Equal(&b) {
		t.Fatal("destroyed key should not equal anything")
	}
}

func TestSecretKey64_InvalidLength(t *testing.T) {
	_, err := NewSecretKey64(make([]byte, 32))
	if err != ErrInvalidKeyLength {
		t.Fatalf("expected ErrInvalidKeyLength, got %v", err)
	}
}

func TestConstants(t *testing.T) {
	if MaxMessageLen != 65535 {
		t.Fatal("MaxMessageLen wrong")
	}
	if PSKLen != 32 {
		t.Fatal("PSKLen wrong")
	}
	if MaxPSKs != 4 {
		t.Fatal("MaxPSKs wrong")
	}
	if MaxHashLen != 64 {
		t.Fatal("MaxHashLen wrong")
	}
	if KeyLen != 32 {
		t.Fatal("KeyLen wrong")
	}
	if TagLen != 16 {
		t.Fatal("TagLen wrong")
	}
}

func TestKeyPair_SecretIsolation(t *testing.T) {
	pub := []byte{1, 2, 3}
	sec := []byte{4, 5, 6}
	kp := NewKeyPair(pub, sec)

	// Modifying original should not affect keypair
	pub[0] = 99
	sec[0] = 99
	if kp.Public[0] != 1 {
		t.Fatal("public key not copied")
	}
	if kp.SecretSlice()[0] != 4 {
		t.Fatal("secret key not copied")
	}
}

func TestKeyPair_Destroy(t *testing.T) {
	kp := NewKeyPair([]byte{1}, []byte{0xff, 0xfe})
	kp.Destroy()
	for i, b := range kp.SecretSlice() {
		if b != 0 {
			t.Fatalf("secret byte %d not zeroed", i)
		}
	}
}

func TestKeyPair_Clone(t *testing.T) {
	kp := NewKeyPair([]byte{1, 2}, []byte{3, 4})
	clone := kp.Clone()

	if !bytes.Equal(kp.Public, clone.Public) {
		t.Fatal("public mismatch")
	}
	if !bytes.Equal(kp.SecretSlice(), clone.SecretSlice()) {
		t.Fatal("secret mismatch")
	}

	// Mutating clone should not affect original
	clone.Public[0] = 99
	if kp.Public[0] == 99 {
		t.Fatal("clone shares public memory")
	}
}

func TestPSKQueue_PushPop(t *testing.T) {
	var q PSKQueue
	psk := bytes.Repeat([]byte{0xab}, 32)

	if err := q.Push(psk); err != nil {
		t.Fatal(err)
	}
	if q.Len() != 1 {
		t.Fatal("expected len 1")
	}

	got, err := q.Pop()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:], psk) {
		t.Fatal("pop mismatch")
	}
	if q.Len() != 0 {
		t.Fatal("expected len 0 after pop")
	}
}

func TestPSKQueue_FIFO(t *testing.T) {
	var q PSKQueue
	for i := 0; i < 4; i++ {
		if err := q.Push(bytes.Repeat([]byte{byte(i)}, 32)); err != nil {
			t.Fatal(err)
		}
	}

	for i := 0; i < 4; i++ {
		got, err := q.Pop()
		if err != nil {
			t.Fatal(err)
		}
		if got[0] != byte(i) {
			t.Fatalf("expected %d, got %d", i, got[0])
		}
	}
}

func TestPSKQueue_Full(t *testing.T) {
	var q PSKQueue
	for i := 0; i < 4; i++ {
		q.Push(bytes.Repeat([]byte{byte(i)}, 32))
	}
	err := q.Push(bytes.Repeat([]byte{0xff}, 32))
	if err != ErrPSKQueueFull {
		t.Fatalf("expected ErrPSKQueueFull, got %v", err)
	}
}

func TestPSKQueue_InvalidLength(t *testing.T) {
	var q PSKQueue
	err := q.Push([]byte{1, 2, 3})
	if err != ErrPSKInvalid {
		t.Fatalf("expected ErrPSKInvalid, got %v", err)
	}
}

func TestPSKQueue_PopEmpty(t *testing.T) {
	var q PSKQueue
	_, err := q.Pop()
	if err != ErrPSKInvalid {
		t.Fatalf("expected ErrPSKInvalid, got %v", err)
	}
}

func TestPSKQueue_ZerosFreedSlot(t *testing.T) {
	var q PSKQueue
	q.Push(bytes.Repeat([]byte{0xff}, 32))
	q.Push(bytes.Repeat([]byte{0xee}, 32))
	q.Pop() // removes 0xff, shifts 0xee to slot 0, zeros slot 1

	// Slot 1 should be zeroed
	for _, b := range q.keys[1] {
		if b != 0 {
			t.Fatal("freed slot not zeroed")
		}
	}
}

func TestPSKQueue_Destroy(t *testing.T) {
	var q PSKQueue
	for i := 0; i < 4; i++ {
		q.Push(bytes.Repeat([]byte{0xff}, 32))
	}
	q.Destroy()
	if q.Len() != 0 {
		t.Fatal("expected len 0 after destroy")
	}
	for i := range q.keys {
		for _, b := range q.keys[i] {
			if b != 0 {
				t.Fatal("not all zeroed after destroy")
			}
		}
	}
}
