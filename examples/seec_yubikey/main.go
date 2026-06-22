// YubiKey-backed SEEC for go-clatter: a hardware-hedged SEEC secret.
//
// go-clatter has ZERO hardware dependency. The clatter.SEEC interface is the
// seam; this example implements it consumer-side by shelling out to YubiKey's
// `ykman` CLI. The library never imports it, and ships no hardware code.
//
// Two forms are shown:
//
//   - Boot-derive (DEFAULT, recommended): ONE HMAC-SHA1 challenge-response at
//     startup derives a 32-byte software SEEC secret, which then drives
//     clatter.NewSEECPRF at full speed. The device gates startup, not every
//     handshake. The 20-byte device secret never leaves the key.
//
//   - Per-call (-percall): deviceSEEC implements clatter.SEEC with the device
//     in EVERY GenRand call - the device IS the keyed PRF. Non-extractable,
//     but one touch + USB round-trip per draw (1-2 per pqNN handshake). Too
//     slow for a hot path and incompatible with headless nodes. The pure form,
//     for illustration; prefer boot-derive.
//
// SEEC is self-protective: enable it for your OWN party (here the initiator).
// SEEC is opt-in hedging - losing the key loses only the hedge, not the
// ability to handshake. Never make hardware SEEC a critical path.
//
// Requirements: `ykman` installed; a YubiKey with an HMAC-SHA1
// challenge-response credential in the chosen OTP slot, configured for
// variable-length challenges. On macOS the host app needs Input Monitoring
// permission (the OTP slot enumerates as a keyboard HID; without it ykman
// fails to open the device).
//
// Run: go run ./examples/seec_yubikey/ [-slot 2] [-percall]
package main

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	clatter "github.com/shurlinet/go-clatter"
	"github.com/shurlinet/go-clatter/crypto/cipher"
	"github.com/shurlinet/go-clatter/crypto/hash"
	"github.com/shurlinet/go-clatter/crypto/kem"
)

// bootLabel is the FIXED challenge used once at startup to derive the software
// SEEC secret. It must never change for a deployment: the same label over the
// same device slot yields the same derived secret, so the SEEC secret is
// stable across restarts (until the slot is reprovisioned).
const bootLabel = "go-clatter/seec/yubikey/boot-derive/v1"

func check(step string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", step, err)
		os.Exit(1)
	}
}

// ykmanChallengeResponse sends challenge to the YubiKey HMAC-SHA1 slot and
// returns the 20-byte response. Touch-required slots block until the key is
// touched (the key blinks). This is the ONLY device-touching code in the
// program; it shells out to ykman so go-clatter carries no hardware dependency.
func ykmanChallengeResponse(slot int, challenge []byte) ([]byte, error) {
	cmd := exec.Command("ykman", "otp", "calculate", fmt.Sprint(slot), hex.EncodeToString(challenge))
	cmd.Stderr = os.Stderr // surface ykman's "Touch your YubiKey..." prompt live
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("ykman otp calculate slot %d: %w", slot, err)
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return nil, fmt.Errorf("ykman returned no response")
	}
	resp, err := hex.DecodeString(fields[len(fields)-1])
	if err != nil {
		return nil, fmt.Errorf("decode hex response: %w", err)
	}
	if len(resp) != 20 {
		return nil, fmt.Errorf("expected 20-byte HMAC-SHA1 response, got %d bytes", len(resp))
	}
	return resp, nil
}

// deriveBootSecret performs ONE challenge-response over the fixed boot label
// and HKDF-expands the 20-byte response into a 32-byte SEEC secret.
func deriveBootSecret(slot int) ([]byte, error) {
	resp, err := ykmanChallengeResponse(slot, []byte(bootLabel))
	if err != nil {
		return nil, err
	}
	secret, err := hkdf.Key(sha256.New, resp, nil, bootLabel, 32)
	if err != nil {
		return nil, fmt.Errorf("hkdf derive: %w", err)
	}
	return secret, nil
}

// deviceSEEC is the raw per-call hardware SEEC: the YubiKey computes a fresh
// HMAC over each draw's random challenge. It satisfies clatter.SEEC.
type deviceSEEC struct{ slot int }

func (d deviceSEEC) GenRand(rng io.Reader, purpose clatter.SEECPurpose, n int) ([]byte, error) {
	if n < 1 || n > 255 {
		return nil, fmt.Errorf("n out of range [1,255]: %d", n)
	}
	r := make([]byte, 32) // fresh entropy = the challenge (the freshness source)
	if _, err := io.ReadFull(rng, r); err != nil {
		return nil, fmt.Errorf("read rng: %w", err)
	}
	resp, err := ykmanChallengeResponse(d.slot, r)
	if err != nil {
		return nil, err
	}
	info := fmt.Sprintf("%s/purpose=%d", bootLabel, purpose)
	out, err := hkdf.Key(sha256.New, resp, nil, info, n)
	if err != nil {
		return nil, fmt.Errorf("hkdf expand: %w", err)
	}
	return out, nil
}

func main() {
	slot := flag.Int("slot", 2, "YubiKey OTP slot with the HMAC-SHA1 challenge-response credential")
	perCall := flag.Bool("percall", false, "use raw per-call hardware SEEC instead of boot-derive")
	flag.Parse()

	var seecImpl clatter.SEEC
	if *perCall {
		fmt.Printf("Per-call hardware SEEC on slot %d: the device signs EVERY draw - touch when it blinks.\n", *slot)
		seecImpl = deviceSEEC{slot: *slot}
	} else {
		fmt.Printf("Boot-derive from slot %d: ONE touch derives a software SEEC secret. Touch when it blinks.\n", *slot)
		secret, err := deriveBootSecret(*slot)
		check("boot-derive", err)
		prf, err := clatter.NewSEECPRF(hash.NewSha256(), secret)
		check("NewSEECPRF", err)
		for i := range secret { // NewSEECPRF copied it; zero our copy
			secret[i] = 0
		}
		defer prf.Destroy()
		seecImpl = prf
		fmt.Println("Derived a 32-byte SEEC secret; the 20-byte device secret never left the key.")
	}

	suite := clatter.CipherSuite{
		EKEM:   kem.NewMlKem768(),
		SKEM:   kem.NewMlKem768(),
		Cipher: cipher.NewChaChaPoly(),
		Hash:   hash.NewSha512(),
	}

	// Self-protective: the initiator hedges its own coins with the hardware
	// secret. The responder runs plain - SEEC is transparent to the wire.
	alice, err := clatter.NewPqHandshake(clatter.PatternPqNN, true, suite, clatter.WithSEEC(seecImpl))
	check("alice NewPqHandshake", err)
	bob, err := clatter.NewPqHandshake(clatter.PatternPqNN, false, suite)
	check("bob NewPqHandshake", err)

	buf := make([]byte, 4096)
	out := make([]byte, 4096)

	// e -->
	n, err := alice.WriteMessage(nil, buf)
	check("alice WriteMessage 1", err)
	_, err = bob.ReadMessage(buf[:n], out)
	check("bob ReadMessage 1", err)

	// <-- ekem
	n, err = bob.WriteMessage(nil, buf)
	check("bob WriteMessage 2", err)
	_, err = alice.ReadMessage(buf[:n], out)
	check("alice ReadMessage 2", err)

	if !alice.IsFinished() || !bob.IsFinished() {
		fmt.Fprintln(os.Stderr, "handshake not finished")
		os.Exit(1)
	}
	fmt.Println("pqNN handshake complete with a YubiKey-backed SEEC hedge on the initiator.")
}
