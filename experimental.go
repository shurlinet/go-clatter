package clatter

import "sync/atomic"

// AllowExperimental controls whether experimental (pre-FIPS) algorithms can
// be used. Both the constructor-level check ([CipherSuite].Experimental) and
// the KEM-level check in every [KEM].GenerateKeypair, [KEM].Encapsulate, and
// [KEM].Decapsulate call require this to be true for experimental KEMs to
// operate.
//
// Default is false. Set to true before constructing handshakes with
// experimental algorithms:
//
//	clatter.AllowExperimental.Store(true)
//
// This is a process-level policy flag. Race-safe ([sync/atomic.Bool]).
var AllowExperimental atomic.Bool
