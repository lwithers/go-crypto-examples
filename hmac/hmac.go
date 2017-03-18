package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
)

var (
	// Secret is some secret data (of arbitrary length and content) shared
	// between two parties.
	Secret = []byte("HMAC secret key")
)

func main() {
	msg := BuildAuthenticatedMessage("hello, world!", Secret)
	VerifyAuthenticatedMessage(msg, Secret)
}

// BuildAuthenticatedMessage returns MESSAGE+DIGEST, where DIGEST is an HMAC
// using the specified secret key.
func BuildAuthenticatedMessage(msg string, secret []byte) []byte {
	// The HMAC object uses an underlying hash function. You should use the
	// SHA-2 family. The SHA-512 variants are preferred if you are primarily
	// working on 64-bit machines, and SHA-256 for 32-bit machines.
	hm := hmac.New(sha512.New512_256, secret)

	// allocate output buffer
	out := make([]byte, len(msg), len(msg)+hm.Size())
	copy(out, []byte(msg))

	// compute the HMAC, and append the result to the output buffer
	hm.Write([]byte(msg))
	return hm.Sum(out)
}

// VerifyAuthenticatedMessage checks that the DIGEST is valid for the given
// secret key when presented with MESSAGE+DIGEST.
func VerifyAuthenticatedMessage(msg, secret []byte) {
	// same as BuildAuthenticatedMessage
	hm := hmac.New(sha512.New512_256, secret)

	if len(msg) < hm.Size() {
		fmt.Printf("authenticated message too short (%d bytes); need "+
			"at least %d bytes\n", len(msg), hm.Size())
		return
	}

	// split message and digest
	digest := msg[len(msg)-hm.Size():]
	msg = msg[:len(msg)-hm.Size()]

	// compute HMAC over the original message
	hm.Write(msg)
	computed := hm.Sum(nil)

	// compare the result — note we *MUST* use hmac.Equal, and not
	// bytes.Compare, because we need a constant-time comparison to avoid
	// timing attacks.
	if hmac.Equal(computed, digest) {
		fmt.Printf("message verified: %q\n", msg)
	} else {
		fmt.Printf("message NOT verified: %q\n", msg)
	}
}
