package main

import (
	"crypto"
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	"reflect"
	"unsafe"

	// since we're not directly referencing the hash algorithm packages, we
	// must tell Go to link the relevant ones in to our executable
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
)

var (
	// SharedSecret is known only to the two parties who are trying to
	// communicate. It typically includes a separator section that cannot
	// occur in the messages to be authenticated.
	SharedSecret = []byte("special secret\x00")

	// Hash is the type of hash algorithm to use. Feel free to change it
	// to experiment. Using a truncated SHA-2 form (e.g. SHA384) will cause
	// the attack to fail. Remember to link in the hash algorithm by using
	// an underscore import above!
	Hash crypto.Hash = crypto.SHA256
)

func main() {
	// show that message authentication succeeds
	verifiedMsg := BADAuthenticate("first message")
	BADVerifyAuthentic(verifiedMsg)

	// now show an attack — note that the attack needs to know the length
	// of the shared secret (modulo the hash block size), but since you can
	// quickly and easily iterate over all the possible values, we just take
	// a shortcut for this example and pass it in as a parameter.
	verifiedMsg = BADAuthenticate("second message")
	guessedLen := len(SharedSecret) % Hash.New().BlockSize()
	verifiedMsg = Attack(verifiedMsg, guessedLen)
	BADVerifyAuthentic(verifiedMsg)
}

// BADVerifyAuthentic takes a message composed of MESSAGE+DIGEST, and verifies
// that DIGEST is correct. DIGEST is computed as the hash over
// SharedSecret+MESSAGE.
//
// This is a BAD example. Do not copy this. Use an HMAC instead.
func BADVerifyAuthentic(msg []byte) {
	// DIGEST is found at the end, so slice it off
	if len(msg) < Hash.Size() {
		fmt.Printf("cannot verify message (%d bytes), as it is too "+
			"short (hash is %d bytes)\n", len(msg), Hash.Size())
		return
	}
	digest := msg[len(msg)-Hash.Size():]
	msg = msg[:len(msg)-Hash.Size()]

	// compute our own digest over the message
	md := Hash.New()
	md.Write(SharedSecret)
	md.Write(msg)
	computed := md.Sum(nil)

	// compare the digest
	//  NB: to avoid timing attacks, we must use a constant-time compare
	if hmac.Equal(digest, computed) {
		fmt.Printf("message verified: %q\n", msg)
	} else {
		fmt.Printf("message NOT verified: %q\n", msg)
	}
}

// BADAuthenticate computes a DIGEST incorporating SharedSecret over the given
// message, returning MESSAGE+DIGEST.
//
// This is a BAD example. Do not copy this. Use an HMAC instead.
func BADAuthenticate(msg string) []byte {
	// prepare buffer holding MESSAGE, with enough capacity to add DIGEST
	result := make([]byte, len(msg), len(msg)+Hash.Size())
	copy(result, []byte(msg))

	// compute digest over the message
	md := Hash.New()
	md.Write(SharedSecret)
	md.Write([]byte(msg))

	// this will append the DIGEST into result
	return md.Sum(result)
}

// Attack pulls apart a verified MESSAGE+DIGEST pair, extends MESSAGE, and
// updates DIGEST. Note that it doesn't know about or use SharedSecret!
func Attack(msg []byte, guessedSecretLen int) []byte {
	// DIGEST is found at the end, so slice it off
	if len(msg) < Hash.Size() {
		fmt.Printf("cannot attack message (%d bytes), as it is too "+
			"short (hash is %d bytes)\n", len(msg), Hash.Size())
		return nil
	}
	digest := msg[len(msg)-Hash.Size():]
	msg = msg[:len(msg)-Hash.Size()]

	modifiedMsg := make([]byte, len(msg), len(msg)+200)
	copy(modifiedMsg, msg)

	// Go's built-in hash functions aren't particularly amenable to being
	// used for length extension attacks, since they encapsulate the state.
	// We have to jump through quite some hoops to get there, and this code
	// will probably crash on anything where my assumptions about the memory
	// layout don't hold true.
	//
	// This won't deter an attacker. They'll have their own hash
	// implementation that will be adapted so you can trivially re-load the
	// internal state.

	md := Hash.New()
	mdptr := reflect.ValueOf(md).Pointer()

	// we assume that the in-memory layout is as follows:
	//  Hash.Size() * byte      → the digest
	//                            NB1: encoded as native-endian unsigned int
	//                            NB2: pad to next power-of-2
	//  Hash.BlockSize() * byte → partial block data
	//  int                     → bytes used in partial block data
	//  int64                   → size of message

	// copy in the digest thus far
	switch Hash {
	// algorithms with 64-bit words
	case crypto.SHA512_224, crypto.SHA512_256, crypto.SHA384, crypto.SHA512:
		for pos := 0; pos < len(digest); pos += 8 {
			h := binary.BigEndian.Uint64(digest[pos:])
			ptr := (*uint64)(unsafe.Pointer(mdptr + uintptr(pos)))
			*ptr = h
		}

	// algorithms with 32-bit words
	default:
		for pos := 0; pos < len(digest); pos += 4 {
			h := binary.BigEndian.Uint32(digest[pos:])
			ptr := (*uint32)(unsafe.Pointer(mdptr + uintptr(pos)))
			*ptr = h
		}
	}

	// compute the length as it would be recorded in the padding
	l := int64(guessedSecretLen + len(msg))

	// pad up to next block boundary, but ensure there is > 8 bytes
	padLen := md.BlockSize() - int(l)%md.BlockSize()
	if padLen <= 8 {
		padLen += md.BlockSize()
	}

	// record length-including-padding back into our digest state
	var sizePos uintptr
	if Hash == crypto.SHA1 {
		// length is last element in the digest struct
		sizePos = reflect.TypeOf(md).Elem().Size() - 8
	} else {
		// length is last-but-one element in the digest struct
		sizePos = reflect.TypeOf(md).Elem().Size() - 16
	}
	l1ptr := (*int64)(unsafe.Pointer(mdptr + sizePos))
	*l1ptr = l + int64(padLen)

	// figure out the padding at the end of the block — this will need to be
	// incorporated into our attack data
	attackPad := make([]byte, padLen)
	attackPad[0] = 0x80
	binary.BigEndian.PutUint64(attackPad[padLen-8:], uint64(l)<<3)
	modifiedMsg = append(modifiedMsg, attackPad...)

	// now we can append our attack message!
	attackMsg := []byte("attack!")
	md.Write(attackMsg)
	modifiedMsg = append(modifiedMsg, attackMsg...)

	// write the new, modified DIGEST into our result
	return md.Sum(modifiedMsg)
}
