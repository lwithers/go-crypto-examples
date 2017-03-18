package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/sys/unix"
)

var (
	// UseScrypt should be set to true to use scrypt, or false to use
	// PBKDF2. Most applications will prefer scrypt, but PBKDF2 is more
	// standardised and has likely undergone higher scrutiny.
	UseScrypt = true

	// MagicMarker is written to the start of a file to denote that it is
	// a file encrypted by this demo application. The values are random.
	MagicMarker = []byte{82, 73, 195, 42, 241, 111, 151, 103}
)

// Changing any of these constants will result in an incompatible
// implementation. Various techniques to counter this would be:
// - use a different magic marker
// - extend the flags mechanism already in place
// - add a version number field, and every time you change the parameter set
//   you bump the version number
// - record the parameters in the file header
const (
	// AESKeySize is the size of AES key used. We should use AES-256 in line
	// with standards recommendations (e.g. NIST 2016:
	// https://www.keylength.com/en/4/).
	AESKeySize = 32 // 32×8 bits = 256

	// SaltSize is the size of the salt parameter to scrypt/pbkdf2.
	// Recommendations are that this should be at least 8 bytes:
	//  https://tools.ietf.org/html/rfc2898
	SaltSize = 16

	// GCMStandardNonceSize is the size of the initialisation vector (or
	// nonce) that is used by the GCM cipher.
	GCMStandardNonceSize = 12

	// Scrypt_N is the CPU/memory cost factor for scrypt.
	Scrypt_N = 1 << 16

	// Scrypt_r is the blocksize, and is typically set to 8.
	Scrypt_r = 8

	// Scrypt_p is the parallelisation factor, and is typically 1 or 16.
	Scrypt_p = 16

	// Pbkdf2Iterations is the number of iterations performed by the PBKDF2
	// algorithm. More iterations takes longer but makes it harder to guess
	// the password. NIST recommend this is set to at least 10000:
	// https://pages.nist.gov/800-63-3/sp800-63b.html#sec5 (§5.1.1.2, last
	// paragraph).
	Pbkdf2Iterations = 10000
)

// Flags used in encrypted file headers.
const (
	// FlagUsesScrypt notes that the file's key was derived using script. If
	// not set, the key was derived using PBKDF2.
	FlagUsesScrypt = 1 << iota
)

func main() {
	// read the input file into memory
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "expecting name of file")
		os.Exit(1)
	}
	fileName := os.Args[1]

	fileData, err := ioutil.ReadFile(fileName)
	defer Clear(fileData) // in case it is plaintext
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// read password from the user
	fmt.Print("Enter password: ")
	passwd, err := terminal.ReadPassword(unix.Stdin)
	fmt.Print("\n")
	defer Clear(passwd)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to read password: ", err)
		os.Exit(1)
	}

	// if the input file has our magic signature, then decrypt; else encrypt
	if IsEncrypted(fileData) {
		target := fileName + ".decrypted"
		err = Decrypt(fileData, passwd, target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to decrypt %q: %v\n",
				fileName, err)
			os.Exit(1)
		}
		fmt.Printf("%q decrypted successfully into %q\n",
			fileName, target)
		return
	}

	target := fileName + ".encrypted"
	if err = Encrypt(fileData, passwd, target); err != nil {
		fmt.Fprintf(os.Stderr, "failed to encrypt %q: %v\n",
			fileName, err)
		os.Exit(1)
	}
	fmt.Printf("%q encrypted successfully into %q\n", fileName, target)
}

// Clear clears some data from memory by overwriting it with a constant bit
// pattern.
func Clear(data []byte) {
	for i := range data {
		data[i] = 0xAA
	}
}

// DeriveCipher returns a cipher object suitable for encrypting and decrypting
// data.
func DeriveCipher(password, keySalt []byte) (cipher.AEAD, error) {
	var (
		key []byte
		err error
	)

	// first derive an AES-256 key from the password and salt
	if UseScrypt {
		key, err = scrypt.Key(password, keySalt, Scrypt_N, Scrypt_r,
			Scrypt_p, AESKeySize)
	} else {
		// we choose to use the SHA-512 hash algorithm with PBKDF2
		key = pbkdf2.Key(password, keySalt, Pbkdf2Iterations,
			AESKeySize, sha512.New)
	}
	if err != nil {
		return nil, err
	}

	// now build a cipher object
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// IsEncrypted reports whether the file starts with our magic marker.
func IsEncrypted(data []byte) bool {
	return len(data) > len(MagicMarker)+4+SaltSize+GCMStandardNonceSize &&
		bytes.HasPrefix(data, MagicMarker)
}

// Decrypt a file.
func Decrypt(ciphertext, passwd []byte, filename string) error {
	// read the header (we already tested for enough bytes in IsEncrypted)
	header := ciphertext
	pos := len(MagicMarker)
	flags := binary.LittleEndian.Uint32(header[pos:])
	pos += 4
	keySalt := header[pos : pos+SaltSize]
	pos += SaltSize
	gcmNonce := header[pos : pos+GCMStandardNonceSize]
	pos += GCMStandardNonceSize
	header = header[:pos] // now only points over actual header

	// update slice header so it only points over the actual ciphertext
	ciphertext = ciphertext[pos:]

	// check flags
	if (flags & FlagUsesScrypt) != 0 {
		flags &^= FlagUsesScrypt
		UseScrypt = true
	} else {
		UseScrypt = false
	}
	if flags != 0 {
		return fmt.Errorf("unrecognised flags 0x%08X", flags)
	}

	// build a decryption object from the password and the recorded salt
	gcm, err := DeriveCipher(keySalt, passwd)
	if err != nil {
		return err
	}

	// Perform the decryption.
	//  We supply the previously-recorded nonce (which doesn't need to be
	//  kept secret). We also ask for the file header to be authenticated,
	//  which prevents anyone from e.g. changing the flags without us
	//  noticing.
	plaintext, err := gcm.Open(nil, gcmNonce, ciphertext, header)
	defer Clear(plaintext)
	if err != nil {
		return err
	}

	// now write out the plaintext file
	return ioutil.WriteFile(filename, plaintext, 0600)
}

// Encrypt a file.
func Encrypt(plaintext, passwd []byte, filename string) error {
	w := bytes.NewBuffer(make([]byte, 0, len(plaintext)+200))
	w.Write(MagicMarker) // signifies this is an encrypted file

	// prepare flags
	var flags uint32
	if UseScrypt {
		flags |= FlagUsesScrypt
	}
	var x [4]byte
	binary.LittleEndian.PutUint32(x[:], flags)
	w.Write(x[:])

	// generate and record salt for key derivation
	//  (note that you do not need to keep the salt data secret, but you
	//  will need it to derive the same key from the password again later,
	//  so it must be written in plaintext).
	keySalt := make([]byte, SaltSize)
	if _, err := rand.Read(keySalt); err != nil {
		// on Linux this should basically never happen, it would be
		// appropriate to panic() here
		return fmt.Errorf("failed to read %d random bytes for salt: %v",
			SaltSize, err)
	}
	w.Write(keySalt)

	// generate and record initialisation vector for encryption
	//  (note that you do not need to keep the nonce data secret, but you
	//  will need it to decrypt the file, so it must be written in
	//  plaintext).
	gcmNonce := make([]byte, GCMStandardNonceSize)
	if _, err := rand.Read(gcmNonce); err != nil {
		return fmt.Errorf("failed to read %d random bytes for GCM: %v",
			GCMStandardNonceSize, err)
	}
	w.Write(gcmNonce)

	// build an encryption object from the password and the generated salt
	gcm, err := DeriveCipher(keySalt, passwd)
	if err != nil {
		return err
	}

	// Perform the encryption.
	//  We ask for the file header which has so far been written to w to be
	//  authenticated too. This means that decryption will fail if anyone
	//  tampers with the file header.
	ciphertext := gcm.Seal(nil, gcmNonce, plaintext, w.Bytes())
	w.Write(ciphertext)

	// write out the encrypted file
	return ioutil.WriteFile(filename, w.Bytes(), 0600)
}
