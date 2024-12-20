package handshake

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"fmt"
	"os"
	"reflect"

	"github.com/danielpfeifer02/quic-go-prio-packs/crypto_turnoff"
	"golang.org/x/crypto/chacha20poly1305"
)

// These cipher suite implementations are copied from the standard library crypto/tls package.

const aeadNonceLength = 12

type cipherSuite struct {
	ID     uint16
	Hash   crypto.Hash
	KeyLen int
	AEAD   func(key, nonceMask []byte) *xorNonceAEAD
}

func (s cipherSuite) IVLen() int { return aeadNonceLength }

func getCipherSuite(id uint16) *cipherSuite {
	id = tls.TLS_CHACHA20_POLY1305_SHA256 // TODO: why not correctly chosen due to config?
	switch id {
	case tls.TLS_AES_128_GCM_SHA256:
		return &cipherSuite{ID: tls.TLS_AES_128_GCM_SHA256, Hash: crypto.SHA256, KeyLen: 16, AEAD: aeadAESGCMTLS13}
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		return &cipherSuite{ID: tls.TLS_CHACHA20_POLY1305_SHA256, Hash: crypto.SHA256, KeyLen: 32, AEAD: aeadChaCha20Poly1305}
	case tls.TLS_AES_256_GCM_SHA384:
		return &cipherSuite{ID: tls.TLS_AES_256_GCM_SHA384, Hash: crypto.SHA384, KeyLen: 32, AEAD: aeadAESGCMTLS13}

	// NO_CRYPTO_TAG
	// based on https://pkg.go.dev/crypto/tls#pkg-constants 0x0000 is not used for any other cipher suite
	case 0x0000:
		// everything except ID is not used and thus arbitrary
		return &cipherSuite{ID: 0x0000, Hash: 0, KeyLen: 0, AEAD: func(key, nonceMask []byte) *xorNonceAEAD {
			return nil
		}}

	default:
		panic(fmt.Sprintf("unknown cypher suite: %d", id))
	}
}

func aeadAESGCMTLS13(key, nonceMask []byte) *xorNonceAEAD {
	if len(nonceMask) != aeadNonceLength {
		panic("tls: internal error: wrong nonce length")
	}
	aes, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(aes)
	if err != nil {
		panic(err)
	}

	ret := &xorNonceAEAD{aead: aead}
	copy(ret.nonceMask[:], nonceMask)
	return ret
}

func aeadChaCha20Poly1305(key, nonceMask []byte) *xorNonceAEAD {
	if len(nonceMask) != aeadNonceLength { // 96 bit nonce
		panic("tls: internal error: wrong nonce length")
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}

	ret := &xorNonceAEAD{aead: aead}
	copy(ret.nonceMask[:], nonceMask)
	return ret
}

// xorNonceAEAD wraps an AEAD by XORing in a fixed pattern to the nonce
// before each call.
type xorNonceAEAD struct {
	nonceMask [aeadNonceLength]byte
	aead      cipher.AEAD
}

func (f *xorNonceAEAD) NonceSize() int        { return 8 } // 64-bit sequence number
func (f *xorNonceAEAD) Overhead() int         { return f.aead.Overhead() }
func (f *xorNonceAEAD) explicitNonceLen() int { return 0 }

func (f *xorNonceAEAD) Seal(out, nonce, plaintext, additionalData []byte) []byte {

	// NO_CRYPTO_TAG
	if crypto_turnoff.CRYPTO_TURNED_OFF {
		return plaintext
	}

	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}
	result := f.aead.Seal(out, f.nonceMask[:], plaintext, additionalData)
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}

	return result
}

func (f *xorNonceAEAD) Open(out, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	return f.OpenCallerConsidering(out, nonce, ciphertext, additionalData, false)
}

var ctr = 0

func (f *xorNonceAEAD) OpenCallerConsidering(out, nonce, ciphertext, additionalData []byte, longheadercall bool) ([]byte, error) {

	// NO_CRYPTO_TAG
	if crypto_turnoff.CRYPTO_TURNED_OFF {
		return ciphertext, nil
	}

	// fmt.Print("\n\n\nCiphertext: ") // TODO: remove
	// for i := 0; i < len(ciphertext); i++ {
	// 	fmt.Printf("%x ", ciphertext[i])
	// }
	// fmt.Println()

	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}
	// fmt.Println("\nf.aead.Open(...) type: ", reflect.TypeOf(f.aead))
	// fmt.Print("nonce: ")
	for i := 0; i < len(f.nonceMask); i++ {
		// fmt.Printf("%02x ", f.nonceMask[i])
	}
	// fmt.Println()

	nonce_copy := make([]byte, len(nonce)) // TODO: remove
	m := copy(nonce_copy, nonce[:])
	if m != len(nonce) {
		panic("chacha20poly1305: bad nonce length passed to Open")
	}

	// TODONOW: something is wrong here when differentiating if decryption needs to be done or not
	var result []byte
	var err error
	// TODO: remove
	// TODONOW: fix this mess lol
	// BIG_TODO: this part seems to make ebpf crypto not being accepted later on
	if false && !longheadercall && crypto_turnoff.INCOMING_SHORT_HEADER_CRYPTO_TURNED_OFF && reflect.TypeOf(f.aead) == reflect.TypeOf(&chacha20poly1305.Chacha20poly1305{}) {
		// fmt.Println("special case", longheadercall)
		// fmt.Println(hex.Dump(ciphertext))
		result, err = ciphertext, nil
	} else {
		// fmt.Println("normal case", longheadercall)
		// fmt.Println(hex.Dump(ciphertext))

		ciphertext_copy := make([]byte, len(ciphertext))
		copy(ciphertext_copy, ciphertext)

		result, err = f.aead.Open(out, f.nonceMask[:], ciphertext, additionalData)

		if err != nil {
			// fmt.Println("ebpf decryption", ctr)
			// fmt.Println("Number of go routines: ", runtime.NumGoroutine())
			ctr += 1
			// fmt.Println("Manual setting since error occured", err)
			result = ciphertext_copy[:len(ciphertext_copy)-16] // remove aead overhead
			err = nil
		} else {
			// fmt.Println("normal decryption")
		}

		// fmt.Println("translated to: (", len(result), err, ")")
		// fmt.Println(hex.Dump(result))
	}

	for i, b := range nonce { // TODO: remove
		if b != nonce_copy[i] {
			fmt.Println(nonce)
			fmt.Println(nonce_copy)
			panic("nonce changed")
		}
	}

	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}

	// fmt.Print("\n\n\nPlaintext: ") // TODO: remove
	// for i := 0; i < len(result); i++ {
	// 	if (i < 'Z' && i > 'A') || (i < 'z' && i > 'a') {
	// 		fmt.Print(string(result[i]))
	// 	} else {
	// 		fmt.Print("*")
	// 	}
	// }
	// fmt.Println()

	// Debug: write into tmp file
	tmp_file := "/tmp/decrypted_correct"
	file, err := os.OpenFile(tmp_file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	_, err = file.Write(result)
	_, err = file.Write([]byte("\n\n\n"))

	return result, err
}

// EBPF_CRYPTO_TAG
func (f *xorNonceAEAD) Start1RTTCryptoBitstreamStorage(nonce []byte, pn uint64) {
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}
	// nonce_copy := make([]byte, len(nonce)) // TODO: remove
	// m := copy(nonce_copy, nonce[:])
	// if m != len(nonce) {
	// 	panic("chacha20poly1305: bad nonce length passed to Start1RTTCryptoBitstreamStorage")
	// }

	chacha20 := f.aead.(*chacha20poly1305.Chacha20poly1305)
	chacha20.Start1RTTCryptoBitstreamStorage(f.nonceMask[:], pn)

	// for i, b := range nonce { // TODO: remove
	// 	if b != nonce_copy[i] {
	// 		fmt.Println(nonce)
	// 		fmt.Println(nonce_copy)
	// 		panic("nonce changed")
	// 	}
	// }

	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}
}
