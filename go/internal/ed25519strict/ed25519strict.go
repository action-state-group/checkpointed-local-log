// Package ed25519strict checks Ed25519 signatures on checkpoints and receipts
// the same way as every other CLL implementation
// (checkpoint-conformance-vectors/ed25519-vectors.json).
//
// crypto/ed25519 accepts a signature by a small-order public key, which
// anyone can make without a private key: when [k]A is the identity, R = rB
// and S = r satisfy [S]B = R + [k]A. It also accepts an identity R and
// non-canonical encodings of A. This package refuses those before handing
// the rest to crypto/ed25519, whose check is cofactorless and refuses S >= L.
package ed25519strict

import (
	"crypto/ed25519"
	"math/big"

	"github.com/veraison/go-cose"
)

var (
	fieldPrime = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	// smallOrderY holds the y coordinates of the eight small-order points:
	// 0 (order 4), 1 (the identity), p - 1 (order 2), and the order-8 pair
	// c and p - c. A canonical encoding with one of these is of small order
	// whatever its sign bit.
	smallOrderY = func() []*big.Int {
		c, _ := new(big.Int).SetString("05fc536d880238b13933c6d305acdfd5f098eff289f4c345b027b2c28f95e826", 16)
		return []*big.Int{
			big.NewInt(0), big.NewInt(1), new(big.Int).Sub(fieldPrime, big.NewInt(1)),
			c, new(big.Int).Sub(fieldPrime, c),
		}
	}()
)

// acceptablePoint reports whether a 32-byte point encoding has y < p and is
// not one of the small-order points.
func acceptablePoint(encoded []byte) bool {
	littleEndian := make([]byte, 32)
	for i := range littleEndian {
		littleEndian[31-i] = encoded[i]
	}
	littleEndian[0] &= 0x7f
	y := new(big.Int).SetBytes(littleEndian)
	if y.Cmp(fieldPrime) >= 0 {
		return false
	}
	for _, small := range smallOrderY {
		if y.Cmp(small) == 0 {
			return false
		}
	}
	return true
}

// Verify reports whether signature is a valid Ed25519 signature of message
// by publicKey, refusing non-canonical or small-order A and R.
func Verify(publicKey, message, signature []byte) bool {
	if len(publicKey) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return false
	}
	if !acceptablePoint(publicKey) || !acceptablePoint(signature[:32]) {
		return false
	}
	return ed25519.Verify(publicKey, message, signature)
}

// Verifier is a go-cose EdDSA verifier that checks with Verify.
type Verifier struct{ publicKey []byte }

var _ cose.Verifier = Verifier{}

// NewVerifier copies publicKey into a go-cose EdDSA verifier.
func NewVerifier(publicKey ed25519.PublicKey) Verifier {
	return Verifier{publicKey: append([]byte(nil), publicKey...)}
}

// Algorithm implements cose.Verifier.
func (Verifier) Algorithm() cose.Algorithm { return cose.AlgorithmEdDSA }

// Verify implements cose.Verifier.
func (v Verifier) Verify(content, signature []byte) error {
	if !Verify(v.publicKey, content, signature) {
		return cose.ErrVerification
	}
	return nil
}
