package cryptoutils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1"
)

// CanonizeECDSASignature returns the canonical versions of the signature
// the canonical version enforce low S values
// if S is above order / 2 it negating the S (modulo the order (N))
func CanonizeECDSASignature(curve elliptic.Curve, sig *ECDSASignature) *ECDSASignature {
	r := new(big.Int).Set(sig.R)
	s := new(big.Int).Set(sig.S)

	order := curve.Params().N
	quo := new(big.Int).Quo(order, new(big.Int).SetInt64(2))
	if s.Cmp(quo) > 0 {
		s = s.Sub(order, s)
	}

	return &ECDSASignature{
		R: r,
		S: s,
	}
}

// CanonizeSignature returns the canonical versions of the ECDSA signature if one is given
func CanonizeSignature(pub crypto.PublicKey, sig Signature) Signature {
	epub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return sig
	}
	s, ok := sig.(*ECDSASignature)
	if !ok {
		return sig
	}

	return CanonizeECDSASignature(epub.Curve, s)
}

// Signature is a type representing a digital signature.
type Signature interface {
	String() string
}

// ECDSASignature is a type representing an ecdsa signature.
type ECDSASignature struct {
	R *big.Int
	S *big.Int
}

func (e *ECDSASignature) String() string {
	return fmt.Sprintf("ecdsa:[r:%x,s:%x]", e.R, e.S)
}

// ED25519Signature is a type representing an Ed25519 signature
type ED25519Signature []byte

func (e ED25519Signature) String() string {
	return fmt.Sprintf("ed25519:[%s]", hex.EncodeToString(e))
}

// S256 returns a Curve which implements secp256k1
func S256() elliptic.Curve {
	return secp256k1.S256()
}

// PrivateKey is implemented by private key types
type PrivateKey interface {
	Public() crypto.PublicKey
}

// NamedCurve returns curve by its standard name or nil
func NamedCurve(name string) elliptic.Curve {
	switch name {
	case "P-224":
		return elliptic.P224()
	case "P-256":
		return elliptic.P256()
	case "P-384":
		return elliptic.P384()
	case "P-521":
		return elliptic.P521()
	case "P-256K", "SECP256K1", "secp256k1":
		return S256()
	default:
		return nil
	}
}

// Sign sign a hash using this private key
func Sign(priv PrivateKey, hash []byte) (Signature, error) {
	switch key := priv.(type) {
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, key, hash)
		if err != nil {
			return nil, err
		}
		return &ECDSASignature{R: r, S: s}, nil
	case ed25519.PrivateKey:
		return ED25519Signature(ed25519.Sign(key, hash)), nil
	}
	return nil, fmt.Errorf("unsupported key type: %T", priv)
}

// ErrSignature error returned by Verify if signature is invalid
var ErrSignature = errors.New("invalid signature")

// Verify verifies the signature
func Verify(pub crypto.PublicKey, hash []byte, sig Signature) error {
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		s, ok := sig.(*ECDSASignature)
		if !ok {
			return fmt.Errorf("ecdsa: unsupported signature type: %T", sig)
		}
		if ok = ecdsa.Verify(key, hash, s.R, s.S); !ok {
			return ErrSignature
		}
	case ed25519.PublicKey:
		s, ok := sig.(ED25519Signature)
		if !ok {
			return fmt.Errorf("ed25519: unsupported signature type: %T", sig)
		}
		if ok = ed25519.Verify(key, hash, s); !ok {
			return ErrSignature
		}
	default:
		return fmt.Errorf("unsupported key type: %T", pub)
	}

	return nil
}
