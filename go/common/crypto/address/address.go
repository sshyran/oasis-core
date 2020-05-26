// Package address implements a generic cryptographic address.
package address

import (
	"bytes"
	"encoding/base64"
	"errors"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
)

const (
	// Addresses are 20 bytes long.
	Size = 20
)

var (
	// ErrMalformed is the error returned when an address is malformed.
	ErrMalformed = errors.New("hash: malformed address")
)

type Address [Size]byte

// MarshalBinary encodes an address into binary form.
func (a *Address) MarshalBinary() (data []byte, err error) {
	data = append([]byte{}, a[:]...)
	return
}

// UnmarshalBinary decodes a binary marshaled address.
func (a *Address) UnmarshalBinary(data []byte) error {
	if len(data) != Size {
		return ErrMalformed
	}

	copy(a[:], data)

	return nil
}

// MarshalText encodes an address into text form.
func (a Address) MarshalText() (data []byte, err error) {
	return []byte(base64.StdEncoding.EncodeToString(a[:])), nil
}

// UnmarshalText decodes a text marshaled address.
func (a *Address) UnmarshalText(text []byte) error {
	b, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return err
	}

	return a.UnmarshalBinary(b)
}

// Equal compares vs another address for equality.
func (a *Address) Equal(cmp *Address) bool {
	return bytes.Equal(a[:], cmp[:])
}

// String returns a string representation of an address.
func (a Address) String() string {
	b64Addr := base64.StdEncoding.EncodeToString(a[:])

	if len(a) != Size {
		return "[malformed]: " + b64Addr
	}

	return b64Addr
}

// IsValid checks whether an address is well-formed.
func (a Address) IsValid() bool {
	if len(a) != Size {
		return false
	}
	// TODO: Transition from public key blacklisting to account blacklisting.
	// if a.isBlacklisted() {
	// 	return false
	// }
	return true
}

// NewFromPublicKey creates a new address by hashing and truncating a public key.
func NewFromPublicKey(pk signature.PublicKey) (a Address) {
	truncatedHash, err := pk.Hash().Truncate(Size)
	if err != nil {
		panic(err)
	}
	_ = a.UnmarshalBinary(truncatedHash)
	return
}
