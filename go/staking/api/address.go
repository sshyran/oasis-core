package api

import (
	"github.com/oasislabs/oasis-core/go/common/crypto/address"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
)

// Address is the staking account's address.
type Address address.Address

// MarshalText encodes an address into text form.
func (a *Address) MarshalText() ([]byte, error) {
	return (*address.Address)(a).MarshalText()
}

// UnmarshalText decodes a text marshaled address.
func (a *Address) UnmarshalText(text []byte) error {
	return (*address.Address)(a).UnmarshalText(text)
}

// Equal compares vs another address for equality.
func (a *Address) Equal(cmp *Address) bool {
	return (*address.Address)(a).Equal((*address.Address)(cmp))
}

// String returns the string representation of an address.
func (a Address) String() string {
	return address.Address(a).String()
}

func (a Address) IsValid() bool {
	return address.Address(a).IsValid()
}

// NewFromPublicKey creates a new address from an entity's id / public key.
func NewFromPublicKey(pk signature.PublicKey) (a Address) {
	return (Address)(address.NewFromPublicKey(pk))
}
