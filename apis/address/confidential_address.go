package address

import (
	cfd "github.com/cryptogarageinc/cfd-go"
	types "github.com/cryptogarageinc/cfd-go/types"
	"github.com/pkg/errors"
)

// go generate comment
//go:generate -command mkdir mock
//go:generate mockgen -source confidential_address.go -destination mock/confidential_address.go -package mock
//go:generate goimports -w mock/confidential_address.go

// -------------------------------------
// API
// -------------------------------------

type ConfidentialAddressApi interface {
	Create(addressString string, confidentialKey *types.Pubkey) (address *types.ConfidentialAddress, err error)
	Parse(addressString string) (address *types.ConfidentialAddress, err error)
}

func NewConfidentialAddressApi() *ConfidentialAddressApiImpl {
	return &ConfidentialAddressApiImpl{}
}

// -------------------------------------
// ConfidentialAddressApiImpl
// -------------------------------------

// ConfidentialAddressApiImpl ...
type ConfidentialAddressApiImpl struct {
	Error error
}

// Create ...
func (u *ConfidentialAddressApiImpl) Create(addressString string, confidentialKey *types.Pubkey) (address *types.ConfidentialAddress, err error) {
	data, err := cfd.CfdGoGetAddressInfo(addressString)
	if err != nil {
		return nil, errors.Wrap(err, "parse address error")
	}
	addr := ""
	if confidentialKey != nil {
		addr, err = cfd.CfdGoCreateConfidentialAddress(addressString, confidentialKey.Hex)
		if err != nil {
			return nil, errors.Wrap(err, "create confidential address error")
		}
	}
	address = &types.ConfidentialAddress{
		ConfidentialAddress: addr,
		Address:             addressString,
		Network:             types.NewNetworkType(data.NetworkType),
		Type:                types.NewAddressTypeByHashType(data.HashType),
		ConfidentialKey:     confidentialKey,
	}
	return address, nil
}

// ParseAddress ...
func (u *ConfidentialAddressApiImpl) Parse(addressString string) (address *types.ConfidentialAddress, err error) {
	addr, key, network, err := cfd.CfdGoParseConfidentialAddress(addressString)
	if err == nil {
		data, err := cfd.CfdGoGetAddressInfo(addr)
		if err != nil {
			return nil, errors.Wrap(err, "parse address error")
		}
		address = &types.ConfidentialAddress{
			ConfidentialAddress: addressString,
			Address:             addr,
			Network:             types.NewNetworkType(network),
			Type:                types.NewAddressTypeByHashType(data.HashType),
			ConfidentialKey:     &types.Pubkey{Hex: key},
		}
	} else {
		data, err := cfd.CfdGoGetAddressInfo(addressString)
		if err != nil {
			return nil, errors.Wrap(err, "parse address error")
		}
		address = &types.ConfidentialAddress{
			Address: addressString,
			Network: types.NewNetworkType(data.NetworkType),
			Type:    types.NewAddressTypeByHashType(data.HashType),
		}
	}
	return address, nil
}
