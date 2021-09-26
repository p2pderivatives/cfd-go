package types

import (
	"strings"

	cfd "github.com/cryptogarageinc/cfd-go"
)

type AddressType int

const (
	// AddressType
	UnknownAddress AddressType = iota
	P2pkhAddress
	P2shAddress
	P2wpkhAddress
	P2wshAddress
	P2shP2wpkhAddress
	P2shP2wshAddress
	TaprootAddress
)

// NewAddressType ...
func NewAddressType(cfdAddressType int) AddressType {
	switch cfdAddressType {
	case int(cfd.KCfdP2pkhAddress):
		return P2pkhAddress
	case int(cfd.KCfdP2shAddress):
		return P2shAddress
	case int(cfd.KCfdP2wpkhAddress):
		return P2wpkhAddress
	case int(cfd.KCfdP2wshAddress):
		return P2wshAddress
	case int(cfd.KCfdP2shP2wpkhAddress):
		return P2shP2wpkhAddress
	case int(cfd.KCfdP2shP2wshAddress):
		return P2shP2wshAddress
	case int(cfd.KCfdTaprootAddress):
		return TaprootAddress
	default:
		return UnknownAddress
	}
}

// NewAddressTypeByHashType ...
func NewAddressTypeByHashType(hashType int) AddressType {
	switch hashType {
	case int(cfd.KCfdP2pkh):
		return P2pkhAddress
	case int(cfd.KCfdP2sh):
		return P2shAddress
	case int(cfd.KCfdP2wpkh):
		return P2wpkhAddress
	case int(cfd.KCfdP2wsh):
		return P2wshAddress
	case int(cfd.KCfdP2shP2wpkh):
		return P2shP2wpkhAddress
	case int(cfd.KCfdP2shP2wsh):
		return P2shP2wshAddress
	case int(cfd.KCfdTaproot):
		return TaprootAddress
	default:
		return UnknownAddress
	}
}

// NewAddressTypeByString ...
func NewAddressTypeByString(addressType string) AddressType {
	switch strings.ToLower(addressType) {
	case "p2pkh":
		return P2pkhAddress
	case "p2sh":
		return P2shAddress
	case "p2wpkh":
		return P2wpkhAddress
	case "p2wsh":
		return P2wshAddress
	case "p2sh-p2wpkh", "p2shp2wpkh":
		return P2shP2wpkhAddress
	case "p2sh-p2wsh", "p2shp2wsh":
		return P2shP2wshAddress
	case "taproot", "p2tr":
		return TaprootAddress
	default:
		return UnknownAddress
	}
}

// ToCfdValue ...
func (n AddressType) ToCfdValue() int {
	switch n {
	case P2pkhAddress:
		return int(cfd.KCfdP2pkhAddress)
	case P2shAddress:
		return int(cfd.KCfdP2shAddress)
	case P2wpkhAddress:
		return int(cfd.KCfdP2wpkhAddress)
	case P2wshAddress:
		return int(cfd.KCfdP2wshAddress)
	case P2shP2wpkhAddress:
		return int(cfd.KCfdP2shP2wpkhAddress)
	case P2shP2wshAddress:
		return int(cfd.KCfdP2shP2wshAddress)
	case TaprootAddress:
		return int(cfd.KCfdTaprootAddress)
	default:
		return int(cfd.KCfdWitnessUnknownAddress)
	}
}

// ToHashType ...
func (n AddressType) ToHashType() HashType {
	switch n {
	case P2pkhAddress:
		return P2pkh
	case P2shAddress:
		return P2sh
	case P2wpkhAddress:
		return P2wpkh
	case P2wshAddress:
		return P2wsh
	case P2shP2wpkhAddress:
		return P2shP2wpkh
	case P2shP2wshAddress:
		return P2shP2wsh
	case TaprootAddress:
		return Taproot
	default:
		return UnknownType
	}
}

// String ...
func (n AddressType) String() string {
	hashType := n.ToHashType()
	if hashType == UnknownType {
		return "WitnessUnknown"
	}
	return hashType.String()
}
