package types

import (
	"fmt"
	"strings"

	cfd "github.com/cryptogarageinc/cfd-go"
)

type HashType int

const (
	// HashType
	UnknownType HashType = iota
	P2pkh
	P2sh
	P2wpkh
	P2wsh
	P2shP2wpkh
	P2shP2wsh
	Taproot
)

// NewHashType ...
func NewHashType(cfdHashType int) HashType {
	switch cfdHashType {
	case int(cfd.KCfdP2pkh):
		return P2pkh
	case int(cfd.KCfdP2sh):
		return P2sh
	case int(cfd.KCfdP2wpkh):
		return P2wpkh
	case int(cfd.KCfdP2wsh):
		return P2wsh
	case int(cfd.KCfdP2shP2wpkh):
		return P2shP2wpkh
	case int(cfd.KCfdP2shP2wsh):
		return P2shP2wsh
	case int(cfd.KCfdTaproot):
		return Taproot
	default:
		return UnknownType
	}
}

// NewHashTypeByString ...
func NewHashTypeByString(hashType string) HashType {
	switch strings.ToLower(hashType) {
	case "p2pkh":
		return P2pkh
	case "p2sh":
		return P2sh
	case "p2wpkh":
		return P2wpkh
	case "p2wsh":
		return P2wsh
	case "p2sh-p2wpkh", "p2shp2wpkh":
		return P2shP2wpkh
	case "p2sh-p2wsh", "p2shp2wsh":
		return P2shP2wsh
	case "taproot", "p2tr":
		return Taproot
	default:
		return UnknownType
	}
}

// ToCfdValue ...
func (n HashType) ToCfdValue() int {
	switch n {
	case P2pkh:
		return int(cfd.KCfdP2pkh)
	case P2sh:
		return int(cfd.KCfdP2sh)
	case P2wpkh:
		return int(cfd.KCfdP2wpkh)
	case P2wsh:
		return int(cfd.KCfdP2wsh)
	case P2shP2wpkh:
		return int(cfd.KCfdP2shP2wpkh)
	case P2shP2wsh:
		return int(cfd.KCfdP2shP2wsh)
	case Taproot:
		return int(cfd.KCfdTaproot)
	default:
		return int(cfd.KCfdUnknown)
	}
}

// String ...
func (n HashType) String() string {
	switch n {
	case P2pkh:
		return "p2pkh"
	case P2sh:
		return "p2sh"
	case P2wpkh:
		return "p2wpkh"
	case P2wsh:
		return "p2wsh"
	case P2shP2wpkh:
		return "p2sh-p2wpkh"
	case P2shP2wsh:
		return "p2sh-p2wwh"
	case Taproot:
		return "taproot"
	default:
		return fmt.Sprintf("unknown:%d", int(n))
	}
}

// IsPubkeyHash ...
func (n HashType) IsPubkeyHash() bool {
	switch n {
	case P2pkh, P2wpkh, P2shP2wpkh:
		return true
	default:
		return false
	}
}

// IsScriptHash ...
func (n HashType) IsScriptHash() bool {
	switch n {
	case P2sh, P2wsh, P2shP2wsh:
		return true
	default:
		return false
	}
}

// IsP2shSegwit ...
func (n HashType) IsP2shSegwit() bool {
	switch n {
	case P2shP2wpkh, P2shP2wsh:
		return true
	default:
		return false
	}
}

// IsWitness ...
func (n HashType) IsWitness() bool {
	switch n {
	case P2wpkh, P2wsh, P2shP2wpkh, P2shP2wsh, Taproot:
		return true
	default:
		return false
	}
}

// IsWitnessV1OrLater ...
func (n HashType) IsWitnessV1OrLater() bool {
	switch n {
	case Taproot:
		return true
	default:
		return false
	}
}

type HashTypes []HashType

func (d HashTypes) IsValid() bool {
	return len(d) > 0
}

func (d HashTypes) Find(hashType HashType) bool {
	for _, element := range d {
		if element == hashType {
			return true
		}
	}
	return false
}
