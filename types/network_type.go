package types

import (
	"fmt"
	"strings"

	cfd "github.com/cryptogarageinc/cfd-go"
)

type NetworkType int

const (
	// NetworkType
	Unknown NetworkType = iota
	Mainnet
	Testnet
	Regtest
	LiquidV1
	ElementsRegtest
)

// NewNetworkTypeByString ...
func NewNetworkTypeByString(networkType string) NetworkType {
	switch strings.ToLower(networkType) {
	case "mainnet":
		return Mainnet
	case "testnet":
		return Testnet
	case "regtest":
		return Regtest
	case "liquidv1":
		return LiquidV1
	case "liquidv1test", "liquidregtest", "elementsregtest":
		return ElementsRegtest
	default:
		return Unknown
	}
}

// NewNetworkType ...
func NewNetworkType(cfdNetworkType int) NetworkType {
	switch cfdNetworkType {
	case int(cfd.KCfdNetworkMainnet):
		return Mainnet
	case int(cfd.KCfdNetworkTestnet):
		return Testnet
	case int(cfd.KCfdNetworkRegtest):
		return Regtest
	case int(cfd.KCfdNetworkLiquidv1):
		return LiquidV1
	case int(cfd.KCfdNetworkElementsRegtest):
		return ElementsRegtest
	default:
		return Unknown
	}
}

// ToCfdValue ...
func (n NetworkType) ToCfdValue() int {
	switch n {
	case Mainnet:
		return int(cfd.KCfdNetworkMainnet)
	case Testnet:
		return int(cfd.KCfdNetworkTestnet)
	case Regtest:
		return int(cfd.KCfdNetworkRegtest)
	case LiquidV1:
		return int(cfd.KCfdNetworkLiquidv1)
	case ElementsRegtest:
		return int(cfd.KCfdNetworkElementsRegtest)
	default:
		return int(cfd.KCfdNetworkMainnet)
	}
}

// String ...
func (n NetworkType) String() string {
	switch n {
	case Mainnet:
		return "Mainnet"
	case Testnet:
		return "Testnet"
	case Regtest:
		return "Regtest"
	case LiquidV1:
		return "LiquidV1"
	case ElementsRegtest:
		return "ElementsRegtest"
	default:
		return fmt.Sprintf("unknown:%d", int(n))
	}
}

// Valid ...
func (n NetworkType) Valid() bool {
	switch n {
	case Mainnet, Testnet, Regtest, LiquidV1, ElementsRegtest:
		return true
	default:
		return false
	}
}

// IsBitcoin ...
func (n NetworkType) IsBitcoin() bool {
	switch n {
	case Mainnet, Testnet, Regtest:
		return true
	default:
		return false
	}
}

// IsElements ...
func (n NetworkType) IsElements() bool {
	switch n {
	case LiquidV1, ElementsRegtest:
		return true
	default:
		return false
	}
}

// ToBitcoinType ...
func (n NetworkType) ToBitcoinType() NetworkType {
	switch n {
	case Mainnet, Testnet, Regtest:
		return n
	case LiquidV1:
		return Mainnet
	case ElementsRegtest:
		return Regtest
	default:
		return Unknown
	}
}

// IsMainnet ...
func (n NetworkType) IsMainnet() bool {
	switch n {
	case Mainnet, LiquidV1:
		return true
	case Testnet, Regtest, ElementsRegtest:
		return false
	default:
		return false
	}
}

// ToBitcoinTypePointer ...
func (n NetworkType) ToBitcoinTypePointer() *NetworkType {
	network := n.ToBitcoinType()
	return &network
}
