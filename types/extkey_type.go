package types

import (
	"fmt"
	"strings"

	cfd "github.com/cryptogarageinc/cfd-go"
)

// ExtkeyType ...
type ExtkeyType int

const (
	// ExtkeyType
	UnknownExtkeyType ExtkeyType = iota
	ExtPrivkeyType
	ExtPubkeyType
)

// NewExtkeyTypeByString ...
func NewExtkeyTypeByString(extkeyType string) ExtkeyType {
	switch strings.ToLower(extkeyType) {
	case "extprivkey", "extprivkeytype":
		return ExtPrivkeyType
	case "extpubkey", "extpubkeytype":
		return ExtPubkeyType
	default:
		return UnknownExtkeyType
	}
}

// NewExtkeyType ...
func NewExtkeyType(cfdExtkeyType int) ExtkeyType {
	switch cfdExtkeyType {
	case int(cfd.KCfdExtPrivkey):
		return ExtPrivkeyType
	case int(cfd.KCfdExtPubkey):
		return ExtPubkeyType
	default:
		return UnknownExtkeyType
	}
}

// ToCfdValue ...
func (n ExtkeyType) ToCfdValue() int {
	switch n {
	case ExtPrivkeyType:
		return int(cfd.KCfdExtPrivkey)
	case ExtPubkeyType:
		return int(cfd.KCfdExtPubkey)
	default:
		return int(cfd.KCfdExtPrivkey)
	}
}

// Valid ...
func (n ExtkeyType) Valid() bool {
	switch n {
	case ExtPrivkeyType, ExtPubkeyType:
		return true
	default:
		return false
	}
}

// String ...
func (n ExtkeyType) String() string {
	switch n {
	case ExtPrivkeyType:
		return "extprivkeytype"
	case ExtPubkeyType:
		return "extpubkeytype"
	default:
		return fmt.Sprintf("unknown:%d", int(n))
	}
}
