package types

import (
	cfd "github.com/cryptogarageinc/cfd-go"
	cfdErrors "github.com/cryptogarageinc/cfd-go/errors"
)

type DescriptorKeyType int
type DescriptorType int

const (
	DescriptorKeyNull DescriptorKeyType = iota
	DescriptorKeyPublic
	DescriptorKeyBip32
	DescriptorKeyBip32Priv
	DescriptorKeySchnorr

	DescriptorTypeNull DescriptorType = iota
	DescriptorTypeSh
	DescriptorTypeWsh
	DescriptorTypePk
	DescriptorTypePkh
	DescriptorTypeWpkh
	DescriptorTypeCombo
	DescriptorTypeMulti
	DescriptorTypeSortedMulti
	DescriptorTypeAddr
	DescriptorTypeRaw
	DescriptorTypeMiniscript
	DescriptorTypeTaproot
)

// Descriptor This struct use for the output descriptor.
type Descriptor struct {
	// Output Descriptor
	OutputDescriptor string
}

// DescriptorRootData stores descriptor root data
type DescriptorRootData struct {
	// depth (0 - )
	Depth uint32
	// script type. (CfdDescriptorScriptType)
	Type DescriptorType
	// address string. (for Type not KCfdDescriptorScriptRaw)
	Address Address
	// hash type.
	HashType HashType
	// redeem script. (for HashType P2sh,P2wsh,P2shP2wsh)
	RedeemScript *Script
	// key
	Key DescriptorKey
	// multisig
	Multisig *DescriptorMultisig
	// Taproot ScriptTree string
	TreeString string // TODO(k-matsuzawa): please wait
}

// DescriptorKey stores a key data for descriptor.
type DescriptorKey struct {
	// key type. (CfdDescriptorKeyType)
	// - KCfdDescriptorKeyNull
	// - KCfdDescriptorKeyPublic
	// - KCfdDescriptorKeyBip32
	// - KCfdDescriptorKeyBip32Priv
	// - KCfdDescriptorKeySchnorr
	KeyType DescriptorKeyType
	// pubkey
	Pubkey *Pubkey
	// extend pubkey
	ExtPubkey *ExtPubkey
	// extend privkey
	ExtPrivkey *ExtPrivkey
	// schnorr pubkey
	SchnorrPubkey string // TODO(k-matsuzawa): please wait
}

// DescriptorMultisig stores the multisig data for descriptor.
type DescriptorMultisig struct {
	ReqSigNum uint32         // number of multisig require signatures
	Keys      DescriptorKeys // Multisig keys
}

/**
 * Descriptor data struct.
 */
type DescriptorData struct {
	// depth (0 - )
	Depth uint32
	// script type. (CfdDescriptorScriptType)
	ScriptType int
	// locking script.
	LockingScript string
	// address string. (for ScriptType not KCfdDescriptorScriptRaw)
	Address string
	// hash type. (CfdHashType)
	HashType int
	// redeem script. (for ScriptType KCfdDescriptorScriptSh or KCfdDescriptorScriptWsh)
	RedeemScript string
	// key type. (see CfdDescriptorKeyData.KeyType)
	KeyType int
	// pubkey
	Pubkey string
	// extend pubkey
	ExtPubkey string
	// extend privkey
	ExtPrivkey string
	// schnorr pubkey
	SchnorrPubkey string
	// has multisig
	IsMultisig bool
	// number of multisig require signatures
	ReqSigNum uint32
	// Taproot ScriptTree string
	TreeString string
}

/**
 * Descriptor key data struct.
 */
type DescriptorKeyData struct {
	// key type. (CfdDescriptorKeyType)
	// - KCfdDescriptorKeyNull
	// - KCfdDescriptorKeyPublic
	// - KCfdDescriptorKeyBip32
	// - KCfdDescriptorKeyBip32Priv
	// - KCfdDescriptorKeySchnorr
	KeyType int
	// pubkey
	Pubkey string
	// extend pubkey
	ExtPubkey string
	// extend privkey
	ExtPrivkey string
	// schnorr pubkey
	SchnorrPubkey string
}

func NewDescriptorData(cfdData *cfd.CfdDescriptorData) *DescriptorData {
	data := &DescriptorData{
		Depth:         cfdData.Depth,
		ScriptType:    cfdData.ScriptType,
		LockingScript: cfdData.LockingScript,
		Address:       cfdData.Address,
		HashType:      cfdData.HashType,
		RedeemScript:  cfdData.RedeemScript,
		KeyType:       cfdData.KeyType,
		Pubkey:        cfdData.Pubkey,
		ExtPubkey:     cfdData.ExtPubkey,
		ExtPrivkey:    cfdData.ExtPrivkey,
		SchnorrPubkey: cfdData.SchnorrPubkey,
		IsMultisig:    cfdData.IsMultisig,
		ReqSigNum:     cfdData.ReqSigNum,
		TreeString:    cfdData.TreeString,
	}
	return data
}

// DescriptorParseFilter defines filter conditions for parsing output descriptors.
type DescriptorParseFilter struct {
	EnableHashTypes            []HashType
	DisableHashTypes           []HashType
	IsMultisigOnlyOnScriptHash bool
	EnableRootDescriptorTypes  []DescriptorType
	DisableRootDescriptorTypes []DescriptorType
}

func NewDescriptorKeyType(keyType int) DescriptorKeyType {
	switch keyType {
	case int(cfd.KCfdDescriptorKeyPublic):
		return DescriptorKeyPublic
	case int(cfd.KCfdDescriptorKeyBip32):
		return DescriptorKeyBip32
	case int(cfd.KCfdDescriptorKeyBip32Priv):
		return DescriptorKeyBip32Priv
	case int(cfd.KCfdDescriptorKeySchnorr):
		return DescriptorKeySchnorr
	default:
		return DescriptorKeyNull
	}
}

// ToCfdValue ...
func (k DescriptorKeyType) ToCfdValue() int {
	switch k {
	case DescriptorKeyPublic:
		return int(cfd.KCfdDescriptorKeyPublic)
	case DescriptorKeyBip32:
		return int(cfd.KCfdDescriptorKeyBip32)
	case DescriptorKeyBip32Priv:
		return int(cfd.KCfdDescriptorKeyBip32Priv)
	case DescriptorKeySchnorr:
		return int(cfd.KCfdDescriptorKeySchnorr)
	default:
		return int(cfd.KCfdDescriptorKeyNull)
	}
}

// Valid ...
func (k DescriptorKeyType) Valid() bool {
	switch k {
	case DescriptorKeyPublic, DescriptorKeyBip32, DescriptorKeyBip32Priv, DescriptorKeySchnorr:
		return true
	default:
		return false
	}
}

func NewDescriptorType(descType int) DescriptorType {
	switch descType {
	case int(cfd.KCfdDescriptorScriptSh):
		return DescriptorTypeSh
	case int(cfd.KCfdDescriptorScriptWsh):
		return DescriptorTypeWsh
	case int(cfd.KCfdDescriptorScriptPk):
		return DescriptorTypePk
	case int(cfd.KCfdDescriptorScriptPkh):
		return DescriptorTypePkh
	case int(cfd.KCfdDescriptorScriptWpkh):
		return DescriptorTypeWpkh
	case int(cfd.KCfdDescriptorScriptCombo):
		return DescriptorTypeCombo
	case int(cfd.KCfdDescriptorScriptMulti):
		return DescriptorTypeMulti
	case int(cfd.KCfdDescriptorScriptSortedMulti):
		return DescriptorTypeSortedMulti
	case int(cfd.KCfdDescriptorScriptAddr):
		return DescriptorTypeAddr
	case int(cfd.KCfdDescriptorScriptRaw):
		return DescriptorTypeRaw
	case int(cfd.KCfdDescriptorScriptMiniscript):
		return DescriptorTypeMiniscript
	case int(cfd.KCfdDescriptorScriptTaproot):
		return DescriptorTypeTaproot
	default:
		return DescriptorTypeNull
	}
}

// ToCfdValue ...
func (t DescriptorType) ToCfdValue() int {
	switch t {
	case DescriptorTypeSh:
		return int(cfd.KCfdDescriptorScriptSh)
	case DescriptorTypeWsh:
		return int(cfd.KCfdDescriptorScriptWsh)
	case DescriptorTypePk:
		return int(cfd.KCfdDescriptorScriptPk)
	case DescriptorTypePkh:
		return int(cfd.KCfdDescriptorScriptPkh)
	case DescriptorTypeWpkh:
		return int(cfd.KCfdDescriptorScriptWpkh)
	case DescriptorTypeCombo:
		return int(cfd.KCfdDescriptorScriptCombo)
	case DescriptorTypeMulti:
		return int(cfd.KCfdDescriptorScriptMulti)
	case DescriptorTypeSortedMulti:
		return int(cfd.KCfdDescriptorScriptSortedMulti)
	case DescriptorTypeAddr:
		return int(cfd.KCfdDescriptorScriptAddr)
	case DescriptorTypeRaw:
		return int(cfd.KCfdDescriptorScriptRaw)
	case DescriptorTypeMiniscript:
		return int(cfd.KCfdDescriptorScriptMiniscript)
	case DescriptorTypeTaproot:
		return int(cfd.KCfdDescriptorScriptTaproot)
	default:
		return int(cfd.KCfdDescriptorScriptNull)
	}
}

func NewDescriptorKey(keyType int, pubkey, extPubkey, extPrivkey, schnorrPubkey string) DescriptorKey {
	obj := DescriptorKey{
		KeyType: NewDescriptorKeyType(keyType),
	}
	if !obj.KeyType.Valid() {
		return obj
	}

	obj.Pubkey = &Pubkey{Hex: pubkey}
	obj.SchnorrPubkey = schnorrPubkey

	switch obj.KeyType {
	case DescriptorKeyBip32:
		obj.ExtPubkey = &ExtPubkey{Key: extPubkey}
	case DescriptorKeyBip32Priv:
		obj.ExtPubkey = &ExtPubkey{Key: extPubkey}
		obj.ExtPrivkey = &ExtPrivkey{Key: extPrivkey}
	}
	return obj
}

func NewDescriptorMultisig(reqSigNum uint32, keys []DescriptorKeyData) *DescriptorMultisig {
	obj := &DescriptorMultisig{
		ReqSigNum: reqSigNum,
		Keys:      make([]DescriptorKey, len(keys)),
	}
	for i, key := range keys {
		obj.Keys[i] = NewDescriptorKey(key.KeyType, key.Pubkey, key.ExtPubkey, key.ExtPrivkey, key.SchnorrPubkey)
	}
	return obj
}

func (d DescriptorRootData) GetAddress() string {
	switch d.Type {
	case DescriptorTypeRaw, DescriptorTypeNull:
		return ""
	default:
		return d.Address.Address
	}
}

func (d DescriptorRootData) HasMultisig() bool {
	return d.Multisig != nil
}

func (d DescriptorRootData) GetRedeemScript() string {
	if d.HashType.IsScriptHash() {
		return d.RedeemScript.ToHex()
	}
	return ""
}

func (d DescriptorRootData) GetPublicKey() string {
	if d.HashType.IsPubkeyHash() {
		return d.Key.GetPublicKey()
	} else if d.HasMultisig() {
		return d.Multisig.Keys[0].GetPublicKey()
	}
	return ""
}

func (d DescriptorRootData) GetPublicKeys() []string {
	if d.HashType.IsPubkeyHash() {
		return []string{d.Key.GetPublicKey()}
	} else if d.HasMultisig() {
		return d.Multisig.Keys.GetPublicKeys()
	}
	return nil
}

func (d DescriptorRootData) ExistPublicKey(pubkey *Pubkey) bool {
	if d.HashType.IsPubkeyHash() {
		return d.Key.Pubkey.Hex == pubkey.Hex
	} else if d.HasMultisig() {
		return d.Multisig.Keys.ExistPublicKey(pubkey)
	}
	return false
}

func (d DescriptorKey) GetPublicKey() string {
	if d.KeyType.Valid() {
		return d.Pubkey.Hex
	}
	return ""
}

type DescriptorKeys []DescriptorKey

func (d DescriptorKeys) Find(key DescriptorKey) bool {
	for _, element := range d {
		if element.Pubkey == key.Pubkey {
			return true
		}
	}
	return false
}

func (d DescriptorKeys) GetPublicKeys() []string {
	keys := make([]string, len(d))
	for i, key := range d {
		keys[i] = key.GetPublicKey()
	}
	return keys
}

func (d DescriptorKeys) ExistPublicKey(pubkey *Pubkey) bool {
	for _, key := range d {
		if key.Pubkey.Hex == pubkey.Hex {
			return true
		}
	}
	return false
}

func (f *DescriptorParseFilter) Check(data *DescriptorRootData) error {
	if f == nil || data == nil {
		return nil
	}

	enableHashTypes := HashTypes(f.EnableHashTypes)
	disableHashTypes := HashTypes(f.DisableHashTypes)
	enableDescTypes := DescriptorTypes(f.EnableRootDescriptorTypes)
	disableDescTypes := DescriptorTypes(f.DisableRootDescriptorTypes)

	switch {
	case enableHashTypes.IsValid() && !enableHashTypes.Find(data.HashType):
		return cfdErrors.ErrDescriptorFilter
	case disableHashTypes.IsValid() && disableHashTypes.Find(data.HashType):
		return cfdErrors.ErrDescriptorFilter
	case data.HashType.IsScriptHash() && f.IsMultisigOnlyOnScriptHash && !data.HasMultisig():
		return cfdErrors.ErrDescriptorFilter
	case enableDescTypes.IsValid() && !enableDescTypes.Find(data.Type):
		return cfdErrors.ErrDescriptorFilter
	case disableDescTypes.IsValid() && disableDescTypes.Find(data.Type):
		return cfdErrors.ErrDescriptorFilter
	}
	return nil
}

type DescriptorTypes []DescriptorType

func (d DescriptorTypes) IsValid() bool {
	return len(d) > 0
}

func (d DescriptorTypes) Find(descType DescriptorType) bool {
	for _, element := range d {
		if element == descType {
			return true
		}
	}
	return false
}
