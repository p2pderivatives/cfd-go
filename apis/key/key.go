package key

import (
	cfd "github.com/cryptogarageinc/cfd-go"
	"github.com/cryptogarageinc/cfd-go/config"
	cfdErrors "github.com/cryptogarageinc/cfd-go/errors"
	"github.com/cryptogarageinc/cfd-go/types"
	"github.com/pkg/errors"
)

// go generate comment
//go:generate -command mkdir mock
//go:generate mockgen -source key.go -destination mock/key.go -package mock
//go:generate goimports -w mock/key.go

// PubkeyApi This interface has pubkey operation API.
type PubkeyApi interface {
	// Verify ...
	Verify(pubkey *types.Pubkey) error
	// IsCompressed ...
	IsCompressed(pubkey *types.Pubkey) error
	// VerifyEcSignature ...
	VerifyEcSignature(pubkey *types.Pubkey, sighash, signature string) (isVerify bool, err error)
}

// PrivkeyApi This interface has privkey operation API.
type PrivkeyApi interface {
	HasWif(wif string) bool
	GetWifFromHex(privkeyHex string) (privkey *types.Privkey, err error)
	GetWifFromHexWithCompressedPubkey(privkeyHex string, compressedPubkey bool) (privkey *types.Privkey, err error)
	GetPrivkeyFromWif(wif string) (privkey *types.Privkey, err error)
	GetPubkey(privkey *types.Privkey) (pubkey *types.Pubkey, err error)
	CreateEcSignature(privkey *types.Privkey, sighash *types.ByteData, sighashType *types.SigHashType) (signature *types.ByteData, err error)
	CreateEcSignatureGrindR(privkey *types.Privkey, sighash *types.ByteData, sighashType *types.SigHashType, grindR bool) (signature *types.ByteData, err error)
}

func NewPubkeyApi() *PubkeyApiImpl {
	return &PubkeyApiImpl{}
}

func NewPrivkeyApi(options ...config.CfdConfigOption) *PrivkeyApiImpl {
	api := PrivkeyApiImpl{}
	conf := config.GetCurrentCfdConfig().WithOptions(options...)

	if !conf.Network.Valid() {
		api.SetError(cfdErrors.ErrNetworkConfig)
	} else {
		network := conf.Network.ToBitcoinType()
		api.network = &network
	}
	return &api
}

// -------------------------------------
// struct
// -------------------------------------

//
type PubkeyApiImpl struct {
}

//
type PrivkeyApiImpl struct {
	cfdErrors.HasInitializeError
	network *types.NetworkType
}

// -------------------------------------
// implement Pubkey
// -------------------------------------

// Verify ...
func (p *PubkeyApiImpl) Verify(pubkey *types.Pubkey) error {
	if pubkey == nil {
		return cfdErrors.ErrParameterNil
	}
	_, err := cfd.CfdGoCompressPubkey(pubkey.Hex)
	return err
}

// IsCompressed ...
func (p *PubkeyApiImpl) IsCompressed(pubkey *types.Pubkey) error {
	if pubkey == nil {
		return cfdErrors.ErrParameterNil
	}
	compressedKey, err := cfd.CfdGoCompressPubkey(pubkey.Hex)
	if err != nil {
		return err
	} else if compressedKey != pubkey.Hex {
		return errors.New("CFD Error: pubkey is uncompressed")
	}
	return nil
}

// VerifyEcSignature ...
func (p *PubkeyApiImpl) VerifyEcSignature(pubkey *types.Pubkey, sighash, signature string) (isVerify bool, err error) {
	if pubkey == nil {
		return false, cfdErrors.ErrParameterNil
	}
	isVerify, err = cfd.CfdGoVerifyEcSignature(sighash, pubkey.Hex, signature)
	if err != nil {
		return false, errors.Wrap(err, "verify ec signature error")
	}
	return isVerify, nil
}

// -------------------------------------
// implement Privkey
// -------------------------------------

// HasWif ...
func (k *PrivkeyApiImpl) HasWif(wif string) bool {
	if _, _, _, err := cfd.CfdGoParsePrivkeyWif(wif); err != nil {
		return false
	}
	return true
}

// GetWifFromHex ...
func (k *PrivkeyApiImpl) GetWifFromHex(privkeyHex string) (privkey *types.Privkey, err error) {
	return k.GetWifFromHexWithCompressedPubkey(privkeyHex, true)
}

// GetWifFromHexWithCompressedPubkey ...
func (k *PrivkeyApiImpl) GetWifFromHexWithCompressedPubkey(privkeyHex string, compressedPubkey bool) (privkey *types.Privkey, err error) {
	if err = k.validConfig(); err != nil {
		return nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	wif, err := cfd.CfdGoGetPrivkeyWif(privkeyHex, k.network.ToCfdValue(), compressedPubkey)
	if err != nil {
		return nil, errors.Wrap(err, "get wif error")
	}
	privkey = &types.Privkey{
		Wif:                wif,
		Hex:                privkeyHex,
		Network:            *k.network,
		IsCompressedPubkey: compressedPubkey,
	}
	return privkey, nil
}

// GetPrivkeyFromWif ...
func (k *PrivkeyApiImpl) GetPrivkeyFromWif(wif string) (privkey *types.Privkey, err error) {
	hex, network, isCompressed, err := cfd.CfdGoParsePrivkeyWif(wif)
	if err != nil {
		return nil, errors.Wrap(err, "parse wif error")
	}
	networkType := types.NewNetworkType(network)
	if (k.network != nil) && (k.network.ToBitcoinType().IsMainnet() != networkType.IsMainnet()) {
		err = errors.Errorf("CFD Error: Unmatch wif network type")
		return nil, err
	}
	privkey = &types.Privkey{
		Wif:                wif,
		Hex:                hex,
		Network:            networkType,
		IsCompressedPubkey: isCompressed,
	}
	return privkey, nil
}

// GetPubkey ...
func (k *PrivkeyApiImpl) GetPubkey(privkey *types.Privkey) (pubkey *types.Pubkey, err error) {
	hex, err := cfd.CfdGoGetPubkeyFromPrivkey(privkey.Hex, "", privkey.IsCompressedPubkey)
	if err != nil {
		return nil, errors.Wrap(err, "get pubkey error")
	}
	pubkey = &types.Pubkey{Hex: hex}
	return pubkey, nil
}

// CreateEcSignature ...
func (k *PrivkeyApiImpl) CreateEcSignature(privkey *types.Privkey, sighash *types.ByteData, sighashType *types.SigHashType) (signature *types.ByteData, err error) {
	return k.CreateEcSignatureGrindR(privkey, sighash, sighashType, true)
}

// CreateEcSignatureGrindR ...
func (k *PrivkeyApiImpl) CreateEcSignatureGrindR(privkey *types.Privkey, sighash *types.ByteData, sighashType *types.SigHashType, grindR bool) (signature *types.ByteData, err error) {
	sig, err := cfd.CfdGoCalculateEcSignature(sighash.ToHex(), privkey.Hex, privkey.Wif, privkey.Network.ToCfdValue(), grindR)
	if err != nil {
		return nil, errors.Wrap(err, "calculate ec signature error")
	}
	if sighashType == nil {
		return types.NewByteDataFromHexIgnoreError(sig), nil
	}
	// DER encode
	derSig, err := cfd.CfdGoEncodeSignatureByDer(sig, sighashType.GetValue(), sighashType.AnyoneCanPay)
	if err != nil {
		return nil, errors.Wrap(err, "DER encode error")
	}
	signature = types.NewByteDataFromHexIgnoreError(derSig)
	return signature, nil
}

// validConfig ...
func (k *PrivkeyApiImpl) validConfig() error {
	if k.network == nil {
		return cfdErrors.ErrNetworkConfig
	} else if !k.network.IsBitcoin() {
		return cfdErrors.ErrBitcoinNetwork
	}
	return nil
}
