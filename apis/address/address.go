package address

import (
	cfd "github.com/cryptogarageinc/cfd-go"
	config "github.com/cryptogarageinc/cfd-go/config"
	cfdErrors "github.com/cryptogarageinc/cfd-go/errors"
	types "github.com/cryptogarageinc/cfd-go/types"
	"github.com/pkg/errors"
)

// go generate comment
//go:generate -command mkdir mock
//go:generate mockgen -source address.go -destination mock/address.go -package mock
//go:generate goimports -w mock/address.go

// -------------------------------------
// API
// -------------------------------------

// AddressApi This interface handles bitcoin addresses.
type AddressApi interface {
	// GetNetworkTypes This function returns the available network types.
	GetNetworkTypes() []types.NetworkType
	ParseAddress(addressString string) (address *types.Address, err error)
	CreateByPubkey(pubkey *types.Pubkey, addressType types.AddressType) (address *types.Address, err error)
	CreateByScript(redeemScript *types.Script, addressType types.AddressType) (address *types.Address, err error)
	CreateMultisigAddress(pubkeys *[]types.Pubkey, requireNum uint32, addressType types.AddressType) (address *types.Address, redeemScript *types.Script, err error)
}

// ElementsAddressApi This interface handles elements addresses.
type ElementsAddressApi interface {
	AddressApi
	GetPeginAddressByPubkey(addressType types.AddressType, fedpegScript, pubkey string) (peginAddress *types.Address, claimScript *types.Script, err error)
	GetPegoutAddress(addressType types.AddressType, descriptorOrXpub string, bip32Counter uint32) (pegoutAddress *types.Address, baseDescriptor *string, err error)
}

// NewAddressApi returns an object that defines the API for address.
func NewAddressApi(options ...config.CfdConfigOption) *AddressApiImpl {
	api := AddressApiImpl{}
	conf := config.GetCurrentCfdConfig().WithOptions(options...)

	if !conf.Network.Valid() {
		api.SetError(cfdErrors.ErrNetworkConfig)
	} else {
		network := conf.Network
		api.network = &network
	}
	return &api
}

// -------------------------------------
// AddressApiImpl
// -------------------------------------

// AddressApiImpl ...
type AddressApiImpl struct {
	cfdErrors.HasInitializeError
	network *types.NetworkType
}

// GetNetworkTypes This function returns the available network types.
func (u *AddressApiImpl) GetNetworkTypes() []types.NetworkType {
	networks := []types.NetworkType{}
	if err := u.validConfig(); err != nil {
		// returns empty networks.
	} else if u.network.IsBitcoin() {
		networks = []types.NetworkType{types.Mainnet, types.Testnet, types.Regtest}
	} else if u.network.IsElements() {
		networks = []types.NetworkType{types.LiquidV1, types.ElementsRegtest}
	}
	return networks
}

// ParseAddress ...
func (u *AddressApiImpl) ParseAddress(addressString string) (address *types.Address, err error) {
	if err = u.validConfig(); err != nil {
		return nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	data, err := cfd.CfdGoGetAddressInfo(addressString)
	if err != nil {
		return nil, errors.Wrap(err, "parse address error")
	}
	address = &types.Address{
		Address:       addressString,
		Network:       types.NewNetworkType(data.NetworkType),
		Type:          types.NewAddressTypeByHashType(data.HashType),
		LockingScript: *types.NewScriptFromHexIgnoreError(data.LockingScript),
	}
	if address.Network.IsBitcoin() != u.network.IsBitcoin() {
		return address, cfdErrors.ErrUnmatchNetwork
	}
	return address, nil
}

// CreateByPubkey ...
func (u *AddressApiImpl) CreateByPubkey(pubkey *types.Pubkey, addressType types.AddressType) (address *types.Address, err error) {
	if err = u.validConfig(); err != nil {
		return nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	addr, _, _, err := cfd.CfdGoCreateAddress(addressType.ToHashType().ToCfdValue(), pubkey.Hex, "", u.network.ToCfdValue())
	if err != nil {
		return nil, errors.Wrap(err, "create address error")
	}
	address = &types.Address{
		Address: addr,
		Network: *u.network,
		Type:    addressType,
	}
	return address, nil
}

// CreateByScript ...
func (u *AddressApiImpl) CreateByScript(redeemScript *types.Script, addressType types.AddressType) (address *types.Address, err error) {
	if err = u.validConfig(); err != nil {
		return nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	addr, _, _, err := cfd.CfdGoCreateAddress(addressType.ToHashType().ToCfdValue(), "", redeemScript.ToHex(), u.network.ToCfdValue())
	if err != nil {
		return nil, errors.Wrap(err, "create address error")
	}
	address = &types.Address{
		Address: addr,
		Network: *u.network,
		Type:    addressType,
	}
	return address, nil
}

// CreateMultisigAddress ...
func (u *AddressApiImpl) CreateMultisigAddress(pubkeys *[]types.Pubkey, requireNum uint32, addressType types.AddressType) (address *types.Address, redeemScript *types.Script, err error) {
	if err = u.validConfig(); err != nil {
		return nil, nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	pubkeyList := make([]string, len(*pubkeys))
	for i := 0; i < len(*pubkeys); i++ {
		pubkeyList[i] = (*pubkeys)[i].Hex
	}
	addr, script, witnessScript, err := cfd.CfdGoCreateMultisigScript(u.network.ToCfdValue(), addressType.ToHashType().ToCfdValue(), pubkeyList, requireNum)
	if err != nil {
		return nil, nil, errors.Wrap(err, "create multisig error")
	}
	if addressType == types.P2shAddress {
		redeemScript = types.NewScriptFromHexIgnoreError(script)
	} else {
		redeemScript = types.NewScriptFromHexIgnoreError(witnessScript)
	}
	address = &types.Address{
		Address: addr,
		Network: *u.network,
		Type:    addressType,
	}
	return address, redeemScript, nil
}

// GetPeginAddressByPubkey ...
func (u *AddressApiImpl) GetPeginAddressByPubkey(addressType types.AddressType, fedpegScript, pubkey string) (peginAddress *types.Address, claimScript *types.Script, err error) {
	if err = u.validConfig(); err != nil {
		return nil, nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}

	addr, script, _, err := cfd.GetPeginAddress(u.network.ToBitcoinType().ToCfdValue(), fedpegScript, addressType.ToCfdValue(), pubkey, "")
	if err != nil {
		return nil, nil, errors.Wrap(err, "get pegin address error")
	}
	peginAddress = &types.Address{
		Address: addr,
		Network: u.network.ToBitcoinType(),
		Type:    addressType,
	}
	claimScript = types.NewScriptFromHexIgnoreError(script)
	return peginAddress, claimScript, nil
}

// GetPegoutAddress ...
func (u *AddressApiImpl) GetPegoutAddress(addressType types.AddressType, descriptorOrXpub string, bip32Counter uint32) (pegoutAddress *types.Address, baseDescriptor *string, err error) {
	if err = u.validConfig(); err != nil {
		return nil, nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	} else if !u.network.IsElements() {
		return nil, nil, errors.Errorf("CFD Error: GetPegoutAddress need elements network type")
	}

	addr, desc, err := cfd.GetPegoutAddress(u.network.ToBitcoinType().ToCfdValue(), u.network.ToCfdValue(), descriptorOrXpub, bip32Counter, addressType.ToCfdValue())
	if err != nil {
		return nil, nil, errors.Wrap(err, "get pegout address error")
	}
	pegoutAddress = &types.Address{
		Address: addr,
		Network: u.network.ToBitcoinType(),
		Type:    addressType,
	}
	baseDescriptor = &desc
	return pegoutAddress, baseDescriptor, nil
}

// validConfig ...
func (u *AddressApiImpl) validConfig() error {
	if u.network == nil {
		return cfdErrors.ErrNetworkConfig
	}
	return nil
}
