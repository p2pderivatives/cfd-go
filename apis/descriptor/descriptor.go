package descriptor

import (
	"strconv"
	"strings"

	cfd "github.com/cryptogarageinc/cfd-go"
	"github.com/cryptogarageinc/cfd-go/apis/address"
	"github.com/cryptogarageinc/cfd-go/config"
	cfdErrors "github.com/cryptogarageinc/cfd-go/errors"
	"github.com/cryptogarageinc/cfd-go/types"
	"github.com/cryptogarageinc/cfd-go/utils"
	"github.com/pkg/errors"
)

// go generate comment
//go:generate -command mkdir mock
//go:generate mockgen -source descriptor.go -destination mock/descriptor.go -package mock
//go:generate goimports -w mock/descriptor.go

type DescriptorApi interface {
	// GetNetworkTypes returnss the available network types.
	GetNetworkTypes() []types.NetworkType
	// NewDescriptorFromAddress returns a Descriptor from pubkey.
	NewDescriptorFromPubkey(
		hashType types.HashType, pubkey *types.Pubkey) *types.Descriptor
	// NewDescriptorFromMultisig returns a Descriptor from multisig.
	NewDescriptorFromMultisig(
		hashType types.HashType,
		pubkeys []string,
		requireNum int,
	) *types.Descriptor
	// NewDescriptor returns a Descriptor.
	NewDescriptorFromString(descriptor string) *types.Descriptor
	// NewDescriptorFromLockingScript returns a Descriptor from locking script.
	NewDescriptorFromLockingScript(lockingScript string) *types.Descriptor
	// NewDescriptorFromAddress returns a Descriptor from address.
	NewDescriptorFromAddress(address string) *types.Descriptor
	// ParseByString returns a Descriptor parsing data.
	ParseByString(descriptor string) (
		data *types.DescriptorRootData,
		descriptorDataList []types.DescriptorData,
		err error,
	)
	// Parse returns a Descriptor parsing data.
	Parse(descriptor *types.Descriptor) (
		data *types.DescriptorRootData,
		descriptorDataList []types.DescriptorData,
		err error,
	)
	// ParseWithDerivationPath returns a Descriptor parsing data.
	ParseWithDerivationPath(
		descriptor *types.Descriptor,
		bip32DerivationPath string,
	) (
		data *types.DescriptorRootData,
		descriptorDataList []types.DescriptorData,
		err error,
	)
	// ParseByFilter returns a Descriptor parsing data by filter.
	ParseByFilter(
		descriptor *types.Descriptor,
		filter *types.DescriptorParseFilter,
	) (
		rootData *types.DescriptorRootData,
		descriptorDataList []types.DescriptorData,
		err error,
	)
	// ParseByFilterWithDerivationPath returns a Descriptor parsing data by filter.
	ParseByFilterWithDerivationPath(
		descriptor *types.Descriptor,
		bip32DerivationPath string,
		filter *types.DescriptorParseFilter,
	) (
		rootData *types.DescriptorRootData,
		descriptorDataList []types.DescriptorData,
		err error,
	)
	// GetChecksum returns a descriptor adding checksum.
	GetChecksum(
		descriptor *types.Descriptor) (descriptorAddedChecksum string, err error)
}

// NewDescriptorApi returns an object that defines the API for output descriptor.
func NewDescriptorApi(options ...config.CfdConfigOption) *DescriptorApiImpl {
	api := DescriptorApiImpl{}
	conf := config.GetCurrentCfdConfig().WithOptions(options...)

	if !conf.Network.Valid() {
		api.SetError(cfdErrors.ErrNetworkConfig)
	} else {
		network := conf.Network
		api.network = &network

		addressApi := address.NewAddressApi(config.NetworkOption(network))
		if addressApi.HasError() {
			api.SetError(addressApi.GetError())
		} else {
			api.addressApi = addressApi
		}
	}
	return &api
}

// -------------------------------------
// Descriptor
// -------------------------------------

// Descriptor This struct use for the output descriptor.
type DescriptorApiImpl struct {
	cfdErrors.HasInitializeError
	network    *types.NetworkType // Network Type
	addressApi address.AddressApi
}

// WithAddressApi This function set an address api.
func (p *DescriptorApiImpl) WithAddressApi(addressApi address.AddressApi) *DescriptorApiImpl {
	if addressApi == nil {
		p.SetError(cfdErrors.ErrParameterNil)
	} else if p.network == nil {
		p.SetError(cfdErrors.ErrNetworkConfig)
	} else if !utils.ValidNetworkTypes(addressApi.GetNetworkTypes(), *p.network) {
		p.SetError(cfdErrors.ErrNetworkConfig)
	} else {
		p.addressApi = addressApi
	}
	return p
}

// GetNetworkTypes returnss the available network types.
func (d *DescriptorApiImpl) GetNetworkTypes() []types.NetworkType {
	networks := []types.NetworkType{}
	if err := d.validConfig(); err != nil {
		// returns empty networks.
	} else if d.network.IsBitcoin() {
		networks = []types.NetworkType{types.Mainnet, types.Testnet, types.Regtest}
	} else if d.network.IsElements() {
		networks = []types.NetworkType{types.LiquidV1, types.ElementsRegtest}
	}
	return networks
}

// NewDescriptorFromAddress returns a Descriptor from pubkey.
func (d *DescriptorApiImpl) NewDescriptorFromPubkey(hashType types.HashType, pubkey *types.Pubkey) *types.Descriptor {
	var desc string
	if hashType == types.P2shP2wpkh {
		desc = "sh(wpkh(" + pubkey.Hex + "))"
	} else if hashType == types.P2wpkh {
		desc = "wpkh(" + pubkey.Hex + ")"
	} else {
		desc = "pkh(" + pubkey.Hex + ")"
	}
	return &types.Descriptor{
		OutputDescriptor: desc,
	}
}

// NewDescriptorFromMultisig returns a Descriptor from multisig.
func (d *DescriptorApiImpl) NewDescriptorFromMultisig(hashType types.HashType, pubkeys []string, requireNum int) *types.Descriptor {
	var desc string
	desc = desc + "multi(" + strconv.Itoa(requireNum) + "," + strings.Join(pubkeys, ",") + ")"
	if hashType == types.P2shP2wsh {
		desc = "sh(wsh(" + desc + "))"
	} else if hashType == types.P2wsh {
		desc = "wsh(" + desc + ")"
	} else if hashType == types.P2sh {
		desc = "sh(" + desc + ")"
	}
	return &types.Descriptor{
		OutputDescriptor: desc,
	}
}

// NewDescriptor returns a Descriptor.
func (d *DescriptorApiImpl) NewDescriptorFromString(descriptor string) *types.Descriptor {
	return &types.Descriptor{
		OutputDescriptor: descriptor,
	}
}

// NewDescriptorFromLockingScript returns a Descriptor from locking script.
func (d *DescriptorApiImpl) NewDescriptorFromLockingScript(lockingScript string) *types.Descriptor {
	desc := "raw(" + lockingScript + ")"
	return &types.Descriptor{
		OutputDescriptor: desc,
	}
}

// NewDescriptorFromAddress returns a Descriptor from address.
func (d *DescriptorApiImpl) NewDescriptorFromAddress(address string) *types.Descriptor {
	desc := "addr(" + address + ")"
	return &types.Descriptor{
		OutputDescriptor: desc,
	}
}

func (d *DescriptorApiImpl) validConfig() error {
	if d.network == nil {
		return cfdErrors.ErrNetworkConfig
	}
	return nil
}

// ParseByString returns a Descriptor parsing data.
func (d *DescriptorApiImpl) ParseByString(descriptor string) (rootData *types.DescriptorRootData, descriptorDataList []types.DescriptorData, err error) {
	return d.ParseWithDerivationPath(&types.Descriptor{OutputDescriptor: descriptor}, "")
}

// Parse returns a Descriptor parsing data.
func (d *DescriptorApiImpl) Parse(descriptor *types.Descriptor) (rootData *types.DescriptorRootData, descriptorDataList []types.DescriptorData, err error) {
	return d.ParseWithDerivationPath(descriptor, "")
}

// ParseWithDerivationPath returns a Descriptor parsing data.
func (d *DescriptorApiImpl) ParseWithDerivationPath(descriptor *types.Descriptor, bip32DerivationPath string) (rootData *types.DescriptorRootData, descriptorDataList []types.DescriptorData, err error) {
	if err = d.validConfig(); err != nil {
		return nil, nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	cfdData, cfdDescDataList, cfdMultisigs, err := cfd.CfdGoParseDescriptorData(descriptor.OutputDescriptor, d.network.ToCfdValue(), bip32DerivationPath)
	if err != nil {
		return nil, nil, errors.Wrap(err, "parse descriptor error")
	}
	data, descriptorDataList, multisigList := convertFromCfd(&cfdData, cfdDescDataList, cfdMultisigs)

	var address types.Address
	if data.Address != "" {
		addrObj, err := d.addressApi.ParseAddress(data.Address)
		if err != nil {
			return nil, nil, errors.Wrap(err, "parse address error")
		}
		address = *addrObj
	}
	rootData = &types.DescriptorRootData{
		Depth:      cfdData.Depth,
		Type:       types.NewDescriptorType(cfdData.ScriptType),
		Address:    address,
		HashType:   types.NewHashType(cfdData.HashType),
		TreeString: cfdData.TreeString,
	}
	if rootData.HashType.IsScriptHash() {
		rootData.RedeemScript = types.NewScriptFromHexIgnoreError(cfdData.RedeemScript)
	}
	rootData.Key = types.NewDescriptorKey(
		cfdData.KeyType, cfdData.Pubkey, cfdData.ExtPubkey, cfdData.ExtPrivkey, cfdData.SchnorrPubkey)
	if cfdData.IsMultisig {
		rootData.Multisig = types.NewDescriptorMultisig(cfdData.ReqSigNum, multisigList)
	}

	return rootData, descriptorDataList, nil
}

// ParseByFilter returns a Descriptor parsing data by filter.
func (d *DescriptorApiImpl) ParseByFilter(descriptor *types.Descriptor, filter *types.DescriptorParseFilter) (rootData *types.DescriptorRootData, descriptorDataList []types.DescriptorData, err error) {
	return d.ParseByFilterWithDerivationPath(descriptor, "", filter)
}

// ParseByFilterWithDerivationPath returns a Descriptor parsing data by filter.
func (d *DescriptorApiImpl) ParseByFilterWithDerivationPath(descriptor *types.Descriptor, bip32DerivationPath string, filter *types.DescriptorParseFilter) (rootData *types.DescriptorRootData, descriptorDataList []types.DescriptorData, err error) {
	data, details, err := d.ParseWithDerivationPath(descriptor, bip32DerivationPath)
	if err != nil {
		return
	} else if err = filter.Check(data); err != nil {
		return
	}
	rootData = data
	descriptorDataList = details
	return
}

// GetChecksum returns a descriptor adding checksum.
func (d *DescriptorApiImpl) GetChecksum(descriptor *types.Descriptor) (descriptorAddedChecksum string, err error) {
	if err = d.validConfig(); err != nil {
		return "", errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	descriptorAddedChecksum, err = cfd.CfdGoGetDescriptorChecksum(d.network.ToCfdValue(), descriptor.OutputDescriptor)
	if err != nil {
		return "", errors.Wrap(err, "parse descriptor error")
	}
	return descriptorAddedChecksum, nil
}

func convertFromCfd(cfdData *cfd.CfdDescriptorData, cfdDescriptorDataList []cfd.CfdDescriptorData, cfdMultisigList []cfd.CfdDescriptorKeyData) (data *types.DescriptorData, descriptorDataList []types.DescriptorData, multisigList []types.DescriptorKeyData) {
	data = types.NewDescriptorData(cfdData)
	descriptorDataList = make([]types.DescriptorData, len(cfdDescriptorDataList))
	for i, data := range cfdDescriptorDataList {
		descriptorDataList[i] = *(types.NewDescriptorData(&data))
	}
	if cfdMultisigList != nil {
		multisigList = make([]types.DescriptorKeyData, len(cfdMultisigList))
		for i, key := range cfdMultisigList {
			multisigList[i] = types.DescriptorKeyData{
				KeyType:       key.KeyType,
				Pubkey:        key.Pubkey,
				ExtPubkey:     key.ExtPubkey,
				ExtPrivkey:    key.ExtPrivkey,
				SchnorrPubkey: key.SchnorrPubkey,
			}
		}
	}
	return data, descriptorDataList, multisigList
}
