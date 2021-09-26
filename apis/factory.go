package apis

import (
	"github.com/cryptogarageinc/cfd-go/apis/address"
	"github.com/cryptogarageinc/cfd-go/apis/block"
	"github.com/cryptogarageinc/cfd-go/apis/crypto"
	"github.com/cryptogarageinc/cfd-go/apis/descriptor"
	"github.com/cryptogarageinc/cfd-go/apis/key"
	"github.com/cryptogarageinc/cfd-go/apis/transaction"
	"github.com/cryptogarageinc/cfd-go/config"
	cfdErrors "github.com/cryptogarageinc/cfd-go/errors"
	"github.com/cryptogarageinc/cfd-go/types"
	"github.com/cryptogarageinc/cfd-go/utils"
	"github.com/pkg/errors"
)

// BitcoinApiFactory ...
type BitcoinApiFactory interface {
	CreateCryptoApi() crypto.CryptoApi
	CreatePubkeyApi() key.PubkeyApi
	CreatePrivkeyApi() key.PrivkeyApi
	CreateExtPubkeyApi() key.ExtPubkeyApi
	CreateExtPrivkeyApi() key.ExtPrivkeyApi
	CreateHdWalletApi() key.HdWalletApi

	CreateBitcoinAddressApi() address.AddressApi
	CreateBitcoinTxApi() transaction.TransactionApi
	CreateBitcoinBlockApi() block.BlockApi
	CreateBitcoinDescriptorApi() descriptor.DescriptorApi
}

// ElementsApiFactory ...
type ElementsApiFactory interface {
	BitcoinApiFactory

	CreateElementsAddressApi() address.ElementsAddressApi
	CreateConfidentialAddressApi() address.ConfidentialAddressApi
	CreateElementsTxApi() transaction.ConfidentialTxApi
	CreateElementsDescriptorApi() descriptor.DescriptorApi
	CreateLedgerLiquidLibApi() transaction.LedgerLiquidLibApi
}

// NewBitcoinApiFactory returns an object of a factory that creates all api for bitcoin.
func NewBitcoinApiFactory(options ...config.CfdConfigOption) *ApiFactoryImpl {
	factory := ApiFactoryImpl{}
	conf := config.GetCurrentCfdConfig().WithOptions(options...)

	if !conf.Network.Valid() {
		factory.SetError(cfdErrors.ErrNetworkConfig)
	} else if !conf.Network.IsBitcoin() {
		factory.SetError(cfdErrors.ErrBitcoinNetwork)
	} else {
		network := conf.Network
		factory.network = &network
	}
	return &factory
}

// NewElementsApiFactory returns an object of a factory that creates all api for elements.
func NewElementsApiFactory(options ...config.CfdConfigOption) *ApiFactoryImpl {
	factory := ApiFactoryImpl{}
	var err error
	conf := config.GetCurrentCfdConfig().WithOptions(options...)

	network := types.Unknown
	if !conf.Network.Valid() {
		factory.SetError(cfdErrors.ErrNetworkConfig)
	} else if !conf.Network.IsElements() {
		factory.SetError(cfdErrors.ErrElementsNetwork)
	} else {
		network = conf.Network
	}

	var bitcoinAssetId *types.ByteData
	var bitcoinGenesisBlockHash *types.ByteData
	if len(conf.BitcoinAssetId) != 0 {
		if bitcoinAssetId, err = utils.ValidAssetId(conf.BitcoinAssetId); err != nil {
			factory.SetError(errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage))
		}
	}
	if len(conf.BitcoinGenesisBlockHash) != 0 {
		if bitcoinGenesisBlockHash, err = utils.ValidBlockHash(conf.BitcoinGenesisBlockHash); err != nil {
			factory.SetError(errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage))
		}
	}

	if network.Valid() {
		factory.network = &network
		factory.bitcoinGenesisBlockHash = bitcoinGenesisBlockHash
		factory.bitcoinAssetId = bitcoinAssetId
	}
	return &factory
}

// -------------------------------------
// ApiFactoryImpl
// -------------------------------------

type ApiFactoryImpl struct {
	cfdErrors.HasInitializeError
	network                 *types.NetworkType
	bitcoinGenesisBlockHash *types.ByteData
	bitcoinAssetId          *types.ByteData
}

func (p *ApiFactoryImpl) getConfig() *config.CfdConfig {
	conf := config.CfdConfig{Network: *p.network}
	if p.bitcoinAssetId != nil {
		conf.BitcoinAssetId = p.bitcoinAssetId.ToHex()
	}
	if p.bitcoinGenesisBlockHash != nil {
		conf.BitcoinGenesisBlockHash = p.bitcoinGenesisBlockHash.ToHex()
	}
	return &conf
}

func (a ApiFactoryImpl) CreateCryptoApi() crypto.CryptoApi {
	return crypto.NewCryptoApi()
}
func (a ApiFactoryImpl) CreatePubkeyApi() key.PubkeyApi {
	return key.NewPubkeyApi()
}
func (a ApiFactoryImpl) CreatePrivkeyApi() key.PrivkeyApi {
	return key.NewPrivkeyApi(a.getConfig().GetOptions()...)
}
func (a ApiFactoryImpl) CreateExtPubkeyApi() key.ExtPubkeyApi {
	return key.NewExtPubkeyApi(a.getConfig().GetOptions()...)
}
func (a ApiFactoryImpl) CreateExtPrivkeyApi() key.ExtPrivkeyApi {
	return key.NewExtPrivkeyApi(a.getConfig().GetOptions()...)
}
func (a ApiFactoryImpl) CreateHdWalletApi() key.HdWalletApi {
	return key.NewHdWalletApi(a.getConfig().GetOptions()...)
}

func (a ApiFactoryImpl) CreateBitcoinAddressApi() address.AddressApi {
	opt := config.NetworkOption(a.getConfig().Network.ToBitcoinType())
	return address.NewAddressApi(opt)
}
func (a ApiFactoryImpl) CreateBitcoinTxApi() transaction.TransactionApi {
	return transaction.NewTransactionApi(a.getConfig().GetOptions()...)
}
func (a ApiFactoryImpl) CreateBitcoinBlockApi() block.BlockApi {
	return block.NewBlockApi(a.getConfig().GetOptions()...)
}
func (a ApiFactoryImpl) CreateBitcoinDescriptorApi() descriptor.DescriptorApi {
	opt := config.NetworkOption(a.getConfig().Network.ToBitcoinType())
	return descriptor.NewDescriptorApi(opt)
}

func (a ApiFactoryImpl) CreateElementsAddressApi() address.ElementsAddressApi {
	return address.NewAddressApi(a.getConfig().GetOptions()...)
}
func (a ApiFactoryImpl) CreateConfidentialAddressApi() address.ConfidentialAddressApi {
	return address.NewConfidentialAddressApi()
}
func (a ApiFactoryImpl) CreateElementsTxApi() transaction.ConfidentialTxApi {
	return transaction.NewConfidentialTxApi(a.getConfig().GetOptions()...)
}
func (a ApiFactoryImpl) CreateElementsDescriptorApi() descriptor.DescriptorApi {
	return descriptor.NewDescriptorApi(a.getConfig().GetOptions()...)
}
func (a ApiFactoryImpl) CreateLedgerLiquidLibApi() transaction.LedgerLiquidLibApi {
	return transaction.NewLedgerLiquidLibApi(a.getConfig().GetOptions()...)
}
