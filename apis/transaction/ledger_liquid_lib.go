package transaction

import (
	cfd "github.com/cryptogarageinc/cfd-go"
	"github.com/cryptogarageinc/cfd-go/apis/key"
	"github.com/cryptogarageinc/cfd-go/config"
	cfdErrors "github.com/cryptogarageinc/cfd-go/errors"
	"github.com/cryptogarageinc/cfd-go/types"
	"github.com/pkg/errors"
)

// go generate comment
//go:generate -command mkdir mock
//go:generate mockgen -source ledger_liquid_lib.go -destination mock/ledger_liquid_lib.go -package mock
//go:generate goimports -w mock/ledger_liquid_lib.go

// ConfidentialTxApi This interface defines the API to operate Elements Confidential Transaction.
type LedgerLiquidLibApi interface {
	// GetAuthorizeSignature returns the authorize signature.
	GetAuthorizeSignature(tx *types.ConfidentialTx, key *types.Privkey) (signature *types.ByteData, err error)
}

// NewLedgerLiquidLibApi returns a struct that implements LedgerLiquidLibApi.
func NewLedgerLiquidLibApi(options ...config.CfdConfigOption) *LedgerLiquidLibApiImpl {
	api := LedgerLiquidLibApiImpl{}
	conf := config.GetCurrentCfdConfig().WithOptions(options...)

	network := types.Unknown
	if !conf.Network.Valid() {
		api.SetError(cfdErrors.ErrNetworkConfig)
	} else if !conf.Network.IsElements() {
		api.SetError(cfdErrors.ErrElementsNetwork)
	} else {
		network = conf.Network
	}

	if network.Valid() {
		api.network = &network

		btcNetworkOpt := config.NetworkOption(network.ToBitcoinType())
		privkeyApi := key.NewPrivkeyApi(btcNetworkOpt)
		if privkeyApi.GetError() != nil {
			api.SetError(privkeyApi.GetError())
		} else {
			api.privkeyApi = privkeyApi
		}
	}
	return &api
}

// -------------------------------------
// ConfidentialTxApiImpl
// -------------------------------------

// ConfidentialTxApiImpl Create confidential transaction utility.
type LedgerLiquidLibApiImpl struct {
	cfdErrors.HasInitializeError
	network    *types.NetworkType
	privkeyApi key.PrivkeyApi
}

// WithPrivkeyApi sets a privkey api.
func (t *LedgerLiquidLibApiImpl) WithPrivkeyApi(privkeyApi key.PrivkeyApi) *LedgerLiquidLibApiImpl {
	if privkeyApi == nil {
		t.SetError(cfdErrors.ErrParameterNil)
	} else {
		t.privkeyApi = privkeyApi
	}
	return t
}

func (t *LedgerLiquidLibApiImpl) GetAuthorizeSignature(tx *types.ConfidentialTx, key *types.Privkey) (signature *types.ByteData, err error) {
	if err = t.validConfig(); err != nil {
		return nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}

	sig, err := cfd.CfdGoSerializeTxForLedger(tx.Hex, true, false)
	if err != nil {
		return nil, errors.Wrap(err, "serialize tx error")
	}
	sigObj := types.NewByteDataFromHexIgnoreError(sig)

	ecSig, err := t.privkeyApi.CreateEcSignatureGrindR(key, sigObj, &types.SigHashTypeAll, false)
	if err != nil {
		return nil, errors.Wrap(err, "create ec-signature error")
	}
	ecSigBytes := ecSig.ToSlice()
	ecSigBytes = ecSigBytes[:len(ecSigBytes)-1] // remove sighashtype
	authSig := types.NewByteData(ecSigBytes)
	signature = &authSig
	return signature, nil
}

func (t *LedgerLiquidLibApiImpl) validConfig() error {
	if t.network == nil {
		return cfdErrors.ErrNetworkConfig
	} else if !t.network.IsElements() {
		return cfdErrors.ErrElementsNetwork
	}
	return nil
}
