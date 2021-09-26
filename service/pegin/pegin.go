package pegin

import (
	cfd "github.com/cryptogarageinc/cfd-go"
	"github.com/cryptogarageinc/cfd-go/apis/address"
	"github.com/cryptogarageinc/cfd-go/apis/descriptor"
	"github.com/cryptogarageinc/cfd-go/apis/key"
	"github.com/cryptogarageinc/cfd-go/apis/transaction"
	"github.com/cryptogarageinc/cfd-go/config"
	cfdErrors "github.com/cryptogarageinc/cfd-go/errors"
	"github.com/cryptogarageinc/cfd-go/types"
	"github.com/cryptogarageinc/cfd-go/utils"

	"github.com/pkg/errors"
)

// go generate comment
//go:generate -command mkdir mock
//go:generate mockgen -source pegin.go -destination mock/pegin.go -package mock
//go:generate goimports -w mock/pegin.go

// Pegin This interface defines the API used by the pegin function.
type Pegin interface {
	// GetPubkeyFromAccountExtPubkey This function get the pubkey from xpubkey.
	GetPubkeyFromAccountExtPubkey(
		accountExtPubkey *types.ExtPubkey,
		bip32Path string, // change and index path
	) (
		pubkey *types.Pubkey,
		derivedExtPubkey *types.ExtPubkey,
		err error,
	)
	// CreatePeginAddress This function get the pegin address and claim script.
	CreatePeginAddress(
		addressType types.AddressType,
		pubkey *types.Pubkey,
		fedpegScript *types.Script,
	) (peginAddress *types.Address, claimScript *types.Script, err error)
	// CreatePeginTransaction This function create the pegin claim transaction.
	CreatePeginTransaction(
		peginOutPoint *types.OutPoint,
		peginData *types.InputPeginData,
		utxoList []*types.ElementsUtxoData,
		sendList []types.InputConfidentialTxOut,
		changeAddress *string,
		option *types.PeginTxOption,
	) (
		tx *types.ConfidentialTx,
		unblindTx *types.ConfidentialTx,
		err error,
	)
	// VerifyPubkeySignature This function validate the signature by pubkey.
	VerifyPubkeySignature(
		proposalTx *types.ConfidentialTx,
		utxoData *types.ElementsUtxoData,
		signature *types.ByteData,
	) (isVerify bool, err error)
	// GetPeginUtxoData This function get the pegin utxo data from transaction.
	GetPeginUtxoData(
		proposalTx *types.ConfidentialTx,
		peginOutPoint *types.OutPoint,
		pubkey *types.Pubkey,
	) (utxoData *types.ElementsUtxoData, err error)
}

// NewPeginService returns an object that defines the API for Pegin.
func NewPeginService(options ...config.CfdConfigOption) *PeginService {
	service := PeginService{}
	var err error
	conf := config.GetCurrentCfdConfig().WithOptions(options...)

	network := types.Unknown
	if !conf.Network.Valid() {
		service.SetError(cfdErrors.ErrNetworkConfig)
	} else if !conf.Network.IsElements() {
		service.SetError(cfdErrors.ErrElementsNetwork)
	} else {
		network = conf.Network
	}

	var bitcoinAssetId *types.ByteData
	if len(conf.BitcoinAssetId) != 0 {
		if bitcoinAssetId, err = utils.ValidAssetId(conf.BitcoinAssetId); err != nil {
			service.SetError(
				errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage))
		}
	}
	var bitcoinGenesisBlockHash *types.ByteData
	if len(conf.BitcoinGenesisBlockHash) != 0 {
		if bitcoinGenesisBlockHash, err = utils.ValidBlockHash(conf.BitcoinGenesisBlockHash); err != nil {
			service.SetError(
				errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage))
		}
	}

	if network.Valid() {
		service.network = &network
		service.bitcoinAssetId = bitcoinAssetId
		service.bitcoinGenesisBlockHash = bitcoinGenesisBlockHash

		elementsConfOpts := service.getConfig().GetOptions()
		descriptorApi := descriptor.NewDescriptorApi(elementsConfOpts...)
		if descriptorApi.GetError() != nil {
			service.SetError(descriptorApi.GetError())
		} else {
			service.descriptorApi = descriptorApi
		}

		addressApi := address.NewAddressApi(elementsConfOpts...)
		if addressApi.GetError() != nil {
			service.SetError(addressApi.GetError())
		} else {
			service.elementsAddressApi = addressApi
		}

		txApi := transaction.NewConfidentialTxApi(elementsConfOpts...)
		if txApi.GetError() != nil {
			service.SetError(txApi.GetError())
		} else {
			service.elementsTxApi = txApi
		}

		btcNetworkOpt := config.NetworkOption(network.ToBitcoinType())
		bitcoinTxApi := transaction.NewTransactionApi(btcNetworkOpt)
		if bitcoinTxApi.GetError() != nil {
			service.SetError(bitcoinTxApi.GetError())
		} else {
			service.bitcoinTxApi = bitcoinTxApi
		}
		service.pubkeyApi = key.NewPubkeyApi()
	}
	return &service
}

// -------------------------------------
// PeginService
// -------------------------------------

// PeginService This struct is implements pegin api.
type PeginService struct {
	cfdErrors.HasInitializeError
	network                 *types.NetworkType
	bitcoinGenesisBlockHash *types.ByteData
	bitcoinAssetId          *types.ByteData
	elementsAddressApi      address.ElementsAddressApi
	bitcoinTxApi            transaction.TransactionApi
	elementsTxApi           transaction.ConfidentialTxApi
	descriptorApi           descriptor.DescriptorApi
	pubkeyApi               key.PubkeyApi
}

// WithElementsDescriptorApi This function set a elements descriptor api.
func (p *PeginService) WithElementsDescriptorApi(descriptorApi descriptor.DescriptorApi) *PeginService {
	if descriptorApi == nil {
		p.SetError(cfdErrors.ErrParameterNil)
	} else if !utils.ValidNetworkTypes(descriptorApi.GetNetworkTypes(), types.LiquidV1) {
		p.SetError(cfdErrors.ErrElementsNetwork)
	} else {
		p.descriptorApi = descriptorApi
	}
	return p
}

// WithElementsAddressApi This function set a elements address api.
func (p *PeginService) WithElementsAddressApi(addressApi address.ElementsAddressApi) *PeginService {
	if addressApi == nil {
		p.SetError(cfdErrors.ErrParameterNil)
	} else if !utils.ValidNetworkTypes(addressApi.GetNetworkTypes(), types.LiquidV1) {
		p.SetError(cfdErrors.ErrElementsNetwork)
	} else {
		p.elementsAddressApi = addressApi
	}
	return p
}

// WithBitcoinTxApi This function set a bitcoin transaction api.
func (p *PeginService) WithBitcoinTxApi(transactionApi transaction.TransactionApi) *PeginService {
	if transactionApi == nil {
		p.SetError(cfdErrors.ErrParameterNil)
	} else {
		p.bitcoinTxApi = transactionApi
	}
	return p
}

// WithConfidentialTxApi This function set a confidential transaction api.
func (p *PeginService) WithConfidentialTxApi(confidentialTxApi transaction.ConfidentialTxApi) *PeginService {
	if confidentialTxApi == nil {
		p.SetError(cfdErrors.ErrParameterNil)
	} else {
		p.elementsTxApi = confidentialTxApi
	}
	return p
}

// WithPubkeyApi This function set a pubkey api.
func (p *PeginService) WithPubkeyApi(pubkeyApi key.PubkeyApi) *PeginService {
	if pubkeyApi == nil {
		p.SetError(cfdErrors.ErrParameterNil)
	} else {
		p.pubkeyApi = pubkeyApi
	}
	return p
}

// GetPubkeyFromExtPubkey This function get the pubkey from xpubkey.
func (p *PeginService) GetPubkeyFromAccountExtPubkey(
	accountExtPubkey *types.ExtPubkey,
	bip32Path string,
) (
	pubkey *types.Pubkey,
	derivedExtPubkey *types.ExtPubkey,
	err error,
) {
	if err = p.validConfig(); err != nil {
		return nil, nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}
	if err = validatePeginExtPubkey(accountExtPubkey); err != nil {
		return nil, nil, errors.Wrap(err, "Pegin extPubkey validation error")
	}

	deriveKey, err := cfd.CfdGoCreateExtkeyFromParentPath(accountExtPubkey.Key, bip32Path, p.network.ToBitcoinType().ToCfdValue(), int(cfd.KCfdExtPubkey))
	if err != nil {
		return nil, nil, errors.Wrap(err, "Pegin extPubkey derive error")
	}
	derivedExtPubkey = &types.ExtPubkey{Key: deriveKey}
	if err = validateDerivedExtPubkey(derivedExtPubkey); err != nil {
		return nil, nil, errors.Wrap(err, "Pegin derive extPubkey validation error")
	}

	pubkeyHex, err := cfd.CfdGoGetPubkeyFromExtkey(deriveKey, p.network.ToBitcoinType().ToCfdValue())
	if err != nil {
		return nil, nil, errors.Wrap(err, "Pegin pubkey get error")
	}
	pubkey = &types.Pubkey{Hex: pubkeyHex}
	return pubkey, derivedExtPubkey, nil
}

// CreatePeginAddress This function get the pegin address and claim script.
func (p *PeginService) CreatePeginAddress(
	addressType types.AddressType,
	pubkey *types.Pubkey,
	fedpegScript *types.Script,
) (
	peginAddress *types.Address,
	claimScript *types.Script,
	err error,
) {
	if err = p.validConfig(); err != nil {
		return nil, nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}

	switch addressType {
	case types.P2shAddress, types.P2wshAddress, types.P2shP2wshAddress:
		break
	default:
		return nil, nil, errors.Errorf("CFD Error: Invalid pegin address type")
	}

	peginAddress, claimScript, err = p.elementsAddressApi.GetPeginAddressByPubkey(addressType, fedpegScript.ToHex(), pubkey.Hex)
	if err != nil {
		return nil, nil, errors.Wrap(err, "get pegin address error")
	}
	return peginAddress, claimScript, nil
}

// CreatePeginTransaction This function create the pegin claim transaction.
func (p *PeginService) CreatePeginTransaction(
	peginOutPoint *types.OutPoint,
	peginData *types.InputPeginData,
	utxoList []*types.ElementsUtxoData,
	sendList []types.InputConfidentialTxOut,
	changeAddress *string,
	option *types.PeginTxOption,
) (tx *types.ConfidentialTx, unblindTx *types.ConfidentialTx, err error) {
	if err = p.validConfig(); err != nil {
		return nil, nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	}

	// validation utxoList, peginData
	if err = p.validateUtxoList(utxoList); err != nil {
		return nil, nil, errors.Wrap(err, "Pegin utxoList validation error")
	} else if err = p.validatePeginData(peginOutPoint, peginData); err != nil {
		return nil, nil, errors.Wrap(err, "Pegin peginData validation error")
	}

	assetId := ""
	cfdConfig := config.GetCurrentCfdConfig()
	if len(cfdConfig.BitcoinAssetId) == 64 {
		assetId = cfdConfig.BitcoinAssetId
	} else {
		assetId = peginData.BitcoinAssetId
	}

	changeAddr, err := p.validateChangeAddress(changeAddress)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Pegin changeAddress validation error")
	}

	blindOutputCount, hasAppendDummyOutput, amount, err := p.validateTxOutList(&sendList, changeAddr)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Pegin sendList validation error")
	}
	if option.IsBlindTx && (blindOutputCount == 0) {
		return nil, nil, errors.Wrap(err, "Pegin sendList empty blinding output error")
	} else if !option.IsBlindTx && (blindOutputCount > 0) {
		return nil, nil, errors.Wrap(err, "Pegin sendList exist blinding output error")
	}

	txins := []types.InputConfidentialTxIn{
		{
			OutPoint:   *peginOutPoint,
			PeginInput: peginData,
		},
	}
	tx, err = p.elementsTxApi.Create(uint32(2), uint32(0), &txins, &sendList, nil)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Pegin CT.Create error")
	}

	// 2. add txout by output if single output.
	if hasAppendDummyOutput {
		// TODO Is this really a necessary process? I feel like it should be integrated with the subsequent process.
		tx.Hex, err = appendDummyOutput(tx.Hex, assetId, p.network)
		if err != nil {
			return nil, nil, errors.Wrap(err, "Pegin append dummy output error")
		}
	}

	// 3. fundrawtransaction
	peginAmount, _, err := cfd.CfdGoGetTxOut(p.network.ToBitcoinType().ToCfdValue(), peginData.BitcoinTransaction, peginOutPoint.Vout)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Pegin get btc txout error")
	}
	fundTxInList := make([]cfd.CfdUtxo, 1)
	fundTxInList[0].Txid = peginOutPoint.Txid
	fundTxInList[0].Vout = peginOutPoint.Vout
	fundTxInList[0].Amount = peginAmount
	fundTxInList[0].Asset = assetId
	fundTxInList[0].IsPegin = true
	fundTxInList[0].ClaimScript = peginData.ClaimScript
	fundTxInList[0].PeginBtcTxSize = uint32(len(peginData.BitcoinTransaction) / 2)
	fundTxInList[0].PeginTxOutProofSize = uint32(len(peginData.TxOutProof) / 2)
	fundTxInList[0].Descriptor = "wpkh(02" + assetId + ")" // dummy for calc fee

	utxoListLen := 0
	if utxoList != nil {
		utxoListLen = len(utxoList)
	}
	fundUtxoList := make([]cfd.CfdUtxo, utxoListLen)
	utxoMap := make(map[types.OutPoint]*types.ElementsUtxoData, utxoListLen)
	for i, txin := range utxoList {
		fundUtxoList[i].Txid = txin.OutPoint.Txid
		fundUtxoList[i].Vout = txin.OutPoint.Vout
		fundUtxoList[i].Amount = txin.Amount
		fundUtxoList[i].Asset = txin.Asset
		fundUtxoList[i].Descriptor = txin.Descriptor
		fundUtxoList[i].AmountCommitment = txin.AmountCommitment
		utxoMap[txin.OutPoint] = txin
	}
	targetAmounts := []cfd.CfdFundRawTxTargetAmount{
		{
			Amount: 0,
			Asset:  assetId,
		},
	}
	if amount == 0 {
		targetAmounts[0].Amount = 1
	}
	if changeAddress != nil {
		targetAmounts[0].ReservedAddress = *changeAddress
	}
	fundOption := cfd.NewCfdFundRawTxOption(p.network.ToCfdValue())
	fundOption.FeeAsset = assetId
	fundOption.EffectiveFeeRate = option.EffectiveFeeRate
	fundOption.LongTermFeeRate = option.LongTermFeeRate
	fundOption.DustFeeRate = option.DustFeeRate
	fundOption.IsBlindTx = option.IsBlindTx
	fundOption.KnapsackMinChange = option.KnapsackMinChange
	fundOption.Exponent = option.Exponent
	fundOption.MinimumBits = option.MinimumBits
	outputTx, _, _, err := cfd.CfdGoFundRawTransaction(p.network.ToCfdValue(), tx.Hex, fundTxInList, fundUtxoList, targetAmounts, &fundOption)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "Pegin FundRawTransaction error (tx: %s)", tx.Hex)
	}
	outputCount, err := cfd.CfdGoGetTxOutCount(p.network.ToCfdValue(), outputTx)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Pegin GetTxOutCount error")
	}

	// 4. check to need append dummy output
	if option.IsBlindTx && !hasAppendDummyOutput && (outputCount == 2) { // 2 = output + fee
		tx.Hex, err = appendDummyOutput(tx.Hex, assetId, p.network)
		if err != nil {
			return nil, nil, errors.Wrap(err, "Pegin append dummy output error")
		}
		outputTx, _, _, err = cfd.CfdGoFundRawTransaction(p.network.ToCfdValue(), tx.Hex, fundTxInList, fundUtxoList, targetAmounts, &fundOption)
		if err != nil {
			return nil, nil, errors.Wrap(err, "Pegin FundRawTransaction error")
		}
	}
	tx.Hex = outputTx

	_, inputs, _, err := p.elementsTxApi.GetAll(tx, false)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Pegin GetTxAll error")
	}

	// 5. blind
	unblindTx = &types.ConfidentialTx{Hex: tx.Hex}
	if option.IsBlindTx {
		blindInputList := make([]types.BlindInputData, len(inputs))
		for i, txin := range inputs {
			blindInputList[i].OutPoint = txin.OutPoint
			if txin.OutPoint.Equal(*peginOutPoint) {
				blindInputList[i].Amount = peginAmount
				blindInputList[i].Asset = assetId
			} else {
				utxo, ok := utxoMap[txin.OutPoint]
				if !ok {
					return nil, nil, cfdErrors.InternalError
				}
				blindInputList[i].Amount = utxo.Amount
				blindInputList[i].Asset = utxo.Asset
				blindInputList[i].ValueBlindFactor = utxo.ValueBlindFactor
				blindInputList[i].AssetBlindFactor = utxo.AssetBlindFactor
			}
		}
		blindOption := types.NewBlindTxOption()
		blindOption.MinimumRangeValue = option.MinimumRangeValue
		blindOption.Exponent = option.Exponent
		blindOption.MinimumBits = option.MinimumBits
		err = p.elementsTxApi.Blind(tx, blindInputList, nil, &blindOption)
		if err != nil {
			return nil, nil, errors.Wrap(err, "Pegin Blind error")
		}
	}
	return tx, unblindTx, nil
}

// VerifyPubkeySignature This function validate the signature by pubkey.
func (p *PeginService) VerifyPubkeySignature(
	proposalTx *types.ConfidentialTx,
	utxoData *types.ElementsUtxoData,
	signature *types.ByteData,
) (isVerify bool, err error) {
	if err = p.validConfig(); err != nil {
		return false, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	} else if proposalTx == nil || utxoData == nil || signature == nil {
		return false, cfdErrors.ErrParameterNil
	} else if err = p.validateUtxoData(utxoData); err != nil {
		return false, errors.Wrap(err, "Pegin utxoData validate error")
	}

	sig, cfdSighashType, _, err := cfd.CfdGoDecodeSignatureFromDer(signature.ToHex())
	if err != nil {
		return false, errors.Wrap(err, "Pegin decode signature error")
	}
	sighashType := types.NewSigHashType(cfdSighashType)
	utxoList := []*types.ElementsUtxoData{utxoData}
	sighash, err := p.elementsTxApi.GetSighash(proposalTx, &utxoData.OutPoint, *sighashType, utxoList)
	if err != nil {
		return false, errors.Wrap(err, "Pegin decode signature error")
	}
	desc := types.Descriptor{OutputDescriptor: utxoData.Descriptor}
	descData, _, err := p.descriptorApi.Parse(&desc)
	if err != nil {
		return false, errors.Wrap(err, "Pegin parse descriptor error")
	} else if !descData.Key.KeyType.Valid() {
		return false, errors.Wrap(err, "Pegin descriptor unsupport key type")
	}
	pubkey := descData.Key.Pubkey
	isVerify, err = p.pubkeyApi.VerifyEcSignature(pubkey, sighash.ToHex(), sig)
	if err != nil {
		return false, errors.Wrap(err, "Pegin verify signature error")
	}
	return isVerify, nil
}

// GetPeginUtxoData This function get the pegin utxo data from transaction.
func (p *PeginService) GetPeginUtxoData(
	proposalTx *types.ConfidentialTx,
	peginOutPoint *types.OutPoint,
	pubkey *types.Pubkey,
) (utxoData *types.ElementsUtxoData, err error) {
	if err = p.validConfig(); err != nil {
		return nil, errors.Wrap(err, cfdErrors.InvalidConfigErrorMessage)
	} else if proposalTx == nil || peginOutPoint == nil || pubkey == nil {
		return nil, cfdErrors.ErrParameterNil
	}

	input, err := p.elementsTxApi.GetTxIn(proposalTx.Hex, peginOutPoint)
	if err != nil {
		return nil, errors.Wrap(err, "Pegin get txin index error")
	} else if len(input.PeginWitness.Stack) < 6 {
		return nil, errors.Wrap(err, "Target outpoint is not pegin")
	}
	btcTx := types.Transaction{Hex: input.PeginWitness.Stack[4]}
	output, err := p.bitcoinTxApi.GetTxOut(&btcTx, peginOutPoint.Vout)
	if err != nil {
		return nil, errors.Wrap(err, "Pegin get btc tx error")
	}

	assetBytes := cfd.NewByteDataFromHexIgnoreError(input.PeginWitness.Stack[1])
	asset := make([]byte, 32)
	for i, data := range assetBytes.ToSlice() {
		asset[32-i-1] = data
	}
	assetObj := cfd.NewByteData(asset)

	utxoData = &types.ElementsUtxoData{
		OutPoint:   *peginOutPoint,
		Amount:     output.Amount,
		Descriptor: "wpkh(" + pubkey.Hex + ")",
		Asset:      assetObj.ToHex(),
		PeginData: &types.PeginUtxoData{
			ClaimScript:        input.PeginWitness.Stack[3],
			BitcoinTransaction: input.PeginWitness.Stack[4],
			TxOutProof:         input.PeginWitness.Stack[5],
		},
	}
	return utxoData, nil
}

func (p *PeginService) validConfig() error {
	if p.network == nil {
		return cfdErrors.ErrNetworkConfig
	} else if !p.network.IsElements() {
		return cfdErrors.ErrElementsNetwork
	}
	return nil
}

func (p *PeginService) getConfig() *config.CfdConfig {
	conf := config.CfdConfig{Network: *p.network}
	if p.bitcoinAssetId != nil {
		conf.BitcoinAssetId = p.bitcoinAssetId.ToHex()
	}
	if p.bitcoinGenesisBlockHash != nil {
		conf.BitcoinGenesisBlockHash = p.bitcoinGenesisBlockHash.ToHex()
	}
	return &conf
}

func validatePeginExtPubkey(extPubkey *types.ExtPubkey) error {
	if extPubkey == nil {
		return errors.Errorf("CFD Error: Pegin extkey is null")
	}
	data, err := cfd.CfdGoGetExtkeyInformation(extPubkey.Key)
	if err != nil {
		return errors.Wrap(err, "extkey convert error")
	} else if data.Depth != 3 {
		return errors.Errorf("CFD Error: Invalid pegin extkey depth (%d)", data.Depth)
	}
	return nil
}

func validateDerivedExtPubkey(extPubkey *types.ExtPubkey) error {
	data, err := cfd.CfdGoGetExtkeyInformation(extPubkey.Key)
	if err != nil {
		return errors.Wrap(err, "extkey convert error")
	} else if data.Depth != 5 {
		return errors.Errorf("CFD Error: Invalid pegin derive depth (%d)", data.Depth)
	}
	return nil
}

func (p *PeginService) validateTxOutList(sendList *[]types.InputConfidentialTxOut, changeAddress *types.ConfidentialAddress) (blindOutputCount uint32, hasAppendDummyOutput bool, amount int64, err error) {
	caApi := address.ConfidentialAddressApiImpl{}
	blindOutputCount = uint32(0)
	unblindOutputCount := uint32(0)
	feeCount := uint32(0)
	for index, txout := range *sendList {
		isFee := false
		switch {
		case txout.PegoutInput != nil:
			return 0, false, 0, errors.Wrapf(err, "Pegin sendList exist pegout data error(n: %d)", index)
		case txout.IsFee:
			isFee = true
		case len(txout.Nonce) == types.CommitmentHexDataSize:
			if txout.IsDestroy || len(txout.LockingScript) > 0 || len(txout.Address) > 0 {
				blindOutputCount += 1
				if txout.IsDestroy && (len(txout.LockingScript) > 0 || len(txout.Address) > 0) {
					return 0, false, 0, errors.Wrapf(err, "Pegin sendList invalid destroy amount error(n: %d)", index)
				}
			} else {
				return 0, false, 0, errors.Wrapf(err, "Pegin sendList invalid nonce error(n: %d)", index)
			}
		case txout.IsDestroy:
			if len(txout.LockingScript) > 0 || len(txout.Address) > 0 {
				return 0, false, 0, errors.Wrapf(err, "Pegin sendList invalid destroy amount error(n: %d)", index)
			}
			unblindOutputCount += 1
		case len(txout.Address) > 0:
			addrInfo, err := caApi.Parse(txout.Address)
			if err != nil {
				return 0, false, 0, errors.Wrapf(err, "Pegin sendList address check error(n: %d)", index)
			} else if addrInfo.Network != *p.network {
				return 0, false, 0, errors.Wrapf(err, "Pegin sendList address network check error(n: %d)", index)
			} else if len(addrInfo.ConfidentialAddress) > 0 {
				blindOutputCount += 1
			} else {
				unblindOutputCount += 1
			}
		case len(txout.LockingScript) > 0:
			unblindOutputCount += 1
		default:
			isFee = true
		}

		if isFee {
			feeCount += 1
		} else {
			amount += txout.Amount
		}
	}

	if changeAddress == nil {
		if blindOutputCount == 1 {
			hasAppendDummyOutput = true
		}
	} else if len(changeAddress.ConfidentialAddress) == 0 {
		if blindOutputCount > 0 {
			return 0, false, 0, errors.Wrap(err, "Pegin sendList mixed output error (changeAddress is blinded)")
		}
		unblindOutputCount += 1
	} else {
		blindOutputCount += 1
		if blindOutputCount == 1 {
			hasAppendDummyOutput = true
		}
	}

	if feeCount > 1 {
		return 0, false, 0, errors.Wrapf(err, "Pegin sendList fee output check error(count: %d)", feeCount)
	} else if (blindOutputCount == 0) && (unblindOutputCount == 0) {
		return 0, false, 0, errors.Wrap(err, "Pegin sendList output empty error")
	} else if (blindOutputCount > 0) && (unblindOutputCount > 0) {
		return 0, false, 0, errors.Wrap(err, "Pegin sendList mixed output error (blind & unblind)")
	}
	return blindOutputCount, hasAppendDummyOutput, amount, nil
}

func (p *PeginService) validateUtxoList(utxoList []*types.ElementsUtxoData) error {
	if utxoList == nil {
		return nil
	}
	for _, utxo := range utxoList {
		switch {
		case len(utxo.OutPoint.Txid) != 64:
			return errors.Errorf("CFD Error: utxo OutPoint.Txid is invalid")
		case utxo.Amount == 0:
			return errors.Errorf("CFD Error: utxo Amount is invalid")
		case len(utxo.Asset) != 64:
			return errors.Errorf("CFD Error: utxo Amount is invalid")
		case (len(utxo.AssetBlindFactor) != 0) && (len(utxo.AssetBlindFactor) != 64):
			return errors.Errorf("CFD Error: utxo AssetBlindFactor is invalid")
		case (len(utxo.ValueBlindFactor) != 0) && (len(utxo.ValueBlindFactor) != 64):
			return errors.Errorf("CFD Error: utxo ValueBlindFactor is invalid")
		case len(utxo.Descriptor) == 0:
			return errors.Errorf("CFD Error: utxo Descriptor is invalid")
		case (len(utxo.AmountCommitment) != 0) && (len(utxo.AmountCommitment) != 66):
			return errors.Errorf("CFD Error: utxo AmountCommitment is invalid")
		case utxo.PeginData != nil:
			return errors.Errorf("CFD Error: Pegin utxo cannot use PeginData")
		case utxo.IsIssuance:
			return errors.Errorf("CFD Error: Pegin utxo cannot use IsIssuance")
		}
	}
	return nil
}

func (p *PeginService) validatePeginData(peginOutPoint *types.OutPoint, peginData *types.InputPeginData) error {
	switch {
	case peginOutPoint == nil:
		return errors.Errorf("CFD Error: peginOutPoint is nil")
	case peginData == nil:
		return errors.Errorf("CFD Error: peginData is nil")
	case len(peginOutPoint.Txid) != 64:
		return errors.Errorf("CFD Error: peginOutPoint.Txid is invalid")
	case len(peginData.TxOutProof) == 0:
		return errors.Errorf("CFD Error: peginData.TxOutProof is empty")
	case len(peginData.BitcoinTransaction) == 0:
		return errors.Errorf("CFD Error: peginData.BitcoinTransaction is empty")
	}

	txid := p.bitcoinTxApi.GetTxid(&types.Transaction{Hex: peginData.BitcoinTransaction})
	if len(txid) == 0 {
		return errors.Errorf("CFD Error: peginData.BitcoinTransaction is invalid")
	} else if txid != peginOutPoint.Txid {
		return errors.Errorf("CFD Error: peginOutPoint.Txid is unmatch")
	}

	claimScript, err := types.NewScriptFromHex(peginData.ClaimScript)
	if err != nil {
		return errors.Wrap(err, "Pegin invalid peginData.ClaimScript error")
	}
	items, err := claimScript.Parse()
	if err != nil {
		return errors.Wrap(err, "Pegin invalid peginData.ClaimScript error")
	} else if len(items) != 2 {
		return errors.Errorf("CFD Error: peginData.ClaimScript is invalid")
	} else if items[0] != "OP_0" { // segwit v0
		return errors.Errorf("CFD Error: peginData.ClaimScript is invalid segwit: %s", items[0])
	} else if (len(items[1]) != 40) && (len(items[1]) != 64) { // segwit v0
		return errors.Errorf("CFD Error: peginData.ClaimScript is invalid length")
	}

	if (p.bitcoinGenesisBlockHash == nil) && (len(peginData.BitcoinGenesisBlockHash) != 64) {
		return errors.Errorf("CFD Error: peginData.BitcoinGenesisBlockHash is invalid")
	} else if (p.bitcoinAssetId == nil) && (len(peginData.BitcoinAssetId) != 64) {
		return errors.Errorf("CFD Error: peginData.BitcoinAssetId is invalid")
	}
	return nil
}

func (p *PeginService) validateChangeAddress(changeAddress *string) (addr *types.ConfidentialAddress, err error) {
	caApi := address.ConfidentialAddressApiImpl{}
	if changeAddress != nil {
		addr, err = caApi.Parse(*changeAddress)
		if err != nil {
			return nil, errors.Wrap(err, "Pegin changeAddress error")
		} else if addr.Network != *p.network {
			return nil, errors.Wrap(err, "Pegin changeAddress network check error")
		}
		return addr, nil
	}
	return nil, nil
}

func (p *PeginService) validateUtxoData(utxo *types.ElementsUtxoData) error {
	switch {
	case len(utxo.OutPoint.Txid) != 64:
		return errors.Errorf("CFD Error: utxo OutPoint.Txid is invalid")
	case utxo.Amount == 0:
		return errors.Errorf("CFD Error: utxo Amount is invalid")
	case len(utxo.Asset) != 64:
		return errors.Errorf("CFD Error: utxo Amount is invalid")
	case (len(utxo.AssetBlindFactor) != 0) && (len(utxo.AssetBlindFactor) != 64):
		return errors.Errorf("CFD Error: utxo AssetBlindFactor is invalid")
	case (len(utxo.ValueBlindFactor) != 0) && (len(utxo.ValueBlindFactor) != 64):
		return errors.Errorf("CFD Error: utxo ValueBlindFactor is invalid")
	case len(utxo.Descriptor) == 0:
		return errors.Errorf("CFD Error: utxo Descriptor is invalid")
	case (len(utxo.AmountCommitment) != 0) && (len(utxo.AmountCommitment) != 66):
		return errors.Errorf("CFD Error: utxo AmountCommitment is invalid")
	case utxo.IsIssuance:
		return errors.Errorf("CFD Error: Pegin utxo cannot use IsIssuance")
	default:
		return nil
	}
}

func appendDummyOutput(txHex string, assetId string, network *types.NetworkType) (outputTxHex string, err error) {
	// generate random confidential key
	nonce, _, _, err := cfd.CfdGoCreateKeyPair(true, network.ToBitcoinType().ToCfdValue())
	if err != nil {
		return "", errors.Wrap(err, "create keyPair error")
	}
	outputTxHex, err = cfd.CfdGoAddConfidentialTxOut(txHex, assetId, 0, "", "", "6a", nonce)
	if err != nil {
		return "", errors.Wrap(err, "add txout error")
	}
	return outputTxHex, nil
}
