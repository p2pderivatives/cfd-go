package pegin

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/cryptogarageinc/cfd-go/apis/address"
	"github.com/cryptogarageinc/cfd-go/apis/descriptor"
	"github.com/cryptogarageinc/cfd-go/apis/key"
	"github.com/cryptogarageinc/cfd-go/apis/transaction"
	"github.com/cryptogarageinc/cfd-go/config"
	cfdErrors "github.com/cryptogarageinc/cfd-go/errors"
	"github.com/cryptogarageinc/cfd-go/types"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

// GetFuncName
func GetFuncName() string {
	pc, _, _, _ := runtime.Caller(1)
	funcName := runtime.FuncForPC(pc).Name()
	index := strings.LastIndex(funcName, ".")
	return funcName[index+1:]
}

func TestCreateClaimPeginTxByCfdConf(t *testing.T) {
	config.SetCfdConfig(config.CfdConfig{
		Network:                 types.ElementsRegtest,
		BitcoinGenesisBlockHash: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
		BitcoinAssetId:          "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
	})

	keyApi := (key.PrivkeyApi)(key.NewPrivkeyApi())
	xprvApi := (key.ExtPrivkeyApi)(key.NewExtPrivkeyApi())
	btcTxApi := (transaction.TransactionApi)(transaction.NewTransactionApi())
	txApi := (transaction.ConfidentialTxApi)(transaction.NewConfidentialTxApi())
	peginApiImpl := NewPeginService()
	assert.NoError(t, peginApiImpl.GetError())
	for _, errItem := range cfdErrors.GetErrors(peginApiImpl.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}
	peginApi := (Pegin)(peginApiImpl)

	// key
	// root: tprv8ZgxMBicQKsPeWHBt7a68nPnvgTnuDhUgDWC8wZCgA8GahrQ3f3uWpq7wE7Uc1dLBnCe1hhCZ886K6ND37memRDWqsA9HgSKDXtwh2Qxo6J
	accountExtPriv := types.ExtPrivkey{
		Key: "tprv8gio6qQZzaVsZkjJY62vfoohmCysvZ9HDPNej342qrMxaV87wH7DQahQMvjXzFyGn1HZwGKMCpiGswAMAqJkB1uPamKKYk7FNsQG4SLnWUA"}
	accountExtPubkey, err := xprvApi.GetExtPubkey(&accountExtPriv)
	assert.NoError(t, err)

	// fedpeg script
	fedpegScript := types.NewScriptFromHexIgnoreError(
		"522103aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf79210291b7d0b1b692f8f524516ed950872e5da10fb1b808b5a526dedc6fed1cf29807210386aa9372fbab374593466bc5451dc59954e90787f08060964d95c87ef34ca5bb53ae")

	// create pegin address
	path := "0/0"
	pubkey, _, err := peginApi.GetPubkeyFromAccountExtPubkey(accountExtPubkey, path)
	assert.NoError(t, err)

	peginAddr, claimScript, err := peginApi.CreatePeginAddress(types.P2shP2wshAddress, pubkey, fedpegScript)
	assert.NoError(t, err)
	assert.Equal(t, "2MuAHHAujmn7s1VekEvPeTSk3BrBZxyeT8v", peginAddr.Address)
	assert.Equal(t, "0014f3ea0aba73fdb23912ebd21f46e156cdd9e94280", claimScript.ToHex())

	// create bitcoin tx
	amount := int64(100000000)
	feeAmount := int64(500)
	peginAmount := amount - feeAmount
	utxoOutPoint := types.OutPoint{
		Txid: "ea9d5a9e974af1d167305aa6ee598706d63274e8a40f4f33af97db37a7adde4c",
		Vout: 0,
	}
	btcInputs := []types.InputTxIn{
		{
			OutPoint: utxoOutPoint,
			Sequence: types.SequenceLockTimeFinal,
		},
	}
	btcOutputs := []types.InputTxOut{
		{
			Amount:  peginAmount,
			Address: peginAddr.Address,
		},
	}
	btcTx, err := btcTxApi.Create(uint32(2), uint32(0), &btcInputs, &btcOutputs)
	assert.NoError(t, err)

	// add sign
	utxoPath := "0/1"
	utxoExtPriv, err := xprvApi.GetExtPrivkeyByPath(&accountExtPriv, utxoPath)
	assert.NoError(t, err)
	utxoPubkey, err := xprvApi.GetPubkey(utxoExtPriv)
	assert.NoError(t, err)
	utxoPrivkey, err := xprvApi.GetPrivkey(utxoExtPriv)
	assert.NoError(t, err)
	utxos := []types.UtxoData{
		{
			OutPoint:   utxoOutPoint,
			Amount:     amount,
			Descriptor: "wpkh(" + utxoPubkey.Hex + ")",
		},
	}
	err = btcTxApi.SignWithPrivkey(btcTx, &utxoOutPoint, utxoPrivkey, types.SigHashTypeAll, &utxos)
	assert.NoError(t, err)
	assert.Equal(t, "020000000001014cdeada737db97af334f0fa4e87432d6068759eea65a3067d1f14a979e5a9dea0000000000ffffffff010cdff5050000000017a9141500eb4946dee5979e708c8b2c6d090773f3b8d1870247304402204d9faa0b3b9c76b3ee875ae9205b50e05c2d0a8dff8e26d269f68eb72531af1402201f71d1e2bec6b7ea90d45dec158d3f85942e0fc09cfad29d917d3cbc6acd981d012103b64236b2c8f34a18e3a584fe0877fb944e2abb4544cb14bee5458bcc2480cefc00000000", btcTx.Hex)

	// btc transaction
	txid := btcTxApi.GetTxid(btcTx)
	assert.Equal(t, "5e5fd4e860d999b30b268ed583dfcfe805c395f8290d8307f6617fdc3f029de3", txid)
	peginIndex := uint32(0)
	// by block
	txoutProof := "00000020fe3b574c1ce6d5cb68fc518e86f7976e599fafc0a2e5754aace7ca16d97a7c78ef9325b8d4f0a4921e060fc5e71435f46a18fa339688142cd4b028c8488c9f8dd1495b5dffff7f200200000002000000024a180a6822abffc3b1080c49016899c6dac25083936df14af12f58db11958ef27926299350fdc2f4d0da1d4f0fbbd3789d29f9dc016358ae42463c0cebf393f30105"

	// create pegin tx
	peginOutPoint := types.OutPoint{
		Txid: txid,
		Vout: peginIndex,
	}
	peginInputData := types.InputPeginData{
		BitcoinTransaction: btcTx.Hex,
		ClaimScript:        claimScript.ToHex(),
		TxOutProof:         txoutProof,
	}
	/*
		dummyUtxos := []*types.ElementsUtxoData{
			{
				OutPoint: types.OutPoint{
					Txid: "0e5fd4e860d999b30b268ed583dfcfe805c395f8290d8307f6617fdc3f029de3",
					Vout: 0,
				},
				Asset:      "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
				Amount:     10000,
				Descriptor: "wpkh(" + utxoPubkey.Hex + ")",
			},
		}
	*/
	outputAddr := "el1qqtl9a3n6878ex25u0wv8u5qlzpfkycc0cftk65t52pkauk55jqka0fajk8d80lafn4t9kqxe77cu9ez2dyr6sq54lwy009uex"
	sendList := []types.InputConfidentialTxOut{}
	option := types.NewPeginTxOption()
	option.KnapsackMinChange = 0
	option.EffectiveFeeRate = 0.1
	option.MinimumBits = 36
	option.KnapsackMinChange = 0
	tx, unblindTx, err := peginApi.CreatePeginTransaction(&peginOutPoint, &peginInputData, nil, sendList, &outputAddr, &option)
	assert.NoError(t, err)

	// output check
	_, inList, outList, err := txApi.GetAll(tx, false)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(inList))
	assert.Equal(t, 3, len(outList))
	assert.Less(t, 13370, len(tx.Hex))
	assert.Greater(t, 13380, len(tx.Hex))
	_, _, unblindTxoutList, err := txApi.GetAll(unblindTx, false)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), unblindTxoutList[0].Amount)        // dummy
	assert.Equal(t, int64(194), unblindTxoutList[1].Amount)      // fee
	assert.Equal(t, int64(99999306), unblindTxoutList[2].Amount) // amount

	// create utxo data
	peginUtxoData, err := peginApi.GetPeginUtxoData(tx, &peginOutPoint, pubkey)
	assert.NoError(t, err)
	assert.Equal(t, "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225", peginUtxoData.Asset)

	// create sighash
	peginUtxos := []*types.ElementsUtxoData{
		peginUtxoData,
	}
	desc := &types.Descriptor{OutputDescriptor: peginUtxos[0].Descriptor}
	sighash, err := txApi.GetSighash(tx, &peginOutPoint, types.SigHashTypeAll, peginUtxos)
	assert.NoError(t, err)

	// crate signature (sign)
	peginExtPriv, err := xprvApi.GetExtPrivkeyByPath(&accountExtPriv, path)
	assert.NoError(t, err)
	privkey, err := xprvApi.GetPrivkey(peginExtPriv)
	assert.NoError(t, err)
	signature, err := keyApi.CreateEcSignature(privkey, sighash, &types.SigHashTypeAll)
	assert.NoError(t, err)

	// verify signature
	assert.Equal(t, peginUtxos[0].Descriptor, peginUtxoData.Descriptor)
	isVerify, err := peginApi.VerifyPubkeySignature(tx, peginUtxoData, signature)
	assert.NoError(t, err)
	assert.True(t, isVerify)

	// add sign to tx
	err = txApi.AddPubkeySignByDescriptor(tx, &peginOutPoint, desc, signature.ToHex())
	assert.NoError(t, err)

	txData, _, _, err := txApi.GetAll(tx, false)
	assert.NoError(t, err)
	if txData.Size != 6793 && txData.Size != 6794 {
		assert.Equal(t, uint32(6793), txData.Size)
	}
	assert.Equal(t, uint32(1938), txData.Vsize)

	// verify (after sign)
	isVerify, reason, err := txApi.VerifySign(tx, &peginOutPoint, peginUtxos)
	assert.NoError(t, err)
	assert.True(t, isVerify)
	assert.Equal(t, "", reason)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCreateClaimPeginTxOverrideApi(t *testing.T) {
	conf := config.CfdConfig{
		Network:                 types.ElementsRegtest,
		BitcoinGenesisBlockHash: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
		BitcoinAssetId:          "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
	}
	config.SetCfdConfig(conf)
	// opts := conf.GetOptions()
	networkOpt := config.NetworkOption(conf.Network)
	blockHashOpt := config.BitcoinGenesisBlockHashOption(conf.BitcoinGenesisBlockHash)
	assetIdOpt := config.BitcoinAssetIdOption(conf.BitcoinAssetId)

	btcNetworkOpt := config.NetworkOption(types.Regtest)
	btcDescApi := descriptor.NewDescriptorApi(btcNetworkOpt)
	assert.NoError(t, btcDescApi.GetError())
	for _, errItem := range cfdErrors.GetErrors(btcDescApi.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}
	btcAddrApi := address.NewAddressApi(btcNetworkOpt)
	assert.NoError(t, btcAddrApi.GetError())
	for _, errItem := range cfdErrors.GetErrors(btcAddrApi.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}
	elmAddrApi := address.NewAddressApi()
	assert.NoError(t, elmAddrApi.GetError())
	for _, errItem := range cfdErrors.GetErrors(elmAddrApi.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}
	elmDescApi := (descriptor.DescriptorApi)(descriptor.NewDescriptorApi())
	pubkeyApi := (key.PubkeyApi)(key.NewPubkeyApi())
	keyApi := (key.PrivkeyApi)(key.NewPrivkeyApi())
	xprvApi := (key.ExtPrivkeyApi)(key.NewExtPrivkeyApi())
	btcTxApi := transaction.NewTransactionApi(networkOpt).WithBitcoinDescriptorApi(btcDescApi)
	assert.NoError(t, btcTxApi.GetError())
	for _, errItem := range cfdErrors.GetErrors(btcTxApi.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}
	txApi := transaction.NewConfidentialTxApi(networkOpt).
		WithElementsDescriptorApi(elmDescApi).
		WithBitcoinAddressApi(btcAddrApi).WithBitcoinTxApi(btcTxApi)
	assert.NoError(t, txApi.GetError())
	for _, errItem := range cfdErrors.GetErrors(txApi.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}
	peginApi := NewPeginService(networkOpt, blockHashOpt, assetIdOpt).
		WithElementsAddressApi(elmAddrApi).WithBitcoinTxApi(btcTxApi).
		WithConfidentialTxApi(txApi).
		WithElementsDescriptorApi(elmDescApi).WithPubkeyApi(pubkeyApi)
	assert.NoError(t, peginApi.GetError())
	for _, errItem := range cfdErrors.GetErrors(peginApi.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}

	// key
	// root: tprv8ZgxMBicQKsPeWHBt7a68nPnvgTnuDhUgDWC8wZCgA8GahrQ3f3uWpq7wE7Uc1dLBnCe1hhCZ886K6ND37memRDWqsA9HgSKDXtwh2Qxo6J
	accountExtPriv := types.ExtPrivkey{
		Key: "tprv8gio6qQZzaVsZkjJY62vfoohmCysvZ9HDPNej342qrMxaV87wH7DQahQMvjXzFyGn1HZwGKMCpiGswAMAqJkB1uPamKKYk7FNsQG4SLnWUA"}
	accountExtPubkey, err := xprvApi.GetExtPubkey(&accountExtPriv)
	assert.NoError(t, err)

	// fedpeg script
	fedpegScript := types.NewScriptFromHexIgnoreError(
		"522103aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf79210291b7d0b1b692f8f524516ed950872e5da10fb1b808b5a526dedc6fed1cf29807210386aa9372fbab374593466bc5451dc59954e90787f08060964d95c87ef34ca5bb53ae")

	// create pegin address
	path := "0/0"
	pubkey, _, err := peginApi.GetPubkeyFromAccountExtPubkey(accountExtPubkey, path)
	assert.NoError(t, err)

	peginAddr, claimScript, err := peginApi.CreatePeginAddress(types.P2shP2wshAddress, pubkey, fedpegScript)
	assert.NoError(t, err)
	assert.Equal(t, "2MuAHHAujmn7s1VekEvPeTSk3BrBZxyeT8v", peginAddr.Address)
	assert.Equal(t, "0014f3ea0aba73fdb23912ebd21f46e156cdd9e94280", claimScript.ToHex())

	// bitcoin tx
	btcTx := &types.Transaction{
		Hex: "020000000001014cdeada737db97af334f0fa4e87432d6068759eea65a3067d1f14a979e5a9dea0000000000ffffffff010cdff5050000000017a9141500eb4946dee5979e708c8b2c6d090773f3b8d1870247304402204d9faa0b3b9c76b3ee875ae9205b50e05c2d0a8dff8e26d269f68eb72531af1402201f71d1e2bec6b7ea90d45dec158d3f85942e0fc09cfad29d917d3cbc6acd981d012103b64236b2c8f34a18e3a584fe0877fb944e2abb4544cb14bee5458bcc2480cefc00000000",
	}

	// btc transaction
	txid := btcTxApi.GetTxid(btcTx)
	assert.Equal(t, "5e5fd4e860d999b30b268ed583dfcfe805c395f8290d8307f6617fdc3f029de3", txid)
	peginIndex := uint32(0)
	// by block
	txoutProof := "00000020fe3b574c1ce6d5cb68fc518e86f7976e599fafc0a2e5754aace7ca16d97a7c78ef9325b8d4f0a4921e060fc5e71435f46a18fa339688142cd4b028c8488c9f8dd1495b5dffff7f200200000002000000024a180a6822abffc3b1080c49016899c6dac25083936df14af12f58db11958ef27926299350fdc2f4d0da1d4f0fbbd3789d29f9dc016358ae42463c0cebf393f30105"

	// create pegin tx
	peginOutPoint := types.OutPoint{
		Txid: txid,
		Vout: peginIndex,
	}
	peginInputData := types.InputPeginData{
		BitcoinTransaction: btcTx.Hex,
		ClaimScript:        claimScript.ToHex(),
		TxOutProof:         txoutProof,
	}
	outputAddr := "el1qqtl9a3n6878ex25u0wv8u5qlzpfkycc0cftk65t52pkauk55jqka0fajk8d80lafn4t9kqxe77cu9ez2dyr6sq54lwy009uex"
	sendList := []types.InputConfidentialTxOut{}
	option := types.NewPeginTxOption()
	option.KnapsackMinChange = 0
	option.EffectiveFeeRate = 0.1
	option.MinimumBits = 36
	option.KnapsackMinChange = 0
	tx, unblindTx, err := peginApi.CreatePeginTransaction(&peginOutPoint, &peginInputData, nil, sendList, &outputAddr, &option)
	assert.NoError(t, err)

	// output check
	_, inList, outList, err := txApi.GetAll(tx, false)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(inList))
	assert.Equal(t, 3, len(outList))
	assert.Less(t, 13370, len(tx.Hex))
	assert.Greater(t, 13380, len(tx.Hex))
	_, _, unblindTxoutList, err := txApi.GetAll(unblindTx, false)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), unblindTxoutList[0].Amount)        // dummy
	assert.Equal(t, int64(194), unblindTxoutList[1].Amount)      // fee
	assert.Equal(t, int64(99999306), unblindTxoutList[2].Amount) // amount

	// create utxo data
	peginUtxoData, err := peginApi.GetPeginUtxoData(tx, &peginOutPoint, pubkey)
	assert.NoError(t, err)
	assert.Equal(t, "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225", peginUtxoData.Asset)

	// create sighash
	peginUtxos := []*types.ElementsUtxoData{
		peginUtxoData,
	}
	desc := &types.Descriptor{OutputDescriptor: peginUtxos[0].Descriptor}
	sighash, err := txApi.GetSighash(tx, &peginOutPoint, types.SigHashTypeAll, peginUtxos)
	assert.NoError(t, err)

	// crate signature (sign)
	peginExtPriv, err := xprvApi.GetExtPrivkeyByPath(&accountExtPriv, path)
	assert.NoError(t, err)
	privkey, err := xprvApi.GetPrivkey(peginExtPriv)
	assert.NoError(t, err)
	signature, err := keyApi.CreateEcSignature(privkey, sighash, &types.SigHashTypeAll)
	assert.NoError(t, err)

	// verify signature
	assert.Equal(t, peginUtxos[0].Descriptor, peginUtxoData.Descriptor)
	isVerify, err := peginApi.VerifyPubkeySignature(tx, peginUtxoData, signature)
	assert.NoError(t, err)
	assert.True(t, isVerify)

	// add sign to tx
	err = txApi.AddPubkeySignByDescriptor(tx, &peginOutPoint, desc, signature.ToHex())
	assert.NoError(t, err)

	txData, _, _, err := txApi.GetAll(tx, false)
	assert.NoError(t, err)
	if txData.Size != 6793 && txData.Size != 6794 {
		assert.Equal(t, uint32(6793), txData.Size)
	}
	assert.Equal(t, uint32(1938), txData.Vsize)

	// verify (after sign)
	isVerify, reason, err := txApi.VerifySign(tx, &peginOutPoint, peginUtxos)
	assert.NoError(t, err)
	assert.True(t, isVerify)
	assert.Equal(t, "", reason)

	fmt.Printf("%s test done.\n", GetFuncName())
}

const DescriptorParseMockErrorMessage = "Mock Descriptor.Parse called"

type DescriptorApiParserMock struct {
	descriptor.DescriptorApi
}

func NewDescriptorApiParserMock(network types.NetworkType) *DescriptorApiParserMock {
	descObj := descriptor.NewDescriptorApi(config.NetworkOption(network))
	obj := DescriptorApiParserMock{descObj}
	return &obj
}

func (d *DescriptorApiParserMock) Parse(descriptor *types.Descriptor) (data *types.DescriptorRootData, descriptorDataList []types.DescriptorData, err error) {
	return nil, nil, errors.New(DescriptorParseMockErrorMessage)
}

func TestCreateClaimPeginTxOverrideApiByMock(t *testing.T) {
	config.SetCfdConfig(config.CfdConfig{
		Network:                 types.ElementsRegtest,
		BitcoinGenesisBlockHash: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
		BitcoinAssetId:          "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
	})

	descMock := NewDescriptorApiParserMock(types.ElementsRegtest)
	keyApi := (key.PrivkeyApi)(key.NewPrivkeyApi())
	xprvApi := (key.ExtPrivkeyApi)(key.NewExtPrivkeyApi())
	peginApi := (Pegin)(NewPeginService().WithElementsDescriptorApi(descMock))
	btcTxApi := (transaction.TransactionApi)(transaction.NewTransactionApi())
	txApi := (transaction.ConfidentialTxApi)(transaction.NewConfidentialTxApi())

	// key
	// root: tprv8ZgxMBicQKsPeWHBt7a68nPnvgTnuDhUgDWC8wZCgA8GahrQ3f3uWpq7wE7Uc1dLBnCe1hhCZ886K6ND37memRDWqsA9HgSKDXtwh2Qxo6J
	accountExtPriv := types.ExtPrivkey{
		Key: "tprv8gio6qQZzaVsZkjJY62vfoohmCysvZ9HDPNej342qrMxaV87wH7DQahQMvjXzFyGn1HZwGKMCpiGswAMAqJkB1uPamKKYk7FNsQG4SLnWUA"}
	accountExtPubkey, err := xprvApi.GetExtPubkey(&accountExtPriv)
	assert.NoError(t, err)

	// fedpeg script
	fedpegScript := types.NewScriptFromHexIgnoreError(
		"522103aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf79210291b7d0b1b692f8f524516ed950872e5da10fb1b808b5a526dedc6fed1cf29807210386aa9372fbab374593466bc5451dc59954e90787f08060964d95c87ef34ca5bb53ae")

	// create pegin address
	path := "0/0"
	pubkey, _, err := peginApi.GetPubkeyFromAccountExtPubkey(accountExtPubkey, path)
	assert.NoError(t, err)

	peginAddr, claimScript, err := peginApi.CreatePeginAddress(types.P2shP2wshAddress, pubkey, fedpegScript)
	assert.NoError(t, err)
	assert.Equal(t, "2MuAHHAujmn7s1VekEvPeTSk3BrBZxyeT8v", peginAddr.Address)
	assert.Equal(t, "0014f3ea0aba73fdb23912ebd21f46e156cdd9e94280", claimScript.ToHex())

	// bitcoin tx
	btcTx := &types.Transaction{
		Hex: "020000000001014cdeada737db97af334f0fa4e87432d6068759eea65a3067d1f14a979e5a9dea0000000000ffffffff010cdff5050000000017a9141500eb4946dee5979e708c8b2c6d090773f3b8d1870247304402204d9faa0b3b9c76b3ee875ae9205b50e05c2d0a8dff8e26d269f68eb72531af1402201f71d1e2bec6b7ea90d45dec158d3f85942e0fc09cfad29d917d3cbc6acd981d012103b64236b2c8f34a18e3a584fe0877fb944e2abb4544cb14bee5458bcc2480cefc00000000",
	}

	// btc transaction
	txid := btcTxApi.GetTxid(btcTx)
	assert.Equal(t, "5e5fd4e860d999b30b268ed583dfcfe805c395f8290d8307f6617fdc3f029de3", txid)
	peginIndex := uint32(0)
	// by block
	txoutProof := "00000020fe3b574c1ce6d5cb68fc518e86f7976e599fafc0a2e5754aace7ca16d97a7c78ef9325b8d4f0a4921e060fc5e71435f46a18fa339688142cd4b028c8488c9f8dd1495b5dffff7f200200000002000000024a180a6822abffc3b1080c49016899c6dac25083936df14af12f58db11958ef27926299350fdc2f4d0da1d4f0fbbd3789d29f9dc016358ae42463c0cebf393f30105"

	// create pegin tx
	peginOutPoint := types.OutPoint{
		Txid: txid,
		Vout: peginIndex,
	}
	peginInputData := types.InputPeginData{
		BitcoinTransaction: btcTx.Hex,
		ClaimScript:        claimScript.ToHex(),
		TxOutProof:         txoutProof,
	}
	outputAddr := "el1qqtl9a3n6878ex25u0wv8u5qlzpfkycc0cftk65t52pkauk55jqka0fajk8d80lafn4t9kqxe77cu9ez2dyr6sq54lwy009uex"
	sendList := []types.InputConfidentialTxOut{}
	option := types.NewPeginTxOption()
	option.KnapsackMinChange = 0
	option.EffectiveFeeRate = 0.1
	option.MinimumBits = 36
	option.KnapsackMinChange = 0
	tx, unblindTx, err := peginApi.CreatePeginTransaction(&peginOutPoint, &peginInputData, nil, sendList, &outputAddr, &option)
	assert.NoError(t, err)

	// output check
	_, inList, outList, err := txApi.GetAll(tx, false)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(inList))
	assert.Equal(t, 3, len(outList))
	assert.Less(t, 13370, len(tx.Hex))
	assert.Greater(t, 13380, len(tx.Hex))
	_, _, unblindTxoutList, err := txApi.GetAll(unblindTx, false)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), unblindTxoutList[0].Amount)        // dummy
	assert.Equal(t, int64(194), unblindTxoutList[1].Amount)      // fee
	assert.Equal(t, int64(99999306), unblindTxoutList[2].Amount) // amount

	// create utxo data
	peginUtxoData, err := peginApi.GetPeginUtxoData(tx, &peginOutPoint, pubkey)
	assert.NoError(t, err)
	assert.Equal(t, "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225", peginUtxoData.Asset)

	// create sighash
	peginUtxos := []*types.ElementsUtxoData{
		peginUtxoData,
	}
	// desc := &types.Descriptor{OutputDescriptor: peginUtxos[0].Descriptor}
	sighash, err := txApi.GetSighash(tx, &peginOutPoint, types.SigHashTypeAll, peginUtxos)
	assert.NoError(t, err)

	// crate signature (sign)
	peginExtPriv, err := xprvApi.GetExtPrivkeyByPath(&accountExtPriv, path)
	assert.NoError(t, err)
	privkey, err := xprvApi.GetPrivkey(peginExtPriv)
	assert.NoError(t, err)
	signature, err := keyApi.CreateEcSignature(privkey, sighash, &types.SigHashTypeAll)
	assert.NoError(t, err)

	// verify signature
	assert.Equal(t, peginUtxos[0].Descriptor, peginUtxoData.Descriptor)
	isVerify, err := peginApi.VerifyPubkeySignature(tx, peginUtxoData, signature)
	assert.Error(t, err)
	// assert.NoError(t, err)
	assert.Contains(t, err.Error(), DescriptorParseMockErrorMessage)
	assert.False(t, isVerify)

	fmt.Printf("%s test done.\n", GetFuncName())
}
