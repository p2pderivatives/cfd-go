package transaction

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	cfdgo "github.com/cryptogarageinc/cfd-go"
	"github.com/cryptogarageinc/cfd-go/apis/address"
	"github.com/cryptogarageinc/cfd-go/apis/descriptor"
	"github.com/cryptogarageinc/cfd-go/apis/key"
	"github.com/cryptogarageinc/cfd-go/config"
	cfdErrors "github.com/cryptogarageinc/cfd-go/errors"
	"github.com/cryptogarageinc/cfd-go/types"
	"github.com/stretchr/testify/assert"
)

// GetFuncName
func GetFuncName() string {
	pc, _, _, _ := runtime.Caller(1)
	funcName := runtime.FuncForPC(pc).Name()
	index := strings.LastIndex(funcName, ".")
	return funcName[index+1:]
}

func TestCreateClaimPeginTx(t *testing.T) {
	network := types.ElementsRegtest
	genesisBlockHash := "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
	asset := "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225"
	conf := config.CfdConfig{
		Network:                 network,
		BitcoinGenesisBlockHash: genesisBlockHash,
		BitcoinAssetId:          asset,
	}
	opts := conf.GetOptions()

	accountExtPriv := types.ExtPrivkey{
		Key: "tprv8gio6qQZzaVsZkjJY62vfoohmCysvZ9HDPNej342qrMxaV87wH7DQahQMvjXzFyGn1HZwGKMCpiGswAMAqJkB1uPamKKYk7FNsQG4SLnWUA"}
	xprvApi := (key.ExtPrivkeyApi)(key.NewExtPrivkeyApi(opts...))
	addrApi := address.NewAddressApi(opts...)
	caApi := address.NewConfidentialAddressApi()
	accountXpriv, err := xprvApi.GetExtPrivkeyByPath(&accountExtPriv, "0/0")
	assert.NoError(t, err)
	blindXpriv, err := xprvApi.GetExtPrivkeyByPath(&accountExtPriv, "0/1")
	assert.NoError(t, err)
	accountPubkey, err := xprvApi.GetPubkey(accountXpriv)
	assert.NoError(t, err)
	blindingKey, err := xprvApi.GetPrivkey(blindXpriv)
	assert.NoError(t, err)
	confidentialKey, err := xprvApi.GetPubkey(blindXpriv)
	assert.NoError(t, err)
	addr, err := addrApi.CreateByPubkey(accountPubkey, types.P2wpkhAddress)
	assert.NoError(t, err)
	ca, err := caApi.Create(addr.Address, confidentialKey)
	assert.NoError(t, err)

	// fedpeg script
	fedpegScript := "522103aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf79210291b7d0b1b692f8f524516ed950872e5da10fb1b808b5a526dedc6fed1cf29807210386aa9372fbab374593466bc5451dc59954e90787f08060964d95c87ef34ca5bb53ae"
	keyUtil := key.PrivkeyApiImpl{}
	privkey, err := keyUtil.GetPrivkeyFromWif("cUfipPioYnHU61pfYTH9uuNoswRXx8rtzXhJZrsPeVV1LRFdTxvp")
	assert.NoError(t, err)
	pubkey, err := keyUtil.GetPubkey(privkey)
	assert.NoError(t, err)

	// create pegin address
	addrUtil := address.NewAddressApi(opts...)
	assert.NoError(t, addrUtil.GetError())
	for _, errItem := range cfdErrors.GetErrors(addrUtil.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}
	peginAddr, claimScript, err := addrUtil.GetPeginAddressByPubkey(types.P2shP2wshAddress, fedpegScript, pubkey.Hex)
	assert.NoError(t, err)
	assert.Equal(t, "2MvmzAFKZ5xh44vyb7qY7NB2AoDuS55rVFW", peginAddr.Address)
	assert.Equal(t, "0014e794713e386d83f32baa0e9d03e47c0839dc57a8", claimScript.ToHex())

	// create bitcoin tx
	amount := int64(100000000)
	feeAmount := int64(500)
	peginAmount := amount - feeAmount
	btcTxUtil := NewTransactionApi(opts...)
	assert.NoError(t, btcTxUtil.GetError())
	for _, errItem := range cfdErrors.GetErrors(btcTxUtil.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}
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
	btcTx, err := btcTxUtil.Create(uint32(2), uint32(0), &btcInputs, &btcOutputs)
	assert.NoError(t, err)
	// add sign
	utxos := []types.UtxoData{
		{
			OutPoint:   utxoOutPoint,
			Amount:     amount,
			Descriptor: "wpkh(02fd54c734e48c544c3c3ad1aab0607f896eb95e23e7058b174a580826a7940ad8)",
		},
	}
	utxoPrivkey, err := keyUtil.GetPrivkeyFromWif("cNYKHjNc33ZyNMcDck59yWm1CYohgPhr2DYyCtmWNkL6sqb5L1rH")
	assert.NoError(t, err)
	err = btcTxUtil.SignWithPrivkey(btcTx, &utxoOutPoint, utxoPrivkey, types.SigHashTypeAll, &utxos)
	assert.NoError(t, err)
	assert.Equal(t, "020000000001014cdeada737db97af334f0fa4e87432d6068759eea65a3067d1f14a979e5a9dea0000000000ffffffff010cdff5050000000017a91426b9ba9cf5d822b70cf490ad0394566f9db20c63870247304402200b3ca71e82551a333fe5c8ce9a8f8454eb8f08aa194180e5a87c79ccf2e46212022065c1f2a363ebcb155a80e234258394140d08f6ab807581953bb21a58f2d229a6012102fd54c734e48c544c3c3ad1aab0607f896eb95e23e7058b174a580826a7940ad800000000", btcTx.Hex)

	assert.Equal(t, "12708508f0baf8691a3d7e22fd19afbf9bd8bf0d358e3310838bcc7916539c7b", btcTxUtil.GetTxid(btcTx))

	peginIndex := uint32(0)
	txoutProof := "00000020fe3b574c1ce6d5cb68fc518e86f7976e599fafc0a2e5754aace7ca16d97a7c78ef9325b8d4f0a4921e060fc5e71435f46a18fa339688142cd4b028c8488c9f8dd1495b5dffff7f200200000002000000024a180a6822abffc3b1080c49016899c6dac25083936df14af12f58db11958ef27926299350fdc2f4d0da1d4f0fbbd3789d29f9dc016358ae42463c0cebf393f30105"

	// create pegin tx
	txUtil := NewConfidentialTxApi(opts...)
	assert.NoError(t, txUtil.GetError())
	for _, errItem := range cfdErrors.GetErrors(txUtil.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}
	peginOutPoint := types.OutPoint{
		Txid: btcTxUtil.GetTxid(btcTx),
		Vout: peginIndex,
	}
	inputs := []types.InputConfidentialTxIn{
		{
			OutPoint: peginOutPoint,
			PeginInput: &types.InputPeginData{
				BitcoinTransaction:      btcTx.Hex,
				BitcoinGenesisBlockHash: genesisBlockHash,
				BitcoinAssetId:          asset,
				ClaimScript:             claimScript.ToHex(),
				TxOutProof:              txoutProof,
			},
		},
	}
	outputs := []types.InputConfidentialTxOut{
		{
			Amount: 99998500,
			//Address: "el1qqtl9a3n6878ex25u0wv8u5qlzpfkycc0cftk65t52pkauk55jqka0fajk8d80lafn4t9kqxe77cu9ez2dyr6sq54lwy009uex",
			Address: ca.ConfidentialAddress,
			Asset:   asset,
		},
		{
			Amount: 1000,
			Asset:  asset,
			IsFee:  true,
		},
	}
	tx, err := txUtil.Create(uint32(2), uint32(0), &inputs, &outputs, nil)
	assert.NoError(t, err)
	assert.Equal(t, "0200000001017b9c531679cc8b8310338e350dbfd89bbfaf19fd227e3d1a69f8baf0088570120000004000ffffffff020125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5db2403b64236b2c8f34a18e3a584fe0877fb944e2abb4544cb14bee5458bcc2480cefc160014f3ea0aba73fdb23912ebd21f46e156cdd9e942800125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000000003e800000000000000000006080cdff505000000002025b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a2006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f160014e794713e386d83f32baa0e9d03e47c0839dc57a8c0020000000001014cdeada737db97af334f0fa4e87432d6068759eea65a3067d1f14a979e5a9dea0000000000ffffffff010cdff5050000000017a91426b9ba9cf5d822b70cf490ad0394566f9db20c63870247304402200b3ca71e82551a333fe5c8ce9a8f8454eb8f08aa194180e5a87c79ccf2e46212022065c1f2a363ebcb155a80e234258394140d08f6ab807581953bb21a58f2d229a6012102fd54c734e48c544c3c3ad1aab0607f896eb95e23e7058b174a580826a7940ad8000000009700000020fe3b574c1ce6d5cb68fc518e86f7976e599fafc0a2e5754aace7ca16d97a7c78ef9325b8d4f0a4921e060fc5e71435f46a18fa339688142cd4b028c8488c9f8dd1495b5dffff7f200200000002000000024a180a6822abffc3b1080c49016899c6dac25083936df14af12f58db11958ef27926299350fdc2f4d0da1d4f0fbbd3789d29f9dc016358ae42463c0cebf393f3010500000000", tx.Hex)

	// blind
	blindTxInList := []types.BlindInputData{
		{
			OutPoint: peginOutPoint,
			Asset:    asset,
			Amount:   peginAmount,
		},
	}
	option := types.NewBlindTxOption()
	option.AppendDummyOutput = true
	err = txUtil.Blind(tx, blindTxInList, nil, &option)
	assert.NoError(t, err)
	_, inList, outList, err := txUtil.GetAllWithAddress(tx, true)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(inList))
	assert.Equal(t, 3, len(outList))
	assert.Equal(t, addr.Address, outList[0].Address)

	// sign
	peginUtxos := []*types.ElementsUtxoData{
		{
			OutPoint: types.OutPoint{
				Txid: peginOutPoint.Txid,
				Vout: peginOutPoint.Vout,
			},
			Amount:     peginAmount,
			Descriptor: "wpkh(" + pubkey.Hex + ")",
		},
	}
	sighash, err := txUtil.GetSighash(tx, &peginOutPoint, types.SigHashTypeAll, peginUtxos)
	assert.NoError(t, err)
	desc := types.Descriptor{
		OutputDescriptor: peginUtxos[0].Descriptor,
	}
	privkeyUtil := key.NewPrivkeyApi()
	signature, err := privkeyUtil.CreateEcSignature(privkey, sighash, &types.SigHashTypeAll)
	assert.NoError(t, err)

	// add sign
	err = txUtil.AddPubkeySignByDescriptor(tx, &peginOutPoint, &desc, signature.ToHex())
	assert.NoError(t, err)

	// verify
	isVerify, reason, err := txUtil.VerifySign(tx, &peginOutPoint, peginUtxos)
	assert.NoError(t, err)
	assert.True(t, isVerify)
	assert.Equal(t, "", reason)

	// unblind
	unblindData, err := txUtil.UnblindTxOut(tx, 0, blindingKey)
	assert.NoError(t, err)
	assert.Equal(t, outputs[0].Amount, unblindData.Amount)
	assert.Equal(t, outputs[0].Asset, unblindData.Asset)

	unblindedData, err := txUtil.UnblindByTxOut(&outList[0], blindingKey)
	assert.NoError(t, err)
	assert.Equal(t, outputs[0].Amount, unblindedData.Amount)
	assert.Equal(t, outputs[0].Asset, unblindedData.Asset)
	assert.Equal(t, unblindData.AssetBlindFactor, unblindedData.AssetBlindFactor)
	assert.Equal(t, unblindData.ValueBlindFactor, unblindedData.ValueBlindFactor)

	amountCommitment, assetCommitment, err := txUtil.GetCommitment(unblindData.Amount, unblindData.ValueBlindFactor, unblindData.AssetBlindFactor, unblindData.Asset)
	assert.NoError(t, err)
	assert.Equal(t, outList[0].CommitmentValue, amountCommitment)
	assert.Equal(t, outList[0].Asset, assetCommitment)

	isVerify, err = txUtil.VerifyEcSignatureByUtxo(tx, &peginOutPoint, peginUtxos[0], &types.SignParameter{
		Data:          *types.NewScriptFromHexIgnoreError(signature.ToHex()),
		RelatedPubkey: pubkey,
	})
	assert.NoError(t, err)
	assert.True(t, isVerify)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCreatePegoutTx(t *testing.T) {
	network := types.LiquidV1
	genesisBlockHash := "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
	asset := "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225"

	// mainchain address descriptor
	mainchainXpubkey := "xpub6A53gzNdDBQYCtFFpZT7kUpoBGpzWigaukrdF9xoUZt7cYMD2qCAHVLsstNoQEDMFJWdX78KvT6yxpC76aGCN5mENVdWtFGcWZoKdtLq5jW"
	mainchainPubkey, err := cfdgo.CfdGoGetPubkeyFromExtkey(mainchainXpubkey, int(cfdgo.KCfdNetworkMainnet))
	assert.NoError(t, err)
	negateMainchainPubkey, err := cfdgo.CfdGoNegatePubkey(mainchainPubkey)
	assert.NoError(t, err)
	mainchainOutputDescriptor := "pkh(" + mainchainXpubkey + "/0/*)"
	bip32Counter := uint32(0)

	onlinePrivkey := "L52AgshDAE14NHJuovwAw8hyrTNK4YQjuiPC9EES4sfM7oBPzU4o"
	onlinePubkey, err := cfdgo.CfdGoGetPubkeyFromPrivkey("", onlinePrivkey, true)
	assert.NoError(t, err)
	// whitelist
	pakEntry := negateMainchainPubkey + onlinePubkey
	whitelist := pakEntry

	// pegout address
	networkOpt := config.NetworkOption(network)
	addrUtil := address.NewAddressApi(networkOpt)
	assert.NoError(t, addrUtil.GetError())
	for _, errItem := range cfdErrors.GetErrors(addrUtil.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}
	pegoutAddr, baseDescriptor, err := addrUtil.GetPegoutAddress(types.P2pkhAddress, mainchainOutputDescriptor, bip32Counter)
	assert.NoError(t, err)
	assert.Equal(t, "1NrcpiZmCxjC7KVKAYT22SzVhhcXtp5o4v", pegoutAddr.Address)
	assert.Equal(t, "pkh("+mainchainXpubkey+")", *baseDescriptor)

	// create pegout tx
	txUtil := NewConfidentialTxApi(networkOpt)
	assert.NoError(t, txUtil.GetError())
	for _, errItem := range cfdErrors.GetErrors(txUtil.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}
	pegoutAddrList := []string{}
	inputs := []types.InputConfidentialTxIn{
		{
			OutPoint: types.OutPoint{
				Txid: "4aa201f333e80b8f62ba5b593edb47b4730212e2917b21279f389ba1c14588a3",
				Vout: 0,
			},
			Sequence: 4294967293,
		},
	}
	outputs := []types.InputConfidentialTxOut{
		{
			Amount:  209998999992700,
			Address: "XBMr6srTXmWuHifFd8gs54xYfiCBsvrksA",
			Asset:   asset,
		},
		{
			Amount: 1000000000,
			Asset:  asset,
			PegoutInput: &types.InputPegoutData{
				OnlineKey:               onlinePrivkey,
				BitcoinGenesisBlockHash: genesisBlockHash,
				BitcoinOutputDescriptor: mainchainOutputDescriptor,
				Bip32Counter:            bip32Counter,
				Whitelist:               whitelist,
			},
		},
		{
			Amount: 7300,
			Asset:  asset,
			IsFee:  true,
		},
	}
	tx, err := txUtil.Create(uint32(2), uint32(0), &inputs, &outputs, &pegoutAddrList)
	assert.NoError(t, err)
	assert.Equal(t, "020000000001a38845c1a19b389f27217b91e2120273b447db3e595bba628f0be833f301a24a0000000000fdffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000befe33cc397c0017a914001d6db698e75a5a8af771730c4ab258af30546b870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000003b9aca0000a06a2006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f1976a914efbced4774546c03a8554ce2da27c0300c9dd43b88ac2103700dcb030588ed828d85f645b48971de0d31e8c0244da46710d18681627f5a4a4101044e949dcf8ac2daac82a3e4999ee28e2711661793570c4daab34cd38d76a425d6bfe102f3fea8be12109925fad32c78b65afea4de1d17a826e7375d0e2d00660125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000001c84000000000000", tx.Hex)
	assert.Equal(t, 1, len(pegoutAddrList))
	assert.Equal(t, "1NrcpiZmCxjC7KVKAYT22SzVhhcXtp5o4v", pegoutAddrList[0])

	pegoutAddress, hasPegout, err := txUtil.GetPegoutAddress(tx, uint32(1))
	assert.NoError(t, err)
	assert.True(t, hasPegout)
	assert.Equal(t, "1NrcpiZmCxjC7KVKAYT22SzVhhcXtp5o4v", pegoutAddress.Address)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCreateClaimPeginTxByCfdConf(t *testing.T) {
	config.SetCfdConfig(config.CfdConfig{
		Network:                 types.ElementsRegtest,
		BitcoinGenesisBlockHash: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
		BitcoinAssetId:          "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
	})

	// fedpeg script
	fedpegScript := "522103aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf79210291b7d0b1b692f8f524516ed950872e5da10fb1b808b5a526dedc6fed1cf29807210386aa9372fbab374593466bc5451dc59954e90787f08060964d95c87ef34ca5bb53ae"
	keyApi := &key.PrivkeyApiImpl{}
	privkey, err := keyApi.GetPrivkeyFromWif("cUfipPioYnHU61pfYTH9uuNoswRXx8rtzXhJZrsPeVV1LRFdTxvp")
	assert.NoError(t, err)
	pubkey, err := keyApi.GetPubkey(privkey)
	assert.NoError(t, err)

	// create pegin address
	addrUtil := address.NewAddressApi()
	peginAddr, claimScript, err := addrUtil.GetPeginAddressByPubkey(types.P2shP2wshAddress, fedpegScript, pubkey.Hex)
	assert.NoError(t, err)
	assert.Equal(t, "2MvmzAFKZ5xh44vyb7qY7NB2AoDuS55rVFW", peginAddr.Address)
	assert.Equal(t, "0014e794713e386d83f32baa0e9d03e47c0839dc57a8", claimScript.ToHex())

	// create bitcoin tx
	amount := int64(100000000)
	feeAmount := int64(500)
	peginAmount := amount - feeAmount
	btcTxUtil := NewTransactionApi()
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
	btcTx, err := btcTxUtil.Create(uint32(2), uint32(0), &btcInputs, &btcOutputs)
	assert.NoError(t, err)
	// add sign
	utxos := []types.UtxoData{
		{
			OutPoint:   utxoOutPoint,
			Amount:     amount,
			Descriptor: "wpkh(02fd54c734e48c544c3c3ad1aab0607f896eb95e23e7058b174a580826a7940ad8)",
		},
	}
	utxoPrivkey, err := keyApi.GetPrivkeyFromWif("cNYKHjNc33ZyNMcDck59yWm1CYohgPhr2DYyCtmWNkL6sqb5L1rH")
	assert.NoError(t, err)
	err = btcTxUtil.SignWithPrivkey(btcTx, &utxoOutPoint, utxoPrivkey, types.SigHashTypeAll, &utxos)
	assert.NoError(t, err)
	assert.Equal(t, "020000000001014cdeada737db97af334f0fa4e87432d6068759eea65a3067d1f14a979e5a9dea0000000000ffffffff010cdff5050000000017a91426b9ba9cf5d822b70cf490ad0394566f9db20c63870247304402200b3ca71e82551a333fe5c8ce9a8f8454eb8f08aa194180e5a87c79ccf2e46212022065c1f2a363ebcb155a80e234258394140d08f6ab807581953bb21a58f2d229a6012102fd54c734e48c544c3c3ad1aab0607f896eb95e23e7058b174a580826a7940ad800000000", btcTx.Hex)

	assert.Equal(t, "12708508f0baf8691a3d7e22fd19afbf9bd8bf0d358e3310838bcc7916539c7b",
		btcTxUtil.GetTxid(btcTx))

	peginIndex := uint32(0)
	txoutProof := "00000020fe3b574c1ce6d5cb68fc518e86f7976e599fafc0a2e5754aace7ca16d97a7c78ef9325b8d4f0a4921e060fc5e71435f46a18fa339688142cd4b028c8488c9f8dd1495b5dffff7f200200000002000000024a180a6822abffc3b1080c49016899c6dac25083936df14af12f58db11958ef27926299350fdc2f4d0da1d4f0fbbd3789d29f9dc016358ae42463c0cebf393f30105"

	// create pegin tx
	txUtil := NewConfidentialTxApi()
	peginOutPoint := types.OutPoint{
		Txid: btcTxUtil.GetTxid(btcTx),
		Vout: peginIndex,
	}
	inputs := []types.InputConfidentialTxIn{
		{
			OutPoint: peginOutPoint,
			PeginInput: &types.InputPeginData{
				BitcoinTransaction: btcTx.Hex,
				ClaimScript:        claimScript.ToHex(),
				TxOutProof:         txoutProof,
			},
		},
	}
	outputs := []types.InputConfidentialTxOut{
		{
			Amount:  99998500,
			Address: "el1qqtl9a3n6878ex25u0wv8u5qlzpfkycc0cftk65t52pkauk55jqka0fajk8d80lafn4t9kqxe77cu9ez2dyr6sq54lwy009uex",
		},
		{
			Amount: 1000,
			IsFee:  true,
		},
	}
	tx, err := txUtil.Create(uint32(2), uint32(0), &inputs, &outputs, nil)
	assert.NoError(t, err)
	assert.Equal(t, "0200000001017b9c531679cc8b8310338e350dbfd89bbfaf19fd227e3d1a69f8baf0088570120000004000ffffffff020125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5db2402fe5ec67a3f8f932a9c7b987e501f105362630fc2576d5174506dde5a94902dd7160014a7b2b1da77ffa99d565b00d9f7b1c2e44a6907a80125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000000003e800000000000000000006080cdff505000000002025b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a2006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f160014e794713e386d83f32baa0e9d03e47c0839dc57a8c0020000000001014cdeada737db97af334f0fa4e87432d6068759eea65a3067d1f14a979e5a9dea0000000000ffffffff010cdff5050000000017a91426b9ba9cf5d822b70cf490ad0394566f9db20c63870247304402200b3ca71e82551a333fe5c8ce9a8f8454eb8f08aa194180e5a87c79ccf2e46212022065c1f2a363ebcb155a80e234258394140d08f6ab807581953bb21a58f2d229a6012102fd54c734e48c544c3c3ad1aab0607f896eb95e23e7058b174a580826a7940ad8000000009700000020fe3b574c1ce6d5cb68fc518e86f7976e599fafc0a2e5754aace7ca16d97a7c78ef9325b8d4f0a4921e060fc5e71435f46a18fa339688142cd4b028c8488c9f8dd1495b5dffff7f200200000002000000024a180a6822abffc3b1080c49016899c6dac25083936df14af12f58db11958ef27926299350fdc2f4d0da1d4f0fbbd3789d29f9dc016358ae42463c0cebf393f3010500000000", tx.Hex)

	// blind
	blindTxInList := []types.BlindInputData{
		{
			OutPoint: peginOutPoint,
			Amount:   peginAmount,
		},
	}
	option := types.NewBlindTxOption()
	option.AppendDummyOutput = true
	err = txUtil.Blind(tx, blindTxInList, nil, &option)
	assert.NoError(t, err)
	_, inList, outList, err := txUtil.GetAll(tx, false)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(inList))
	assert.Equal(t, 3, len(outList))

	// create signature
	peginUtxos := []*types.ElementsUtxoData{
		{
			OutPoint:   peginOutPoint,
			Amount:     peginAmount,
			Descriptor: "wpkh(" + pubkey.Hex + ")",
		},
	}
	sighash, err := txUtil.GetSighash(tx, &peginOutPoint, types.SigHashTypeAll, peginUtxos)
	assert.NoError(t, err)
	desc := &types.Descriptor{OutputDescriptor: peginUtxos[0].Descriptor}
	signature, err := keyApi.CreateEcSignature(privkey, sighash, &types.SigHashTypeAll)
	assert.NoError(t, err)

	// add sign
	err = txUtil.AddPubkeySignByDescriptor(tx, &peginOutPoint, desc, signature.ToHex())
	assert.NoError(t, err)

	// verify
	isVerify, reason, err := txUtil.VerifySign(tx, &peginOutPoint, peginUtxos)
	assert.NoError(t, err)
	assert.True(t, isVerify)
	assert.Equal(t, "", reason)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCreatePegoutTxByCfdConf(t *testing.T) {
	config.SetCfdConfig(config.CfdConfig{
		Network:                 types.NewNetworkTypeByString("liquidv1"),
		BitcoinGenesisBlockHash: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
		BitcoinAssetId:          "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
	})

	// mainchain address descriptor
	mainchainXpubkey := "xpub6A53gzNdDBQYCtFFpZT7kUpoBGpzWigaukrdF9xoUZt7cYMD2qCAHVLsstNoQEDMFJWdX78KvT6yxpC76aGCN5mENVdWtFGcWZoKdtLq5jW"
	mainchainPubkey, err := cfdgo.CfdGoGetPubkeyFromExtkey(mainchainXpubkey, int(cfdgo.KCfdNetworkMainnet))
	assert.NoError(t, err)
	negateMainchainPubkey, err := cfdgo.CfdGoNegatePubkey(mainchainPubkey)
	assert.NoError(t, err)
	mainchainOutputDescriptor := "pkh(" + mainchainXpubkey + "/0/*)"
	bip32Counter := uint32(0)

	onlinePrivkey := "L52AgshDAE14NHJuovwAw8hyrTNK4YQjuiPC9EES4sfM7oBPzU4o"
	onlinePubkey, err := cfdgo.CfdGoGetPubkeyFromPrivkey("", onlinePrivkey, true)
	assert.NoError(t, err)
	// whitelist
	pakEntry := negateMainchainPubkey + onlinePubkey
	whitelist := pakEntry

	// pegout address
	addrUtil := address.NewAddressApi()
	pegoutAddr, baseDescriptor, err := addrUtil.GetPegoutAddress(types.P2pkhAddress, mainchainOutputDescriptor, bip32Counter)
	assert.NoError(t, err)
	assert.Equal(t, "1NrcpiZmCxjC7KVKAYT22SzVhhcXtp5o4v", pegoutAddr.Address)
	assert.Equal(t, "pkh("+mainchainXpubkey+")", *baseDescriptor)

	// create pegout tx
	txUtil := NewConfidentialTxApi()
	pegoutAddrList := []string{}
	inputs := []types.InputConfidentialTxIn{
		{
			OutPoint: types.OutPoint{
				Txid: "4aa201f333e80b8f62ba5b593edb47b4730212e2917b21279f389ba1c14588a3",
				Vout: 0,
			},
			Sequence: 4294967293,
		},
	}
	outputs := []types.InputConfidentialTxOut{
		{
			Amount:  209998999992700,
			Address: "XBMr6srTXmWuHifFd8gs54xYfiCBsvrksA",
		},
		{
			Amount: 1000000000,
			PegoutInput: &types.InputPegoutData{
				OnlineKey:               onlinePrivkey,
				BitcoinOutputDescriptor: mainchainOutputDescriptor,
				Bip32Counter:            bip32Counter,
				Whitelist:               whitelist,
			},
		},
		{
			Amount: 7300,
			IsFee:  true,
		},
	}
	tx, err := txUtil.Create(uint32(2), uint32(0), &inputs, &outputs, &pegoutAddrList)
	assert.NoError(t, err)
	assert.Equal(t, "020000000001a38845c1a19b389f27217b91e2120273b447db3e595bba628f0be833f301a24a0000000000fdffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000befe33cc397c0017a914001d6db698e75a5a8af771730c4ab258af30546b870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000003b9aca0000a06a2006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f1976a914efbced4774546c03a8554ce2da27c0300c9dd43b88ac2103700dcb030588ed828d85f645b48971de0d31e8c0244da46710d18681627f5a4a4101044e949dcf8ac2daac82a3e4999ee28e2711661793570c4daab34cd38d76a425d6bfe102f3fea8be12109925fad32c78b65afea4de1d17a826e7375d0e2d00660125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000001c84000000000000", tx.Hex)
	assert.Equal(t, 1, len(pegoutAddrList))
	assert.Equal(t, "1NrcpiZmCxjC7KVKAYT22SzVhhcXtp5o4v", pegoutAddrList[0])

	pegoutAddress, hasPegout, err := txUtil.GetPegoutAddress(tx, uint32(1))
	assert.NoError(t, err)
	assert.True(t, hasPegout)
	assert.Equal(t, "1NrcpiZmCxjC7KVKAYT22SzVhhcXtp5o4v", pegoutAddress.Address)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdAddMultisigSignConfidentialTxManual(t *testing.T) {
	// TODO(k-matsuzawa): invalid tx...
	kTxData := "0200000000020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570000000000ffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac00000000"

	txid := "57a15002d066ce52573d674df925c9bc0f1164849420705f2cfad8a68111230f"
	vout := uint32(0)

	pubkey1 := "02715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad"
	privkey1 := "cRVLMWHogUo51WECRykTbeLNbm5c57iEpSegjdxco3oef6o5dbFi"
	pubkey2 := "02bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d71"
	privkey2 := "cQUTZ8VbWNYBEtrB7xwe41kqiKMQPRZshTvBHmkoJGaUfmS5pxzR"
	networkType := types.ElementsRegtest
	sigHashType := types.SigHashTypeAll
	hashType := types.P2wsh
	btcNwType := networkType.ToBitcoinType()
	api := NewConfidentialTxApi(config.NetworkOption(networkType))
	keyApi := key.NewPrivkeyApi(config.NetworkOption(networkType))
	tx := types.ConfidentialTx{Hex: kTxData}
	outPoint := types.OutPoint{Txid: txid, Vout: vout}

	// create multisig address
	pubkeys := []string{pubkey2, pubkey1}
	addr, scriptsig, multisigScript, err := cfdgo.CfdGoCreateMultisigScript(
		networkType.ToCfdValue(), hashType.ToCfdValue(), pubkeys, uint32(2))
	assert.NoError(t, err)
	assert.Equal(t, "ert1qdenhgyqf6yzkwjshlph8xsesxrh2qcpuqg8myh4q33h6m4kz7cksear3yn", addr)
	assert.Equal(t, "522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52ae", multisigScript)
	assert.Equal(t, "", scriptsig)

	satoshi := int64(13000000000000)
	utxo := types.ElementsUtxoData{
		OutPoint:   outPoint,
		Amount:     satoshi,
		Asset:      "186c7f955149a5274b39e24b6a50d1d6479f552f6522d91f3a97d771f1c18179",
		Descriptor: "wsh(multi(2,02bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d71,02715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad))",
	}
	sighash, err := api.GetSighash(&tx, &outPoint, sigHashType, []*types.ElementsUtxoData{&utxo})
	assert.NoError(t, err)
	assert.Equal(t, "d17f091203341a0d1f0101c6d010a40ce0f3cef8a09b2b605b77bb6cfc23359f", sighash.ToHex())

	// user1
	signature1, err := keyApi.CreateEcSignature(
		&types.Privkey{Wif: privkey1, Network: btcNwType}, sighash, nil)
	assert.NoError(t, err)

	// user2
	derSignature2, err := keyApi.CreateEcSignature(
		&types.Privkey{Wif: privkey2, Network: btcNwType}, sighash, &sigHashType)
	assert.NoError(t, err)
	assert.Equal(t, "30440220795dbf165d3197fe27e2b73d57cacfb8d742029c972b109040c7785aee4e75ea022065f7a985efe82eba1d0e0cafd7cf711bb8c65485bddc4e495315dd92bd7e4a7901", derSignature2.ToHex())

	signDataList := []types.SignParameter{
		{
			IsDerEncode: false,
			SigHashType: sigHashType,
		},
		{
			Data:        *types.NewScriptFromHexIgnoreError(derSignature2.ToHex()),
			IsDerEncode: false,
			SigHashType: sigHashType,
		},
		{
			Data:        *types.NewScriptFromHexIgnoreError(signature1.ToHex()),
			IsDerEncode: true,
			SigHashType: sigHashType,
		},
	}
	err = api.AddScriptSign(&tx, &outPoint, hashType, signDataList,
		types.NewScriptFromHexIgnoreError(multisigScript))
	assert.NoError(t, err)
	assert.Equal(t, "0200000001020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570000000000ffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac00000000000004004730440220795dbf165d3197fe27e2b73d57cacfb8d742029c972b109040c7785aee4e75ea022065f7a985efe82eba1d0e0cafd7cf711bb8c65485bddc4e495315dd92bd7e4a790147304402202ce4acde192e4109832d46970b510158d42fc156c92afff137157ebfc2a03e2a02200b7dfd3a92770d79d29b3c55fb6325b22bce0e1362de74b2dac80d9689b5a89b0147522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52ae00000000000000000000000000", tx.Hex)

	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdAddMultisigSignConfidentialTx(t *testing.T) {
	// TODO(k-matsuzawa): invalid tx...
	kTxData := "0200000000020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570000000000ffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac00000000"

	txid := "57a15002d066ce52573d674df925c9bc0f1164849420705f2cfad8a68111230f"
	vout := uint32(0)

	pubkey1 := "02715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad"
	privkey1 := "cRVLMWHogUo51WECRykTbeLNbm5c57iEpSegjdxco3oef6o5dbFi"
	pubkey2 := "02bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d71"
	privkey2 := "cQUTZ8VbWNYBEtrB7xwe41kqiKMQPRZshTvBHmkoJGaUfmS5pxzR"
	networkType := types.ElementsRegtest
	sigHashType := types.SigHashTypeAll
	hashType := types.P2wsh
	btcNwType := networkType.ToBitcoinType()
	api := NewConfidentialTxApi(config.NetworkOption(networkType))
	keyApi := key.NewPrivkeyApi(config.NetworkOption(networkType))
	tx := types.ConfidentialTx{Hex: kTxData}
	outPoint := types.OutPoint{Txid: txid, Vout: vout}

	// create multisig address
	pubkeys := []string{pubkey2, pubkey1}
	addr, scriptsig, multisigScript, err := cfdgo.CfdGoCreateMultisigScript(
		networkType.ToCfdValue(), hashType.ToCfdValue(), pubkeys, uint32(2))
	assert.NoError(t, err)
	assert.Equal(t, "ert1qdenhgyqf6yzkwjshlph8xsesxrh2qcpuqg8myh4q33h6m4kz7cksear3yn", addr)
	assert.Equal(t, "522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52ae", multisigScript)
	assert.Equal(t, "", scriptsig)

	satoshi := int64(13000000000000)
	utxo := types.ElementsUtxoData{
		OutPoint:   outPoint,
		Amount:     satoshi,
		Asset:      "186c7f955149a5274b39e24b6a50d1d6479f552f6522d91f3a97d771f1c18179",
		Descriptor: "wsh(multi(2,02bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d71,02715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad))",
	}
	sighash, err := api.GetSighash(&tx, &outPoint, sigHashType, []*types.ElementsUtxoData{&utxo})
	assert.NoError(t, err)
	assert.Equal(t, "d17f091203341a0d1f0101c6d010a40ce0f3cef8a09b2b605b77bb6cfc23359f", sighash.ToHex())

	// user1
	signature1, err := keyApi.CreateEcSignature(
		&types.Privkey{Wif: privkey1, Network: btcNwType}, sighash, nil)
	assert.NoError(t, err)

	// user2
	derSignature2, err := keyApi.CreateEcSignature(
		&types.Privkey{Wif: privkey2, Network: btcNwType}, sighash, &sigHashType)
	assert.NoError(t, err)
	assert.Equal(t, "30440220795dbf165d3197fe27e2b73d57cacfb8d742029c972b109040c7785aee4e75ea022065f7a985efe82eba1d0e0cafd7cf711bb8c65485bddc4e495315dd92bd7e4a7901", derSignature2.ToHex())

	signDataList := []types.SignParameter{
		{
			Data:          *types.NewScriptFromHexIgnoreError(signature1.ToHex()),
			IsDerEncode:   true,
			SigHashType:   sigHashType,
			RelatedPubkey: &types.Pubkey{Hex: pubkey1},
		},
		{
			Data:          *types.NewScriptFromHexIgnoreError(derSignature2.ToHex()),
			IsDerEncode:   false,
			SigHashType:   sigHashType,
			RelatedPubkey: &types.Pubkey{Hex: pubkey2},
		},
	}
	err = api.AddTxMultisigSignByDescriptor(&tx, &outPoint,
		&types.Descriptor{OutputDescriptor: utxo.Descriptor}, signDataList)
	assert.NoError(t, err)
	assert.Equal(t, "0200000001020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570000000000ffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac00000000000004004730440220795dbf165d3197fe27e2b73d57cacfb8d742029c972b109040c7785aee4e75ea022065f7a985efe82eba1d0e0cafd7cf711bb8c65485bddc4e495315dd92bd7e4a790147304402202ce4acde192e4109832d46970b510158d42fc156c92afff137157ebfc2a03e2a02200b7dfd3a92770d79d29b3c55fb6325b22bce0e1362de74b2dac80d9689b5a89b0147522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52ae00000000000000000000000000", tx.Hex)

	isVerify, err := api.VerifyEcSignatureByUtxo(&tx, &outPoint, &utxo, &signDataList[1])
	assert.NoError(t, err)
	assert.True(t, isVerify)

	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestBlindTransaction(t *testing.T) {
	network := types.ElementsRegtest
	genesisBlockHash := "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
	asset := "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225"
	conf := config.CfdConfig{
		Network:                 network,
		BitcoinGenesisBlockHash: genesisBlockHash,
		BitcoinAssetId:          asset,
	}
	opts := conf.GetOptions()

	accountExtPriv := types.ExtPrivkey{
		Key: "tprv8gio6qQZzaVsZkjJY62vfoohmCysvZ9HDPNej342qrMxaV87wH7DQahQMvjXzFyGn1HZwGKMCpiGswAMAqJkB1uPamKKYk7FNsQG4SLnWUA"}
	xprvApi := (key.ExtPrivkeyApi)(key.NewExtPrivkeyApi(opts...))
	addrApi := address.NewAddressApi(opts...)
	caApi := address.NewConfidentialAddressApi()
	accountXpriv, err := xprvApi.GetExtPrivkeyByPath(&accountExtPriv, "0/0")
	assert.NoError(t, err)
	blindXpriv, err := xprvApi.GetExtPrivkeyByPath(&accountExtPriv, "0/1")
	assert.NoError(t, err)
	xpriv, err := xprvApi.GetExtPrivkeyByPath(&accountExtPriv, "0/2")
	assert.NoError(t, err)
	blindXpriv2, err := xprvApi.GetExtPrivkeyByPath(&accountExtPriv, "0/3")
	assert.NoError(t, err)
	accountPrivkey, err := xprvApi.GetPrivkey(accountXpriv)
	assert.NoError(t, err)
	accountPubkey, err := xprvApi.GetPubkey(accountXpriv)
	assert.NoError(t, err)
	// blindingKey1, err := xprvApi.GetPrivkey(blindXpriv)
	// assert.NoError(t, err)
	confidentialKey1, err := xprvApi.GetPubkey(blindXpriv)
	assert.NoError(t, err)
	privkey, err := xprvApi.GetPrivkey(xpriv)
	assert.NoError(t, err)
	pubkey, err := xprvApi.GetPubkey(xpriv)
	assert.NoError(t, err)
	// blindingKey2, err := xprvApi.GetPrivkey(blindXpriv2)
	// assert.NoError(t, err)
	confidentialKey2, err := xprvApi.GetPubkey(blindXpriv2)
	assert.NoError(t, err)
	addr, err := addrApi.CreateByPubkey(accountPubkey, types.P2wpkhAddress)
	assert.NoError(t, err)
	ca1, err := caApi.Create(addr.Address, confidentialKey1)
	assert.NoError(t, err)

	// create pegin address
	addrUtil := address.NewAddressApi(opts...)
	assert.NoError(t, addrUtil.GetError())
	descUtil := descriptor.NewDescriptorApi(opts...)
	assert.NoError(t, descUtil.GetError())

	// create bitcoin tx
	amount1 := int64(100000000)
	amount2 := int64(80000000)
	feeAmount := int64(500)
	outputAmount1 := int64(150000000)
	outputAmount2 := amount1 + amount2 - feeAmount - outputAmount1

	// create pegin tx
	txUtil := NewConfidentialTxApi(opts...)
	assert.NoError(t, txUtil.GetError())

	outpoint1 := types.OutPoint{
		Txid: "dcb18911fa9faad6632ca43b81739082b0a19588ac0000000000000400473044",
		Vout: 1,
	}
	outpoint2 := types.OutPoint{
		Txid: "29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc6455",
		Vout: 2,
	}
	utxos := []*types.ElementsUtxoData{
		{
			OutPoint:   outpoint1,
			Amount:     amount1,
			Asset:      asset,
			Descriptor: "wpkh(" + pubkey.Hex + ")",
		},
		{
			OutPoint:         outpoint2,
			Amount:           amount2,
			Asset:            asset,
			Descriptor:       "wsh(multi(2," + pubkey.Hex + "," + accountPubkey.Hex + "))",
			AssetBlindFactor: "e75ea022065f7a985efe82eba1d0e0cafd7cf711bb8c65485bddc4e495315dd9",
			ValueBlindFactor: "c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801fe",
		},
	}

	amountCommitment, _, err := txUtil.GetCommitment(utxos[1].Amount, utxos[1].ValueBlindFactor, utxos[1].AssetBlindFactor, utxos[1].Asset)
	assert.NoError(t, err)
	utxos[1].AmountCommitment = amountCommitment

	desc, _, err := descUtil.Parse(&types.Descriptor{OutputDescriptor: utxos[1].Descriptor})
	assert.NoError(t, err)
	ca2, err := caApi.Create(desc.Address.Address, confidentialKey2)
	assert.NoError(t, err)

	inputs := []types.InputConfidentialTxIn{
		{
			OutPoint: outpoint1,
		},
		{
			OutPoint: outpoint2,
		},
	}
	outputs := []types.InputConfidentialTxOut{
		{
			Amount:  outputAmount1,
			Address: ca1.ConfidentialAddress,
			Asset:   asset,
		},
		{
			Amount:  outputAmount2,
			Address: ca2.ConfidentialAddress,
			Asset:   asset,
		},
		{
			Amount: feeAmount,
			Asset:  asset,
			IsFee:  true,
		},
	}
	tx, err := txUtil.Create(uint32(2), uint32(0), &inputs, &outputs, nil)
	assert.NoError(t, err)
	assert.Equal(t, "0200000000024430470004000000000000ac8895a1b0829073813ba42c63d6aa9ffa1189b1dc0100000000ffffffff5564cc020027b9290000000001ed6927df918c89b5e3d8b5062acab2c749a3290200000000ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000008f0d18003b64236b2c8f34a18e3a584fe0877fb944e2abb4544cb14bee5458bcc2480cefc160014f3ea0aba73fdb23912ebd21f46e156cdd9e942800125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000001c9c18c03d5ea88cc41bb5eae228fe83332f9ad1375e3b731b9d0dfc5f37222527c5147d02200205921dfe0a2763e39b3e96f93c8493ede64644a3d1c39882d529fea254546ef6b0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000000001f4000000000000", tx.Hex)

	// blind
	blindTxInList := []types.BlindInputData{
		{
			OutPoint: outpoint1,
			Asset:    asset,
			Amount:   amount1,
		},
		{
			OutPoint:         outpoint2,
			Asset:            asset,
			Amount:           amount2,
			AssetBlindFactor: utxos[1].AssetBlindFactor,
			ValueBlindFactor: utxos[1].ValueBlindFactor,
		},
	}
	option := types.NewBlindTxOption()
	option.AppendDummyOutput = true
	err = txUtil.Blind(tx, blindTxInList, nil, &option)
	assert.NoError(t, err)
	_, inList, outList, err := txUtil.GetAllWithAddress(tx, false)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(inList))
	assert.Equal(t, 3, len(outList))
	assert.Equal(t, addr.Address, outList[0].Address)

	// sign
	sighash, err := txUtil.GetSighash(tx, &outpoint1, types.SigHashTypeAll, utxos)
	assert.NoError(t, err)
	desc1 := types.Descriptor{
		OutputDescriptor: utxos[0].Descriptor,
	}
	privkeyUtil := key.NewPrivkeyApi()
	signature, err := privkeyUtil.CreateEcSignature(privkey, sighash, &types.SigHashTypeAll)
	assert.NoError(t, err)

	// add sign
	err = txUtil.AddPubkeySignByDescriptor(tx, &outpoint1, &desc1, signature.ToHex())
	assert.NoError(t, err)

	// verify signature
	isVerify, err := txUtil.VerifyEcSignatureByUtxo(tx, &outpoint1, utxos[0], &types.SignParameter{
		Data:          *types.NewScriptFromHexIgnoreError(signature.ToHex()),
		RelatedPubkey: pubkey,
	})
	assert.NoError(t, err)
	assert.True(t, isVerify)

	// sign
	sighash, err = txUtil.GetSighash(tx, &outpoint2, types.SigHashTypeAll, utxos)
	assert.NoError(t, err)
	desc2 := types.Descriptor{
		OutputDescriptor: utxos[1].Descriptor,
	}
	signature1, err := privkeyUtil.CreateEcSignature(privkey, sighash, &types.SigHashTypeAll)
	assert.NoError(t, err)
	signature2, err := privkeyUtil.CreateEcSignature(accountPrivkey, sighash, &types.SigHashTypeAll)
	assert.NoError(t, err)
	signs := []types.SignParameter{
		{
			Data:          *types.NewScriptFromHexIgnoreError(signature1.ToHex()),
			RelatedPubkey: pubkey,
		},
		{
			Data:          *types.NewScriptFromHexIgnoreError(signature2.ToHex()),
			RelatedPubkey: accountPubkey,
		},
	}

	// verify signature
	isVerify, err = txUtil.VerifyEcSignatureByUtxo(tx, &outpoint2, utxos[1], &signs[0])
	assert.NoError(t, err)
	assert.True(t, isVerify)
	isVerify, err = txUtil.VerifyEcSignatureByUtxo(tx, &outpoint2, utxos[1], &signs[1])
	assert.NoError(t, err)
	assert.True(t, isVerify)

	// add sign
	err = txUtil.AddTxMultisigSignByDescriptor(tx, &outpoint2, &desc2, signs)
	assert.NoError(t, err)

	// verify
	isVerify, reason, err := txUtil.VerifySign(tx, &outpoint1, utxos)
	assert.NoError(t, err)
	assert.True(t, isVerify)
	assert.Equal(t, "", reason)

	isVerify, reason, err = txUtil.VerifySign(tx, &outpoint2, utxos)
	assert.NoError(t, err)
	assert.True(t, isVerify)
	assert.Equal(t, "", reason)

	fmt.Printf("%s test done.\n", GetFuncName())
}
