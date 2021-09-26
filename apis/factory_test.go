package apis

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	cfd "github.com/cryptogarageinc/cfd-go"
	"github.com/cryptogarageinc/cfd-go/apis/key"
	"github.com/cryptogarageinc/cfd-go/config"
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
	factory := NewElementsApiFactory(opts...)
	assert.NoError(t, factory.GetError())

	// fedpeg script
	fedpegScript := "522103aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf79210291b7d0b1b692f8f524516ed950872e5da10fb1b808b5a526dedc6fed1cf29807210386aa9372fbab374593466bc5451dc59954e90787f08060964d95c87ef34ca5bb53ae"
	keyUtil := key.PrivkeyApiImpl{}
	privkey, err := keyUtil.GetPrivkeyFromWif("cUfipPioYnHU61pfYTH9uuNoswRXx8rtzXhJZrsPeVV1LRFdTxvp")
	assert.NoError(t, err)
	pubkey, err := keyUtil.GetPubkey(privkey)
	assert.NoError(t, err)

	// create pegin address
	addrUtil := factory.CreateElementsAddressApi()
	peginAddr, claimScript, err := addrUtil.GetPeginAddressByPubkey(types.P2shP2wshAddress, fedpegScript, pubkey.Hex)
	assert.NoError(t, err)
	assert.Equal(t, "2MvmzAFKZ5xh44vyb7qY7NB2AoDuS55rVFW", peginAddr.Address)
	assert.Equal(t, "0014e794713e386d83f32baa0e9d03e47c0839dc57a8", claimScript.ToHex())

	// create bitcoin tx
	amount := int64(100000000)
	feeAmount := int64(500)
	peginAmount := amount - feeAmount
	btcTxUtil := factory.CreateBitcoinTxApi()
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
	txUtil := factory.CreateElementsTxApi()
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
			Amount:  99998500,
			Address: "el1qqtl9a3n6878ex25u0wv8u5qlzpfkycc0cftk65t52pkauk55jqka0fajk8d80lafn4t9kqxe77cu9ez2dyr6sq54lwy009uex",
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
	assert.Equal(t, "0200000001017b9c531679cc8b8310338e350dbfd89bbfaf19fd227e3d1a69f8baf0088570120000004000ffffffff020125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5db2402fe5ec67a3f8f932a9c7b987e501f105362630fc2576d5174506dde5a94902dd7160014a7b2b1da77ffa99d565b00d9f7b1c2e44a6907a80125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000000003e800000000000000000006080cdff505000000002025b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a2006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f160014e794713e386d83f32baa0e9d03e47c0839dc57a8c0020000000001014cdeada737db97af334f0fa4e87432d6068759eea65a3067d1f14a979e5a9dea0000000000ffffffff010cdff5050000000017a91426b9ba9cf5d822b70cf490ad0394566f9db20c63870247304402200b3ca71e82551a333fe5c8ce9a8f8454eb8f08aa194180e5a87c79ccf2e46212022065c1f2a363ebcb155a80e234258394140d08f6ab807581953bb21a58f2d229a6012102fd54c734e48c544c3c3ad1aab0607f896eb95e23e7058b174a580826a7940ad8000000009700000020fe3b574c1ce6d5cb68fc518e86f7976e599fafc0a2e5754aace7ca16d97a7c78ef9325b8d4f0a4921e060fc5e71435f46a18fa339688142cd4b028c8488c9f8dd1495b5dffff7f200200000002000000024a180a6822abffc3b1080c49016899c6dac25083936df14af12f58db11958ef27926299350fdc2f4d0da1d4f0fbbd3789d29f9dc016358ae42463c0cebf393f3010500000000", tx.Hex)

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
	_, inList, outList, err := txUtil.GetAll(tx, false)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(inList))
	assert.Equal(t, 3, len(outList))

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
	privkeyUtil := factory.CreatePrivkeyApi()
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

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCreatePegoutTx(t *testing.T) {
	network := types.LiquidV1
	genesisBlockHash := "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
	asset := "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225"
	networkOpt := config.NetworkOption(network)
	factory := NewElementsApiFactory(networkOpt)
	assert.NoError(t, factory.GetError())

	// mainchain address descriptor
	mainchainXpubkey := "xpub6A53gzNdDBQYCtFFpZT7kUpoBGpzWigaukrdF9xoUZt7cYMD2qCAHVLsstNoQEDMFJWdX78KvT6yxpC76aGCN5mENVdWtFGcWZoKdtLq5jW"
	mainchainPubkey, err := cfd.CfdGoGetPubkeyFromExtkey(mainchainXpubkey, int(cfd.KCfdNetworkMainnet))
	assert.NoError(t, err)
	negateMainchainPubkey, err := cfd.CfdGoNegatePubkey(mainchainPubkey)
	assert.NoError(t, err)
	mainchainOutputDescriptor := "pkh(" + mainchainXpubkey + "/0/*)"
	bip32Counter := uint32(0)

	onlinePrivkey := "L52AgshDAE14NHJuovwAw8hyrTNK4YQjuiPC9EES4sfM7oBPzU4o"
	onlinePubkey, err := cfd.CfdGoGetPubkeyFromPrivkey("", onlinePrivkey, true)
	assert.NoError(t, err)
	// whitelist
	pakEntry := negateMainchainPubkey + onlinePubkey
	whitelist := pakEntry

	// pegout address
	addrUtil := factory.CreateElementsAddressApi()
	pegoutAddr, baseDescriptor, err := addrUtil.GetPegoutAddress(types.P2pkhAddress, mainchainOutputDescriptor, bip32Counter)
	assert.NoError(t, err)
	assert.Equal(t, "1NrcpiZmCxjC7KVKAYT22SzVhhcXtp5o4v", pegoutAddr.Address)
	assert.Equal(t, "pkh("+mainchainXpubkey+")", *baseDescriptor)

	// create pegout tx
	txUtil := factory.CreateElementsTxApi()
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
	factory := NewElementsApiFactory()
	assert.NoError(t, factory.GetError())

	// fedpeg script
	fedpegScript := "522103aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf79210291b7d0b1b692f8f524516ed950872e5da10fb1b808b5a526dedc6fed1cf29807210386aa9372fbab374593466bc5451dc59954e90787f08060964d95c87ef34ca5bb53ae"
	keyApi := &key.PrivkeyApiImpl{}
	privkey, err := keyApi.GetPrivkeyFromWif("cUfipPioYnHU61pfYTH9uuNoswRXx8rtzXhJZrsPeVV1LRFdTxvp")
	assert.NoError(t, err)
	pubkey, err := keyApi.GetPubkey(privkey)
	assert.NoError(t, err)

	// create pegin address
	addrUtil := factory.CreateElementsAddressApi()
	peginAddr, claimScript, err := addrUtil.GetPeginAddressByPubkey(types.P2shP2wshAddress, fedpegScript, pubkey.Hex)
	assert.NoError(t, err)
	assert.Equal(t, "2MvmzAFKZ5xh44vyb7qY7NB2AoDuS55rVFW", peginAddr.Address)
	assert.Equal(t, "0014e794713e386d83f32baa0e9d03e47c0839dc57a8", claimScript.ToHex())

	// create bitcoin tx
	amount := int64(100000000)
	feeAmount := int64(500)
	peginAmount := amount - feeAmount
	btcTxUtil := factory.CreateBitcoinTxApi()
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
	txUtil := factory.CreateElementsTxApi()
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
	factory := NewElementsApiFactory()
	assert.NoError(t, factory.GetError())

	// mainchain address descriptor
	mainchainXpubkey := "xpub6A53gzNdDBQYCtFFpZT7kUpoBGpzWigaukrdF9xoUZt7cYMD2qCAHVLsstNoQEDMFJWdX78KvT6yxpC76aGCN5mENVdWtFGcWZoKdtLq5jW"
	mainchainPubkey, err := cfd.CfdGoGetPubkeyFromExtkey(mainchainXpubkey, int(cfd.KCfdNetworkMainnet))
	assert.NoError(t, err)
	negateMainchainPubkey, err := cfd.CfdGoNegatePubkey(mainchainPubkey)
	assert.NoError(t, err)
	mainchainOutputDescriptor := "pkh(" + mainchainXpubkey + "/0/*)"
	bip32Counter := uint32(0)

	onlinePrivkey := "L52AgshDAE14NHJuovwAw8hyrTNK4YQjuiPC9EES4sfM7oBPzU4o"
	onlinePubkey, err := cfd.CfdGoGetPubkeyFromPrivkey("", onlinePrivkey, true)
	assert.NoError(t, err)
	// whitelist
	pakEntry := negateMainchainPubkey + onlinePubkey
	whitelist := pakEntry

	// pegout address
	addrUtil := factory.CreateElementsAddressApi()
	pegoutAddr, baseDescriptor, err := addrUtil.GetPegoutAddress(types.P2pkhAddress, mainchainOutputDescriptor, bip32Counter)
	assert.NoError(t, err)
	assert.Equal(t, "1NrcpiZmCxjC7KVKAYT22SzVhhcXtp5o4v", pegoutAddr.Address)
	assert.Equal(t, "pkh("+mainchainXpubkey+")", *baseDescriptor)

	// create pegout tx
	txUtil := factory.CreateElementsTxApi()
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
