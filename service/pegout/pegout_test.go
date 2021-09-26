package pegout

import (
	"errors"
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
	"github.com/stretchr/testify/assert"
)

// GetFuncName
func GetFuncName() string {
	pc, _, _, _ := runtime.Caller(1)
	funcName := runtime.FuncForPC(pc).Name()
	index := strings.LastIndex(funcName, ".")
	return funcName[index+1:]
}

func TestCreatePegoutTxByCfdConf(t *testing.T) {
	config.SetCfdConfig(config.CfdConfig{
		Network:                 types.NewNetworkTypeByString("liquidv1"),
		BitcoinGenesisBlockHash: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
		BitcoinAssetId:          "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
	})

	// pegoutApi := (Pegout)(NewPegoutService())
	// keyApi := (key.PrivkeyApi)(key.NewPrivkeyApi())
	xprvApi := (key.ExtPrivkeyApi)(key.NewExtPrivkeyApi())
	privkeyApi := (key.PrivkeyApi)(key.NewPrivkeyApi())
	txApi := (transaction.ConfidentialTxApi)(transaction.NewConfidentialTxApi())
	pegoutApi := (Pegout)(NewPegoutService())

	// key
	// root: xprv9s21ZrQH143K4SS9fUBooJcNan78y4SxCHjma2238tm8pGourqqBZh6pDJHEkksojBRQU4m4kgB1n1dK98tKHKPjxnLyLCUNRK7RgyqDZj7
	accountExtPriv := types.ExtPrivkey{
		Key: "xprv9zFUjcmCAhj2mYvQk1AAJGdrbMTciiBhabGLwLRtMuWjKu7Ab9qUvsjcySjGXZqjWHcZWyKRb92RXcXtCrj541Rr9vDv6WMrZ2vdbMQ98sZ"}
	utxoPath := "0/10"
	utxoExtPriv, err := xprvApi.GetExtPrivkeyByPath(&accountExtPriv, utxoPath)
	assert.NoError(t, err)
	utxoPubkey, err := xprvApi.GetPubkey(utxoExtPriv)
	assert.NoError(t, err)
	assert.Equal(t, "03e68167b077f06fdcef2b1c4b914df53fcdc4ea2ed43852cc3c2abf2b7992b729", utxoPubkey.Hex)
	utxoPrivkey, err := xprvApi.GetPrivkey(utxoExtPriv)
	assert.NoError(t, err)
	assert.Equal(t, "0d96bb6416bf243e35a9969316cbd303e5204be3fbce05c96b8bbc5d7a392c67", utxoPrivkey.Hex)
	assert.Equal(t, "Kwg8FCSKWKdwyKzYTheBAN2SvSNCSCudHBDYJBodidoSsXskGQ3S", utxoPrivkey.Wif)

	onlinePrivkeyWif := "L52AgshDAE14NHJuovwAw8hyrTNK4YQjuiPC9EES4sfM7oBPzU4o"
	onlinePrivkey, err := privkeyApi.GetPrivkeyFromWif(onlinePrivkeyWif)
	// pegoutApi.CreateOnlinePrivateKey()  // generate random privkey
	assert.NoError(t, err)

	// mainchain address descriptor
	// m/44h/0h/1h
	mainchainXpubkey := types.ExtPubkey{Key: "xpub6DEq98J615HL2A5UXP5DVPmEtet7DXAsqQHEBvfbEcwAC9PBKu9cG3tCkU5fXkiaJkeQzc81YiY6DDUg82eGx2dr7NpvBXstZvw5M6wisVo"}
	addressIndex := uint32(0)

	// whitelist
	pakEntry, err := pegoutApi.CreatePakEntry(&mainchainXpubkey, onlinePrivkey)
	assert.NoError(t, err)
	whitelist := pakEntry.ToHex()

	// pegout address
	pegoutAddr, desc, err := pegoutApi.CreatePegoutAddress(types.P2pkhAddress, &mainchainXpubkey, addressIndex)
	assert.NoError(t, err)
	assert.Equal(t, "1D4YiPF4k9qotSS3QWMa2E8Bt4jV9SZPmE", pegoutAddr.Address)
	assert.Equal(t, "pkh(xpub6DEq98J615HL2A5UXP5DVPmEtet7DXAsqQHEBvfbEcwAC9PBKu9cG3tCkU5fXkiaJkeQzc81YiY6DDUg82eGx2dr7NpvBXstZvw5M6wisVo)", desc.OutputDescriptor)

	// create pegout tx
	pegoutData := types.InputConfidentialTxOut{
		Amount: 1000000000,
		PegoutInput: &types.InputPegoutData{
			OnlineKey:               onlinePrivkey.Hex,
			BitcoinOutputDescriptor: desc.OutputDescriptor,
			Bip32Counter:            addressIndex,
			Whitelist:               whitelist,
		},
	}
	utxos := []*types.ElementsUtxoData{
		{
			OutPoint: types.OutPoint{
				Txid: "4aa201f333e80b8f62ba5b593edb47b4730212e2917b21279f389ba1c14588a3",
				Vout: 0,
			},
			Amount:           20000000000,
			Asset:            "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
			Descriptor:       "wpkh([d7f351ee/" + utxoPath + "]" + utxoPubkey.Hex + ")",
			AssetBlindFactor: "95e6e0912047f088394be103f3a1761adcbd92466abfe41f0964a3aa2fc201e5",
			ValueBlindFactor: "55bf185ddc2d1c747da2a82b8c9954179edec0af886daaf98d8a7b862e78bcee",
			AmountCommitment: "08b760fd74cae28eaa41126b3c1129b2d708d893e17b4e61bd9d5a5b12a1c7643b",
		},
	}
	changeAddress := "lq1qqwqawne0jyc2swqv9qp8fstrgxuux2824zxkqew9gdak4yudxvwhha0kwdv2p3j0lyekhchrzmuekp94fpfp6fkeggjkerfr8"
	option := types.NewPegoutTxOption()
	option.KnapsackMinChange = 0
	tx, pegoutAddr, unblindTx, err := pegoutApi.CreatePegoutTransaction(utxos, pegoutData, nil, &changeAddress, &option)
	assert.NoError(t, err)
	assert.Equal(t, "1D4YiPF4k9qotSS3QWMa2E8Bt4jV9SZPmE", pegoutAddr.Address)

	// output check
	_, inList, outList, err := txApi.GetAll(tx, false)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(inList))
	assert.Equal(t, 3, len(outList)) // pegout, fee, output(change)
	assert.Less(t, 6780, len(tx.Hex))
	assert.Greater(t, 6800, len(tx.Hex))
	_, _, unblindTxoutList, err := txApi.GetAll(unblindTx, false)
	assert.NoError(t, err)
	assert.Equal(t, int64(1000000000), unblindTxoutList[0].Amount)
	assert.Equal(t, int64(179), unblindTxoutList[1].Amount)
	assert.Equal(t, int64(18999999821), unblindTxoutList[2].Amount)

	pegoutAddress, hasPegout, err := txApi.GetPegoutAddress(tx, uint32(0))
	assert.NoError(t, err)
	assert.True(t, hasPegout)
	assert.Equal(t, pegoutAddr.Address, pegoutAddress.Address)

	// get sighash
	signUtxos, err := txApi.FilterUtxoByTxInList(tx, utxos)
	assert.NoError(t, err)
	utxoDesc := &types.Descriptor{OutputDescriptor: signUtxos[0].Descriptor}
	sighash, err := txApi.GetSighash(tx, &utxos[0].OutPoint, types.SigHashTypeAll, signUtxos)
	assert.NoError(t, err)

	// calc signature
	signature, err := privkeyApi.CreateEcSignature(utxoPrivkey, sighash, &types.SigHashTypeAll)
	assert.NoError(t, err)

	// verify signature
	isVerify, err := pegoutApi.VerifyPubkeySignature(tx, utxos[0], signature)
	assert.NoError(t, err)
	assert.True(t, isVerify)

	// add sign
	err = txApi.AddPubkeySignByDescriptor(tx, &utxos[0].OutPoint, utxoDesc, signature.ToHex())
	assert.NoError(t, err)

	// verify (after sign)
	isVerify, reason, err := txApi.VerifySign(tx, &utxos[0].OutPoint, signUtxos)
	assert.NoError(t, err)
	assert.True(t, isVerify)
	assert.Equal(t, "", reason)
	// assert.Equal(t, "", tx.Hex)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCreatePegoutTxSubtractFee(t *testing.T) {
	config.SetCfdConfig(config.CfdConfig{
		Network:                 types.NewNetworkTypeByString("liquidv1"),
		BitcoinGenesisBlockHash: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
		BitcoinAssetId:          "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
	})

	// pegoutApi := (Pegout)(NewPegoutService())
	// keyApi := (key.PrivkeyApi)(key.NewPrivkeyApi())
	xprvApi := (key.ExtPrivkeyApi)(key.NewExtPrivkeyApi())
	privkeyApi := (key.PrivkeyApi)(key.NewPrivkeyApi())
	txApi := (transaction.ConfidentialTxApi)(transaction.NewConfidentialTxApi())
	pegoutApi := (Pegout)(NewPegoutService())

	// key
	// root: xprv9s21ZrQH143K4SS9fUBooJcNan78y4SxCHjma2238tm8pGourqqBZh6pDJHEkksojBRQU4m4kgB1n1dK98tKHKPjxnLyLCUNRK7RgyqDZj7
	accountExtPriv := types.ExtPrivkey{
		Key: "xprv9zFUjcmCAhj2mYvQk1AAJGdrbMTciiBhabGLwLRtMuWjKu7Ab9qUvsjcySjGXZqjWHcZWyKRb92RXcXtCrj541Rr9vDv6WMrZ2vdbMQ98sZ"}
	utxoPath := "0/10"
	utxoExtPriv, err := xprvApi.GetExtPrivkeyByPath(&accountExtPriv, utxoPath)
	assert.NoError(t, err)
	utxoPubkey, err := xprvApi.GetPubkey(utxoExtPriv)
	assert.NoError(t, err)
	assert.Equal(t, "03e68167b077f06fdcef2b1c4b914df53fcdc4ea2ed43852cc3c2abf2b7992b729", utxoPubkey.Hex)
	utxoPrivkey, err := xprvApi.GetPrivkey(utxoExtPriv)
	assert.NoError(t, err)
	assert.Equal(t, "0d96bb6416bf243e35a9969316cbd303e5204be3fbce05c96b8bbc5d7a392c67", utxoPrivkey.Hex)
	assert.Equal(t, "Kwg8FCSKWKdwyKzYTheBAN2SvSNCSCudHBDYJBodidoSsXskGQ3S", utxoPrivkey.Wif)

	onlinePrivkeyWif := "L52AgshDAE14NHJuovwAw8hyrTNK4YQjuiPC9EES4sfM7oBPzU4o"
	onlinePrivkey, err := privkeyApi.GetPrivkeyFromWif(onlinePrivkeyWif)
	// pegoutApi.CreateOnlinePrivateKey()  // generate random privkey
	assert.NoError(t, err)

	// mainchain address descriptor
	// m/44h/0h/1h
	mainchainXpubkey := types.ExtPubkey{Key: "xpub6DEq98J615HL2A5UXP5DVPmEtet7DXAsqQHEBvfbEcwAC9PBKu9cG3tCkU5fXkiaJkeQzc81YiY6DDUg82eGx2dr7NpvBXstZvw5M6wisVo"}
	addressIndex := uint32(0)

	// whitelist
	pakEntry, err := pegoutApi.CreatePakEntry(&mainchainXpubkey, onlinePrivkey)
	assert.NoError(t, err)
	whitelist := pakEntry.ToHex()

	// pegout address
	pegoutAddr, desc, err := pegoutApi.CreatePegoutAddress(types.P2pkhAddress, &mainchainXpubkey, addressIndex)
	assert.NoError(t, err)
	assert.Equal(t, "1D4YiPF4k9qotSS3QWMa2E8Bt4jV9SZPmE", pegoutAddr.Address)
	assert.Equal(t, "pkh(xpub6DEq98J615HL2A5UXP5DVPmEtet7DXAsqQHEBvfbEcwAC9PBKu9cG3tCkU5fXkiaJkeQzc81YiY6DDUg82eGx2dr7NpvBXstZvw5M6wisVo)", desc.OutputDescriptor)

	// create pegout tx
	pegoutData := types.InputConfidentialTxOut{
		Amount: 1000000000,
		PegoutInput: &types.InputPegoutData{
			OnlineKey:               onlinePrivkey.Hex,
			BitcoinOutputDescriptor: desc.OutputDescriptor,
			Bip32Counter:            addressIndex,
			Whitelist:               whitelist,
		},
	}
	utxos := []*types.ElementsUtxoData{
		{
			OutPoint: types.OutPoint{
				Txid: "4aa201f333e80b8f62ba5b593edb47b4730212e2917b21279f389ba1c14588a3",
				Vout: 0,
			},
			Amount:           20000000000,
			Asset:            "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
			Descriptor:       "wpkh([d7f351ee/" + utxoPath + "]" + utxoPubkey.Hex + ")",
			AssetBlindFactor: "95e6e0912047f088394be103f3a1761adcbd92466abfe41f0964a3aa2fc201e5",
			ValueBlindFactor: "55bf185ddc2d1c747da2a82b8c9954179edec0af886daaf98d8a7b862e78bcee",
			AmountCommitment: "08b760fd74cae28eaa41126b3c1129b2d708d893e17b4e61bd9d5a5b12a1c7643b",
		},
	}
	changeAddress := "lq1qqwqawne0jyc2swqv9qp8fstrgxuux2824zxkqew9gdak4yudxvwhha0kwdv2p3j0lyekhchrzmuekp94fpfp6fkeggjkerfr8"
	option := types.NewPegoutTxOption()
	option.KnapsackMinChange = 0
	option.SubtractFee = true
	tx, pegoutAddr, unblindTx, err := pegoutApi.CreatePegoutTransaction(utxos, pegoutData, nil, &changeAddress, &option)
	assert.NoError(t, err)
	assert.Equal(t, "1D4YiPF4k9qotSS3QWMa2E8Bt4jV9SZPmE", pegoutAddr.Address)

	// output check
	_, inList, outList, err := txApi.GetAll(tx, false)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(inList))
	assert.Equal(t, 3, len(outList)) // pegout, fee, output(change)
	assert.Less(t, 6780, len(tx.Hex))
	assert.Greater(t, 6800, len(tx.Hex))
	_, _, unblindTxoutList, err := txApi.GetAll(unblindTx, false)
	assert.NoError(t, err)
	assert.Equal(t, int64(999999821), unblindTxoutList[0].Amount)
	assert.Equal(t, int64(179), unblindTxoutList[1].Amount)
	assert.Equal(t, int64(19000000000), unblindTxoutList[2].Amount)

	pegoutAddress, hasPegout, err := txApi.GetPegoutAddress(tx, uint32(0))
	assert.NoError(t, err)
	assert.True(t, hasPegout)
	assert.Equal(t, pegoutAddr.Address, pegoutAddress.Address)

	// get sighash
	signUtxos, err := txApi.FilterUtxoByTxInList(tx, utxos)
	assert.NoError(t, err)
	utxoDesc := &types.Descriptor{OutputDescriptor: signUtxos[0].Descriptor}
	sighash, err := txApi.GetSighash(tx, &utxos[0].OutPoint, types.SigHashTypeAll, signUtxos)
	assert.NoError(t, err)

	// calc signature
	signature, err := privkeyApi.CreateEcSignature(utxoPrivkey, sighash, &types.SigHashTypeAll)
	assert.NoError(t, err)

	// verify signature
	isVerify, err := pegoutApi.VerifyPubkeySignature(tx, utxos[0], signature)
	assert.NoError(t, err)
	assert.True(t, isVerify)

	// add sign
	err = txApi.AddPubkeySignByDescriptor(tx, &utxos[0].OutPoint, utxoDesc, signature.ToHex())
	assert.NoError(t, err)

	// verify (after sign)
	isVerify, reason, err := txApi.VerifySign(tx, &utxos[0].OutPoint, signUtxos)
	assert.NoError(t, err)
	assert.True(t, isVerify)
	assert.Equal(t, "", reason)
	// assert.Equal(t, "", tx.Hex)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCreatePegoutTxSubtractFeeManyUtxo(t *testing.T) {
	config.SetCfdConfig(config.CfdConfig{
		Network:                 types.NewNetworkTypeByString("liquidv1"),
		BitcoinGenesisBlockHash: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
		BitcoinAssetId:          "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
	})

	// pegoutApi := (Pegout)(NewPegoutService())
	// keyApi := (key.PrivkeyApi)(key.NewPrivkeyApi())
	xprvApi := (key.ExtPrivkeyApi)(key.NewExtPrivkeyApi())
	privkeyApi := (key.PrivkeyApi)(key.NewPrivkeyApi())
	txApi := (transaction.ConfidentialTxApi)(transaction.NewConfidentialTxApi())
	pegoutApi := (Pegout)(NewPegoutService())

	// key
	// root: xprv9s21ZrQH143K4SS9fUBooJcNan78y4SxCHjma2238tm8pGourqqBZh6pDJHEkksojBRQU4m4kgB1n1dK98tKHKPjxnLyLCUNRK7RgyqDZj7
	accountExtPriv := types.ExtPrivkey{
		Key: "xprv9zFUjcmCAhj2mYvQk1AAJGdrbMTciiBhabGLwLRtMuWjKu7Ab9qUvsjcySjGXZqjWHcZWyKRb92RXcXtCrj541Rr9vDv6WMrZ2vdbMQ98sZ"}
	utxoPath := "0/10"
	utxoExtPriv, err := xprvApi.GetExtPrivkeyByPath(&accountExtPriv, utxoPath)
	assert.NoError(t, err)
	utxoPubkey, err := xprvApi.GetPubkey(utxoExtPriv)
	assert.NoError(t, err)
	assert.Equal(t, "03e68167b077f06fdcef2b1c4b914df53fcdc4ea2ed43852cc3c2abf2b7992b729", utxoPubkey.Hex)
	utxoPrivkey, err := xprvApi.GetPrivkey(utxoExtPriv)
	assert.NoError(t, err)
	assert.Equal(t, "0d96bb6416bf243e35a9969316cbd303e5204be3fbce05c96b8bbc5d7a392c67", utxoPrivkey.Hex)
	assert.Equal(t, "Kwg8FCSKWKdwyKzYTheBAN2SvSNCSCudHBDYJBodidoSsXskGQ3S", utxoPrivkey.Wif)

	onlinePrivkeyWif := "L52AgshDAE14NHJuovwAw8hyrTNK4YQjuiPC9EES4sfM7oBPzU4o"
	onlinePrivkey, err := privkeyApi.GetPrivkeyFromWif(onlinePrivkeyWif)
	// pegoutApi.CreateOnlinePrivateKey()  // generate random privkey
	assert.NoError(t, err)

	// mainchain address descriptor
	// m/44h/0h/1h
	mainchainXpubkey := types.ExtPubkey{Key: "xpub6DEq98J615HL2A5UXP5DVPmEtet7DXAsqQHEBvfbEcwAC9PBKu9cG3tCkU5fXkiaJkeQzc81YiY6DDUg82eGx2dr7NpvBXstZvw5M6wisVo"}
	addressIndex := uint32(0)

	// whitelist
	pakEntry, err := pegoutApi.CreatePakEntry(&mainchainXpubkey, onlinePrivkey)
	assert.NoError(t, err)
	whitelist := pakEntry.ToHex()

	// pegout address
	pegoutAddr, desc, err := pegoutApi.CreatePegoutAddress(types.P2pkhAddress, &mainchainXpubkey, addressIndex)
	assert.NoError(t, err)
	assert.Equal(t, "1D4YiPF4k9qotSS3QWMa2E8Bt4jV9SZPmE", pegoutAddr.Address)
	assert.Equal(t, "pkh(xpub6DEq98J615HL2A5UXP5DVPmEtet7DXAsqQHEBvfbEcwAC9PBKu9cG3tCkU5fXkiaJkeQzc81YiY6DDUg82eGx2dr7NpvBXstZvw5M6wisVo)", desc.OutputDescriptor)

	// create pegout tx
	pegoutData := types.InputConfidentialTxOut{
		Amount: 110000,
		PegoutInput: &types.InputPegoutData{
			OnlineKey:               onlinePrivkey.Hex,
			BitcoinOutputDescriptor: desc.OutputDescriptor,
			Bip32Counter:            addressIndex,
			Whitelist:               whitelist,
		},
	}
	utxos := []*types.ElementsUtxoData{
		{
			OutPoint: types.OutPoint{
				Txid: "4aa201f333e80b8f62ba5b593edb47b4730212e2917b21279f389ba1c14588a3",
				Vout: 0,
			},
			Amount:           40000,
			Asset:            "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
			Descriptor:       "wpkh([d7f351ee/" + utxoPath + "]" + utxoPubkey.Hex + ")",
			AssetBlindFactor: "95e6e0912047f088394be103f3a1761adcbd92466abfe41f0964a3aa2fc201e5",
			ValueBlindFactor: "55bf185ddc2d1c747da2a82b8c9954179edec0af886daaf98d8a7b862e78bcee",
			AmountCommitment: "08b760fd74cae28eaa41126b3c1129b2d708d893e17b4e61bd9d5a5b12a1c7643b",
		},
		{
			OutPoint: types.OutPoint{
				Txid: "4aa201f333e80b8f62ba5b593edb47b4730212e2917b21279f389ba1c14588a3",
				Vout: 1,
			},
			Amount:           40000,
			Asset:            "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
			Descriptor:       "wpkh([d7f351ee/" + utxoPath + "]" + utxoPubkey.Hex + ")",
			AssetBlindFactor: "95e6e0912047f088394be103f3a1761adcbd92466abfe41f0964a3aa2fc201e5",
			ValueBlindFactor: "55bf185ddc2d1c747da2a82b8c9954179edec0af886daaf98d8a7b862e78bcee",
			AmountCommitment: "08b760fd74cae28eaa41126b3c1129b2d708d893e17b4e61bd9d5a5b12a1c7643b",
		},
		{
			OutPoint: types.OutPoint{
				Txid: "4aa201f333e80b8f62ba5b593edb47b4730212e2917b21279f389ba1c14588a3",
				Vout: 2,
			},
			Amount:           40000,
			Asset:            "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
			Descriptor:       "wpkh([d7f351ee/" + utxoPath + "]" + utxoPubkey.Hex + ")",
			AssetBlindFactor: "95e6e0912047f088394be103f3a1761adcbd92466abfe41f0964a3aa2fc201e5",
			ValueBlindFactor: "55bf185ddc2d1c747da2a82b8c9954179edec0af886daaf98d8a7b862e78bcee",
			AmountCommitment: "08b760fd74cae28eaa41126b3c1129b2d708d893e17b4e61bd9d5a5b12a1c7643b",
		},
		{
			OutPoint: types.OutPoint{
				Txid: "4aa201f333e80b8f62ba5b593edb47b4730212e2917b21279f389ba1c14588a3",
				Vout: 3,
			},
			Amount:           40000,
			Asset:            "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
			Descriptor:       "wpkh([d7f351ee/" + utxoPath + "]" + utxoPubkey.Hex + ")",
			AssetBlindFactor: "95e6e0912047f088394be103f3a1761adcbd92466abfe41f0964a3aa2fc201e5",
			ValueBlindFactor: "55bf185ddc2d1c747da2a82b8c9954179edec0af886daaf98d8a7b862e78bcee",
			AmountCommitment: "08b760fd74cae28eaa41126b3c1129b2d708d893e17b4e61bd9d5a5b12a1c7643b",
		},
		{
			OutPoint: types.OutPoint{
				Txid: "4aa201f333e80b8f62ba5b593edb47b4730212e2917b21279f389ba1c14588a3",
				Vout: 4,
			},
			Amount:           40000,
			Asset:            "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
			Descriptor:       "wpkh([d7f351ee/" + utxoPath + "]" + utxoPubkey.Hex + ")",
			AssetBlindFactor: "95e6e0912047f088394be103f3a1761adcbd92466abfe41f0964a3aa2fc201e5",
			ValueBlindFactor: "55bf185ddc2d1c747da2a82b8c9954179edec0af886daaf98d8a7b862e78bcee",
			AmountCommitment: "08b760fd74cae28eaa41126b3c1129b2d708d893e17b4e61bd9d5a5b12a1c7643b",
		},
		{
			OutPoint: types.OutPoint{
				Txid: "4aa201f333e80b8f62ba5b593edb47b4730212e2917b21279f389ba1c14588a3",
				Vout: 5,
			},
			Amount:           40000,
			Asset:            "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
			Descriptor:       "wpkh([d7f351ee/" + utxoPath + "]" + utxoPubkey.Hex + ")",
			AssetBlindFactor: "95e6e0912047f088394be103f3a1761adcbd92466abfe41f0964a3aa2fc201e5",
			ValueBlindFactor: "55bf185ddc2d1c747da2a82b8c9954179edec0af886daaf98d8a7b862e78bcee",
			AmountCommitment: "08b760fd74cae28eaa41126b3c1129b2d708d893e17b4e61bd9d5a5b12a1c7643b",
		},
		{
			OutPoint: types.OutPoint{
				Txid: "4aa201f333e80b8f62ba5b593edb47b4730212e2917b21279f389ba1c14588a3",
				Vout: 6,
			},
			Amount:           30000,
			Asset:            "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
			Descriptor:       "wpkh([d7f351ee/" + utxoPath + "]" + utxoPubkey.Hex + ")",
			AssetBlindFactor: "95e6e0912047f088394be103f3a1761adcbd92466abfe41f0964a3aa2fc201e5",
			ValueBlindFactor: "55bf185ddc2d1c747da2a82b8c9954179edec0af886daaf98d8a7b862e78bcee",
			AmountCommitment: "08b760fd74cae28eaa41126b3c1129b2d708d893e17b4e61bd9d5a5b12a1c7643b",
		},
		{
			OutPoint: types.OutPoint{
				Txid: "4aa201f333e80b8f62ba5b593edb47b4730212e2917b21279f389ba1c14588a3",
				Vout: 7,
			},
			Amount:           40000,
			Asset:            "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
			Descriptor:       "wpkh([d7f351ee/" + utxoPath + "]" + utxoPubkey.Hex + ")",
			AssetBlindFactor: "95e6e0912047f088394be103f3a1761adcbd92466abfe41f0964a3aa2fc201e5",
			ValueBlindFactor: "55bf185ddc2d1c747da2a82b8c9954179edec0af886daaf98d8a7b862e78bcee",
			AmountCommitment: "08b760fd74cae28eaa41126b3c1129b2d708d893e17b4e61bd9d5a5b12a1c7643b",
		},
		{
			OutPoint: types.OutPoint{
				Txid: "4aa201f333e80b8f62ba5b593edb47b4730212e2917b21279f389ba1c14588a3",
				Vout: 8,
			},
			Amount:           10000,
			Asset:            "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
			Descriptor:       "wpkh([d7f351ee/" + utxoPath + "]" + utxoPubkey.Hex + ")",
			AssetBlindFactor: "95e6e0912047f088394be103f3a1761adcbd92466abfe41f0964a3aa2fc201e5",
			ValueBlindFactor: "55bf185ddc2d1c747da2a82b8c9954179edec0af886daaf98d8a7b862e78bcee",
			AmountCommitment: "08b760fd74cae28eaa41126b3c1129b2d708d893e17b4e61bd9d5a5b12a1c7643b",
		},
		{
			OutPoint: types.OutPoint{
				Txid: "4aa201f333e80b8f62ba5b593edb47b4730212e2917b21279f389ba1c14588a3",
				Vout: 9,
			},
			Amount:           30000,
			Asset:            "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
			Descriptor:       "wpkh([d7f351ee/" + utxoPath + "]" + utxoPubkey.Hex + ")",
			AssetBlindFactor: "95e6e0912047f088394be103f3a1761adcbd92466abfe41f0964a3aa2fc201e5",
			ValueBlindFactor: "55bf185ddc2d1c747da2a82b8c9954179edec0af886daaf98d8a7b862e78bcee",
			AmountCommitment: "08b760fd74cae28eaa41126b3c1129b2d708d893e17b4e61bd9d5a5b12a1c7643b",
		},
	}
	changeAddress := "lq1qqwqawne0jyc2swqv9qp8fstrgxuux2824zxkqew9gdak4yudxvwhha0kwdv2p3j0lyekhchrzmuekp94fpfp6fkeggjkerfr8"
	option := types.NewPegoutTxOption()
	option.KnapsackMinChange = 0
	option.SubtractFee = true
	option.EffectiveFeeRate = 0.15
	option.LongTermFeeRate = 0.15
	option.DustFeeRate = 1.0
	tx, pegoutAddr, unblindTx, err := pegoutApi.CreatePegoutTransaction(utxos, pegoutData, nil, &changeAddress, &option)
	assert.NoError(t, err)
	assert.Equal(t, "1D4YiPF4k9qotSS3QWMa2E8Bt4jV9SZPmE", pegoutAddr.Address)

	// output check
	_, inList, outList, err := txApi.GetAll(tx, false)
	assert.NoError(t, err)
	if len(inList) == 3 {
		assert.Equal(t, 3, len(inList))
		assert.Equal(t, 3, len(outList)) // pegout, fee, output(change)
		assert.Less(t, 7035, len(tx.Hex))
		assert.Greater(t, 7040, len(tx.Hex))
		_, _, unblindTxoutList, err := txApi.GetAll(unblindTx, false)
		assert.NoError(t, err)
		assert.Equal(t, int64(109791), unblindTxoutList[0].Amount)
		assert.Equal(t, int64(0), unblindTxoutList[1].Amount)
		assert.Equal(t, int64(209), unblindTxoutList[2].Amount)
	} else {
		assert.Equal(t, 4, len(inList))
		assert.Equal(t, 3, len(outList)) // pegout, fee, output(change)
		assert.Less(t, 7185, len(tx.Hex))
		assert.Greater(t, 7189, len(tx.Hex))
		_, _, unblindTxoutList, err := txApi.GetAll(unblindTx, false)
		assert.NoError(t, err)
		assert.Equal(t, int64(109787), unblindTxoutList[0].Amount)
		assert.Equal(t, int64(213), unblindTxoutList[1].Amount)
		assert.Equal(t, int64(10000), unblindTxoutList[2].Amount)
	}

	pegoutAddress, hasPegout, err := txApi.GetPegoutAddress(tx, uint32(0))
	assert.NoError(t, err)
	assert.True(t, hasPegout)
	assert.Equal(t, pegoutAddr.Address, pegoutAddress.Address)

	// get sighash
	signUtxos, err := txApi.FilterUtxoByTxInList(tx, utxos)
	assert.NoError(t, err)
	utxoDesc := &types.Descriptor{OutputDescriptor: signUtxos[0].Descriptor}
	sighash, err := txApi.GetSighash(tx, &signUtxos[0].OutPoint, types.SigHashTypeAll, signUtxos)
	assert.NoError(t, err)

	// calc signature
	signature, err := privkeyApi.CreateEcSignature(utxoPrivkey, sighash, &types.SigHashTypeAll)
	assert.NoError(t, err)

	// verify signature
	isVerify, err := pegoutApi.VerifyPubkeySignature(tx, signUtxos[0], signature)
	assert.NoError(t, err)
	assert.True(t, isVerify)

	// add sign
	err = txApi.AddPubkeySignByDescriptor(tx, &signUtxos[0].OutPoint, utxoDesc, signature.ToHex())
	assert.NoError(t, err)

	// verify (after sign)
	isVerify, reason, err := txApi.VerifySign(tx, &signUtxos[0].OutPoint, signUtxos)
	assert.NoError(t, err)
	assert.True(t, isVerify)
	assert.Equal(t, "", reason)
	// assert.Equal(t, "", tx.Hex)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCreatePegoutTxSubtractFeeJust(t *testing.T) {
	config.SetCfdConfig(config.CfdConfig{
		Network:                 types.NewNetworkTypeByString("liquidv1"),
		BitcoinGenesisBlockHash: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
		BitcoinAssetId:          "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
	})

	// pegoutApi := (Pegout)(NewPegoutService())
	// keyApi := (key.PrivkeyApi)(key.NewPrivkeyApi())
	xprvApi := (key.ExtPrivkeyApi)(key.NewExtPrivkeyApi())
	privkeyApi := (key.PrivkeyApi)(key.NewPrivkeyApi())
	txApi := (transaction.ConfidentialTxApi)(transaction.NewConfidentialTxApi())
	pegoutApi := (Pegout)(NewPegoutService())

	// key
	// root: xprv9s21ZrQH143K4SS9fUBooJcNan78y4SxCHjma2238tm8pGourqqBZh6pDJHEkksojBRQU4m4kgB1n1dK98tKHKPjxnLyLCUNRK7RgyqDZj7
	accountExtPriv := types.ExtPrivkey{
		Key: "xprv9zFUjcmCAhj2mYvQk1AAJGdrbMTciiBhabGLwLRtMuWjKu7Ab9qUvsjcySjGXZqjWHcZWyKRb92RXcXtCrj541Rr9vDv6WMrZ2vdbMQ98sZ"}
	utxoPath := "0/10"
	utxoExtPriv, err := xprvApi.GetExtPrivkeyByPath(&accountExtPriv, utxoPath)
	assert.NoError(t, err)
	utxoPubkey, err := xprvApi.GetPubkey(utxoExtPriv)
	assert.NoError(t, err)
	assert.Equal(t, "03e68167b077f06fdcef2b1c4b914df53fcdc4ea2ed43852cc3c2abf2b7992b729", utxoPubkey.Hex)
	utxoPrivkey, err := xprvApi.GetPrivkey(utxoExtPriv)
	assert.NoError(t, err)
	assert.Equal(t, "0d96bb6416bf243e35a9969316cbd303e5204be3fbce05c96b8bbc5d7a392c67", utxoPrivkey.Hex)
	assert.Equal(t, "Kwg8FCSKWKdwyKzYTheBAN2SvSNCSCudHBDYJBodidoSsXskGQ3S", utxoPrivkey.Wif)

	onlinePrivkeyWif := "L52AgshDAE14NHJuovwAw8hyrTNK4YQjuiPC9EES4sfM7oBPzU4o"
	onlinePrivkey, err := privkeyApi.GetPrivkeyFromWif(onlinePrivkeyWif)
	// pegoutApi.CreateOnlinePrivateKey()  // generate random privkey
	assert.NoError(t, err)

	// mainchain address descriptor
	// m/44h/0h/1h
	mainchainXpubkey := types.ExtPubkey{Key: "xpub6DEq98J615HL2A5UXP5DVPmEtet7DXAsqQHEBvfbEcwAC9PBKu9cG3tCkU5fXkiaJkeQzc81YiY6DDUg82eGx2dr7NpvBXstZvw5M6wisVo"}
	addressIndex := uint32(0)

	// whitelist
	pakEntry, err := pegoutApi.CreatePakEntry(&mainchainXpubkey, onlinePrivkey)
	assert.NoError(t, err)
	whitelist := pakEntry.ToHex()

	// pegout address
	pegoutAddr, desc, err := pegoutApi.CreatePegoutAddress(types.P2pkhAddress, &mainchainXpubkey, addressIndex)
	assert.NoError(t, err)
	assert.Equal(t, "1D4YiPF4k9qotSS3QWMa2E8Bt4jV9SZPmE", pegoutAddr.Address)
	assert.Equal(t, "pkh(xpub6DEq98J615HL2A5UXP5DVPmEtet7DXAsqQHEBvfbEcwAC9PBKu9cG3tCkU5fXkiaJkeQzc81YiY6DDUg82eGx2dr7NpvBXstZvw5M6wisVo)", desc.OutputDescriptor)

	// create pegout tx
	pegoutData := types.InputConfidentialTxOut{
		Amount: 120000,
		PegoutInput: &types.InputPegoutData{
			OnlineKey:               onlinePrivkey.Hex,
			BitcoinOutputDescriptor: desc.OutputDescriptor,
			Bip32Counter:            addressIndex,
			Whitelist:               whitelist,
		},
	}
	utxos := []*types.ElementsUtxoData{
		{
			OutPoint: types.OutPoint{
				Txid: "4aa201f333e80b8f62ba5b593edb47b4730212e2917b21279f389ba1c14588a3",
				Vout: 0,
			},
			Amount:           60000,
			Asset:            "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
			Descriptor:       "wpkh([d7f351ee/" + utxoPath + "]" + utxoPubkey.Hex + ")",
			AssetBlindFactor: "95e6e0912047f088394be103f3a1761adcbd92466abfe41f0964a3aa2fc201e5",
			ValueBlindFactor: "55bf185ddc2d1c747da2a82b8c9954179edec0af886daaf98d8a7b862e78bcee",
			AmountCommitment: "08b760fd74cae28eaa41126b3c1129b2d708d893e17b4e61bd9d5a5b12a1c7643b",
		},
		{
			OutPoint: types.OutPoint{
				Txid: "4aa201f333e80b8f62ba5b593edb47b4730212e2917b21279f389ba1c14588a3",
				Vout: 1,
			},
			Amount:           60000,
			Asset:            "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
			Descriptor:       "wpkh([d7f351ee/" + utxoPath + "]" + utxoPubkey.Hex + ")",
			AssetBlindFactor: "95e6e0912047f088394be103f3a1761adcbd92466abfe41f0964a3aa2fc201e5",
			ValueBlindFactor: "55bf185ddc2d1c747da2a82b8c9954179edec0af886daaf98d8a7b862e78bcee",
			AmountCommitment: "08b760fd74cae28eaa41126b3c1129b2d708d893e17b4e61bd9d5a5b12a1c7643b",
		},
	}
	changeAddress := "lq1qqwqawne0jyc2swqv9qp8fstrgxuux2824zxkqew9gdak4yudxvwhha0kwdv2p3j0lyekhchrzmuekp94fpfp6fkeggjkerfr8"
	option := types.NewPegoutTxOption()
	option.KnapsackMinChange = 0
	option.SubtractFee = true
	option.EffectiveFeeRate = 0.15
	option.DustFeeRate = 1.0
	tx, pegoutAddr, unblindTx, err := pegoutApi.CreatePegoutTransaction(utxos, pegoutData, nil, &changeAddress, &option)
	assert.NoError(t, err)
	assert.Equal(t, "1D4YiPF4k9qotSS3QWMa2E8Bt4jV9SZPmE", pegoutAddr.Address)

	// output check
	_, inList, outList, err := txApi.GetAll(tx, false)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(inList))
	assert.Equal(t, 3, len(outList)) // pegout, dummy, fee
	assert.Less(t, 6883, len(tx.Hex))
	assert.Greater(t, 6887, len(tx.Hex))
	_, _, unblindTxoutList, err := txApi.GetAll(unblindTx, false)
	assert.NoError(t, err)
	assert.Equal(t, int64(119812), unblindTxoutList[0].Amount)
	assert.Equal(t, int64(0), unblindTxoutList[1].Amount)
	assert.Equal(t, int64(188), unblindTxoutList[2].Amount)

	pegoutAddress, hasPegout, err := txApi.GetPegoutAddress(tx, uint32(0))
	assert.NoError(t, err)
	assert.True(t, hasPegout)
	assert.Equal(t, pegoutAddr.Address, pegoutAddress.Address)

	// get sighash
	signUtxos, err := txApi.FilterUtxoByTxInList(tx, utxos)
	assert.NoError(t, err)
	utxoDesc := &types.Descriptor{OutputDescriptor: signUtxos[0].Descriptor}
	sighash, err := txApi.GetSighash(tx, &signUtxos[0].OutPoint, types.SigHashTypeAll, signUtxos)
	assert.NoError(t, err)

	// calc signature
	signature, err := privkeyApi.CreateEcSignature(utxoPrivkey, sighash, &types.SigHashTypeAll)
	assert.NoError(t, err)

	// verify signature
	isVerify, err := pegoutApi.VerifyPubkeySignature(tx, signUtxos[0], signature)
	assert.NoError(t, err)
	assert.True(t, isVerify)

	// add sign
	err = txApi.AddPubkeySignByDescriptor(tx, &signUtxos[0].OutPoint, utxoDesc, signature.ToHex())
	assert.NoError(t, err)

	// verify (after sign)
	isVerify, reason, err := txApi.VerifySign(tx, &signUtxos[0].OutPoint, signUtxos)
	assert.NoError(t, err)
	assert.True(t, isVerify)
	assert.Equal(t, "", reason)
	// assert.Equal(t, "", tx.Hex)
	assert.Greater(t, 7099, len(tx.Hex))

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCreatePegoutTxWithUnblindUtxoByCfdConf(t *testing.T) {
	config.SetCfdConfig(config.CfdConfig{
		Network:                 types.NewNetworkTypeByString("liquidv1"),
		BitcoinGenesisBlockHash: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
		BitcoinAssetId:          "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
	})

	// pegoutApi := (Pegout)(NewPegoutService())
	// keyApi := (key.PrivkeyApi)(key.NewPrivkeyApi())
	xprvApi := (key.ExtPrivkeyApi)(key.NewExtPrivkeyApi())
	privkeyApi := (key.PrivkeyApi)(key.NewPrivkeyApi())
	txApi := (transaction.ConfidentialTxApi)(transaction.NewConfidentialTxApi())
	pegoutApi := (Pegout)(NewPegoutService())

	// key
	// root: xprv9s21ZrQH143K4SS9fUBooJcNan78y4SxCHjma2238tm8pGourqqBZh6pDJHEkksojBRQU4m4kgB1n1dK98tKHKPjxnLyLCUNRK7RgyqDZj7
	accountExtPriv := types.ExtPrivkey{
		Key: "xprv9zFUjcmCAhj2mYvQk1AAJGdrbMTciiBhabGLwLRtMuWjKu7Ab9qUvsjcySjGXZqjWHcZWyKRb92RXcXtCrj541Rr9vDv6WMrZ2vdbMQ98sZ"}
	utxoPath := "0/10"
	utxoExtPriv, err := xprvApi.GetExtPrivkeyByPath(&accountExtPriv, utxoPath)
	assert.NoError(t, err)
	utxoPubkey, err := xprvApi.GetPubkey(utxoExtPriv)
	assert.NoError(t, err)
	assert.Equal(t, "03e68167b077f06fdcef2b1c4b914df53fcdc4ea2ed43852cc3c2abf2b7992b729", utxoPubkey.Hex)
	utxoPrivkey, err := xprvApi.GetPrivkey(utxoExtPriv)
	assert.NoError(t, err)
	assert.Equal(t, "0d96bb6416bf243e35a9969316cbd303e5204be3fbce05c96b8bbc5d7a392c67", utxoPrivkey.Hex)
	assert.Equal(t, "Kwg8FCSKWKdwyKzYTheBAN2SvSNCSCudHBDYJBodidoSsXskGQ3S", utxoPrivkey.Wif)

	onlinePrivkeyWif := "L52AgshDAE14NHJuovwAw8hyrTNK4YQjuiPC9EES4sfM7oBPzU4o"
	onlinePrivkey, err := privkeyApi.GetPrivkeyFromWif(onlinePrivkeyWif)
	// pegoutApi.CreateOnlinePrivateKey()  // generate random privkey
	assert.NoError(t, err)

	// mainchain address descriptor
	// m/44h/0h/1h
	mainchainXpubkey := types.ExtPubkey{Key: "xpub6DEq98J615HL2A5UXP5DVPmEtet7DXAsqQHEBvfbEcwAC9PBKu9cG3tCkU5fXkiaJkeQzc81YiY6DDUg82eGx2dr7NpvBXstZvw5M6wisVo"}
	addressIndex := uint32(0)

	// whitelist
	pakEntry, err := pegoutApi.CreatePakEntry(&mainchainXpubkey, onlinePrivkey)
	assert.NoError(t, err)
	whitelist := pakEntry.ToHex()

	// pegout address
	pegoutAddr, desc, err := pegoutApi.CreatePegoutAddress(types.P2pkhAddress, &mainchainXpubkey, addressIndex)
	assert.NoError(t, err)
	assert.Equal(t, "1D4YiPF4k9qotSS3QWMa2E8Bt4jV9SZPmE", pegoutAddr.Address)
	assert.Equal(t, "pkh(xpub6DEq98J615HL2A5UXP5DVPmEtet7DXAsqQHEBvfbEcwAC9PBKu9cG3tCkU5fXkiaJkeQzc81YiY6DDUg82eGx2dr7NpvBXstZvw5M6wisVo)", desc.OutputDescriptor)

	// create pegout tx
	pegoutData := types.InputConfidentialTxOut{
		Amount: 1000000000,
		PegoutInput: &types.InputPegoutData{
			OnlineKey:               onlinePrivkey.Hex,
			BitcoinOutputDescriptor: desc.OutputDescriptor,
			Bip32Counter:            addressIndex,
			Whitelist:               whitelist,
		},
	}
	utxos := []*types.ElementsUtxoData{
		{
			OutPoint: types.OutPoint{
				Txid: "4aa201f333e80b8f62ba5b593edb47b4730212e2917b21279f389ba1c14588a3",
				Vout: 0,
			},
			Amount:     2100000000000000,
			Asset:      "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
			Descriptor: "wpkh([d7f351ee/" + utxoPath + "]" + utxoPubkey.Hex + ")",
		},
	}
	txouts := []types.InputConfidentialTxOut{
		{
			Amount:  200000000000000,
			Address: "lq1qqgv5wwfp4h0pfnyy2kkxl0kg3qnahcpfq7emrxu9xusz879axq0spg9cxu8wf72ktsft5r8vxnkfd8s5kmg32fvy8texp5p6s",
		},
	}
	changeAddress := "lq1qqwqawne0jyc2swqv9qp8fstrgxuux2824zxkqew9gdak4yudxvwhha0kwdv2p3j0lyekhchrzmuekp94fpfp6fkeggjkerfr8"
	option := types.NewPegoutTxOption()
	option.KnapsackMinChange = 0
	tx, pegoutAddr, unblindTx, err := pegoutApi.CreatePegoutTransaction(utxos, pegoutData, &txouts, &changeAddress, &option)
	assert.NoError(t, err)
	assert.Equal(t, "1D4YiPF4k9qotSS3QWMa2E8Bt4jV9SZPmE", pegoutAddr.Address)

	// output check
	_, inList, outList, err := txApi.GetAll(tx, false)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(inList))
	assert.Equal(t, 4, len(outList)) // pegout, fee, output(send), change
	assert.Less(t, 17310, len(tx.Hex))
	assert.Greater(t, 17320, len(tx.Hex))
	_, _, unblindTxoutList, err := txApi.GetAll(unblindTx, false)
	assert.NoError(t, err)
	assert.Equal(t, int64(200000000000000), unblindTxoutList[1].Amount)

	pegoutAddress, hasPegout, err := txApi.GetPegoutAddress(tx, uint32(0))
	assert.NoError(t, err)
	assert.True(t, hasPegout)
	assert.Equal(t, pegoutAddr.Address, pegoutAddress.Address)

	// get sighash
	signUtxos, err := txApi.FilterUtxoByTxInList(tx, utxos)
	assert.NoError(t, err)
	utxoDesc := &types.Descriptor{OutputDescriptor: signUtxos[0].Descriptor}
	sighash, err := txApi.GetSighash(tx, &utxos[0].OutPoint, types.SigHashTypeAll, signUtxos)
	assert.NoError(t, err)

	// calc signature
	signature, err := privkeyApi.CreateEcSignature(utxoPrivkey, sighash, &types.SigHashTypeAll)
	assert.NoError(t, err)

	// verify signature
	isVerify, err := pegoutApi.VerifyPubkeySignature(tx, utxos[0], signature)
	assert.NoError(t, err)
	assert.True(t, isVerify)

	// add sign
	err = txApi.AddPubkeySignByDescriptor(tx, &utxos[0].OutPoint, utxoDesc, signature.ToHex())
	assert.NoError(t, err)

	// verify (after sign)
	isVerify, reason, err := txApi.VerifySign(tx, &utxos[0].OutPoint, signUtxos)
	assert.NoError(t, err)
	assert.True(t, isVerify)
	assert.Equal(t, "", reason)
	// assert.Equal(t, "", tx.Hex)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCreatePegoutTxWithAppendDummyByCfdConf(t *testing.T) {
	config.SetCfdConfig(config.CfdConfig{
		Network:                 types.ElementsRegtest,
		BitcoinGenesisBlockHash: "000088f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
		BitcoinAssetId:          "0000f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
	})
	curConfig := config.CfdConfig{
		Network:                 types.NewNetworkTypeByString("liquidv1"),
		BitcoinGenesisBlockHash: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
		BitcoinAssetId:          "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
	}
	opts := curConfig.GetOptions()

	// pegoutApi := (Pegout)(NewPegoutService())
	// keyApi := (key.PrivkeyApi)(key.NewPrivkeyApi())
	xprvApi := key.NewExtPrivkeyApi(opts...)
	assert.NoError(t, xprvApi.GetError())
	for _, errItem := range cfdErrors.GetErrors(xprvApi.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}
	privkeyApi := key.NewPrivkeyApi(opts...)
	assert.NoError(t, privkeyApi.GetError())
	for _, errItem := range cfdErrors.GetErrors(privkeyApi.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}
	txApi := transaction.NewConfidentialTxApi(opts...)
	assert.NoError(t, txApi.GetError())
	for _, errItem := range cfdErrors.GetErrors(txApi.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}
	pegoutApi := NewPegoutService(opts...)
	assert.NoError(t, pegoutApi.GetError())
	for _, errItem := range cfdErrors.GetErrors(pegoutApi.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}

	// key
	// root: xprv9s21ZrQH143K4SS9fUBooJcNan78y4SxCHjma2238tm8pGourqqBZh6pDJHEkksojBRQU4m4kgB1n1dK98tKHKPjxnLyLCUNRK7RgyqDZj7
	accountExtPriv := types.ExtPrivkey{
		Key: "xprv9zFUjcmCAhj2mYvQk1AAJGdrbMTciiBhabGLwLRtMuWjKu7Ab9qUvsjcySjGXZqjWHcZWyKRb92RXcXtCrj541Rr9vDv6WMrZ2vdbMQ98sZ"}
	utxoPath := "0/10"
	utxoExtPriv, err := xprvApi.GetExtPrivkeyByPath(&accountExtPriv, utxoPath)
	assert.NoError(t, err)
	utxoPubkey, err := xprvApi.GetPubkey(utxoExtPriv)
	assert.NoError(t, err)
	assert.Equal(t, "03e68167b077f06fdcef2b1c4b914df53fcdc4ea2ed43852cc3c2abf2b7992b729", utxoPubkey.Hex)
	utxoPrivkey, err := xprvApi.GetPrivkey(utxoExtPriv)
	assert.NoError(t, err)
	assert.Equal(t, "0d96bb6416bf243e35a9969316cbd303e5204be3fbce05c96b8bbc5d7a392c67", utxoPrivkey.Hex)
	assert.Equal(t, "Kwg8FCSKWKdwyKzYTheBAN2SvSNCSCudHBDYJBodidoSsXskGQ3S", utxoPrivkey.Wif)

	onlinePrivkeyWif := "L52AgshDAE14NHJuovwAw8hyrTNK4YQjuiPC9EES4sfM7oBPzU4o"
	onlinePrivkey, err := privkeyApi.GetPrivkeyFromWif(onlinePrivkeyWif)
	// pegoutApi.CreateOnlinePrivateKey()  // generate random privkey
	assert.NoError(t, err)

	// mainchain address descriptor
	// m/44h/0h/1h
	mainchainXpubkey := types.ExtPubkey{Key: "xpub6DEq98J615HL2A5UXP5DVPmEtet7DXAsqQHEBvfbEcwAC9PBKu9cG3tCkU5fXkiaJkeQzc81YiY6DDUg82eGx2dr7NpvBXstZvw5M6wisVo"}
	addressIndex := uint32(0)

	// whitelist
	pakEntry, err := pegoutApi.CreatePakEntry(&mainchainXpubkey, onlinePrivkey)
	assert.NoError(t, err)
	whitelist := pakEntry.ToHex()

	// pegout address
	pegoutAddr, desc, err := pegoutApi.CreatePegoutAddress(types.P2pkhAddress, &mainchainXpubkey, addressIndex)
	assert.NoError(t, err)
	assert.Equal(t, "1D4YiPF4k9qotSS3QWMa2E8Bt4jV9SZPmE", pegoutAddr.Address)
	assert.Equal(t, "pkh(xpub6DEq98J615HL2A5UXP5DVPmEtet7DXAsqQHEBvfbEcwAC9PBKu9cG3tCkU5fXkiaJkeQzc81YiY6DDUg82eGx2dr7NpvBXstZvw5M6wisVo)", desc.OutputDescriptor)

	// create pegout tx
	pegoutData := types.InputConfidentialTxOut{
		Amount: 1000000000,
		PegoutInput: &types.InputPegoutData{
			OnlineKey:               onlinePrivkey.Hex,
			BitcoinOutputDescriptor: desc.OutputDescriptor,
			Bip32Counter:            addressIndex,
			Whitelist:               whitelist,
		},
	}
	utxos := []*types.ElementsUtxoData{
		{
			OutPoint: types.OutPoint{
				Txid: "4aa201f333e80b8f62ba5b593edb47b4730212e2917b21279f389ba1c14588a3",
				Vout: 0,
			},
			Amount:     2100000000000000,
			Asset:      "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
			Descriptor: "wpkh([d7f351ee/" + utxoPath + "]" + utxoPubkey.Hex + ")",
		},
	}
	changeAddress := "lq1qqwqawne0jyc2swqv9qp8fstrgxuux2824zxkqew9gdak4yudxvwhha0kwdv2p3j0lyekhchrzmuekp94fpfp6fkeggjkerfr8"
	option := types.NewPegoutTxOption()
	option.KnapsackMinChange = 0
	tx, pegoutAddr, unblindTx, err := pegoutApi.CreatePegoutTransaction(utxos, pegoutData, nil, &changeAddress, &option)
	assert.NoError(t, err)
	assert.Equal(t, "1D4YiPF4k9qotSS3QWMa2E8Bt4jV9SZPmE", pegoutAddr.Address)

	// output check
	_, inList, outList, err := txApi.GetAll(tx, false)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(inList))
	assert.Equal(t, 4, len(outList)) // pegout, fee, change, dummy
	// If the dummy output is blinded, the rangeproof will be small because the CT value cannot be high.
	assert.Less(t, 15330, len(tx.Hex))
	assert.Greater(t, 15340, len(tx.Hex))
	_, _, unblindTxoutList, err := txApi.GetAll(unblindTx, false)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), unblindTxoutList[1].Amount)

	pegoutAddress, hasPegout, err := txApi.GetPegoutAddress(tx, uint32(0))
	assert.NoError(t, err)
	assert.True(t, hasPegout)
	assert.Equal(t, pegoutAddr.Address, pegoutAddress.Address)

	// get sighash
	signUtxos, err := txApi.FilterUtxoByTxInList(tx, utxos)
	assert.NoError(t, err)
	utxoDesc := &types.Descriptor{OutputDescriptor: signUtxos[0].Descriptor}
	sighash, err := txApi.GetSighash(tx, &utxos[0].OutPoint, types.SigHashTypeAll, signUtxos)
	assert.NoError(t, err)

	// calc signature
	signature, err := privkeyApi.CreateEcSignature(utxoPrivkey, sighash, &types.SigHashTypeAll)
	assert.NoError(t, err)

	// verify signature
	isVerify, err := pegoutApi.VerifyPubkeySignature(tx, utxos[0], signature)
	assert.NoError(t, err)
	assert.True(t, isVerify)

	// add sign
	err = txApi.AddPubkeySignByDescriptor(tx, &utxos[0].OutPoint, utxoDesc, signature.ToHex())
	assert.NoError(t, err)

	// verify (after sign)
	isVerify, reason, err := txApi.VerifySign(tx, &utxos[0].OutPoint, signUtxos)
	assert.NoError(t, err)
	assert.True(t, isVerify)
	assert.Equal(t, "", reason)
	// assert.Equal(t, "", tx.Hex)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCreatePegoutOverrideApis(t *testing.T) {
	config.SetCfdConfig(config.CfdConfig{
		Network:                 types.ElementsRegtest,
		BitcoinGenesisBlockHash: "000088f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
		BitcoinAssetId:          "0000f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
	})
	curConfig := config.CfdConfig{
		Network:                 types.NewNetworkTypeByString("liquidv1"),
		BitcoinGenesisBlockHash: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
		BitcoinAssetId:          "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
	}
	confOpts := curConfig.GetOptions()

	// pegoutApi := (Pegout)(NewPegoutService())
	// keyApi := (key.PrivkeyApi)(key.NewPrivkeyApi())
	btcNetworkConf := config.NetworkOption(types.Mainnet)
	btcAddrApi := address.NewAddressApi(btcNetworkConf)
	assert.NoError(t, btcAddrApi.GetError())
	for _, errItem := range cfdErrors.GetErrors(btcAddrApi.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}
	btcDescApi := descriptor.NewDescriptorApi(btcNetworkConf)
	assert.NoError(t, btcDescApi.GetError())
	for _, errItem := range cfdErrors.GetErrors(btcDescApi.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}
	elmDescApi := descriptor.NewDescriptorApi(confOpts...)
	assert.NoError(t, elmDescApi.GetError())
	for _, errItem := range cfdErrors.GetErrors(elmDescApi.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}
	btcTxApi := transaction.NewTransactionApi(btcNetworkConf).WithBitcoinDescriptorApi(btcDescApi)
	assert.NoError(t, btcTxApi.GetError())
	for _, errItem := range cfdErrors.GetErrors(btcTxApi.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}
	pubkeyApi := key.NewPubkeyApi()
	xprvApi := key.NewExtPrivkeyApi(confOpts...)
	assert.NoError(t, xprvApi.GetError())
	for _, errItem := range cfdErrors.GetErrors(xprvApi.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}
	privkeyApi := key.NewPrivkeyApi(confOpts...)
	assert.NoError(t, privkeyApi.GetError())
	for _, errItem := range cfdErrors.GetErrors(privkeyApi.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}
	txApi := transaction.NewConfidentialTxApi(confOpts...).
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
	pegoutApi := NewPegoutService(confOpts...).
		WithBitcoinAddressApi(btcAddrApi).
		WithElementsDescriptorApi(elmDescApi).
		WithConfidentialTxApi(txApi).WithPubkeyApi(pubkeyApi)
	assert.NoError(t, pegoutApi.GetError())
	for _, errItem := range cfdErrors.GetErrors(pegoutApi.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}

	// key
	// root: xprv9s21ZrQH143K4SS9fUBooJcNan78y4SxCHjma2238tm8pGourqqBZh6pDJHEkksojBRQU4m4kgB1n1dK98tKHKPjxnLyLCUNRK7RgyqDZj7
	accountExtPriv := types.ExtPrivkey{
		Key: "xprv9zFUjcmCAhj2mYvQk1AAJGdrbMTciiBhabGLwLRtMuWjKu7Ab9qUvsjcySjGXZqjWHcZWyKRb92RXcXtCrj541Rr9vDv6WMrZ2vdbMQ98sZ"}
	utxoPath := "0/10"
	utxoExtPriv, err := xprvApi.GetExtPrivkeyByPath(&accountExtPriv, utxoPath)
	assert.NoError(t, err)
	utxoPubkey, err := xprvApi.GetPubkey(utxoExtPriv)
	assert.NoError(t, err)
	assert.Equal(t, "03e68167b077f06fdcef2b1c4b914df53fcdc4ea2ed43852cc3c2abf2b7992b729", utxoPubkey.Hex)
	utxoPrivkey, err := xprvApi.GetPrivkey(utxoExtPriv)
	assert.NoError(t, err)
	assert.Equal(t, "0d96bb6416bf243e35a9969316cbd303e5204be3fbce05c96b8bbc5d7a392c67", utxoPrivkey.Hex)
	assert.Equal(t, "Kwg8FCSKWKdwyKzYTheBAN2SvSNCSCudHBDYJBodidoSsXskGQ3S", utxoPrivkey.Wif)

	onlinePrivkeyWif := "L52AgshDAE14NHJuovwAw8hyrTNK4YQjuiPC9EES4sfM7oBPzU4o"
	onlinePrivkey, err := privkeyApi.GetPrivkeyFromWif(onlinePrivkeyWif)
	// pegoutApi.CreateOnlinePrivateKey()  // generate random privkey
	assert.NoError(t, err)

	// mainchain address descriptor
	// m/44h/0h/1h
	mainchainXpubkey := types.ExtPubkey{Key: "xpub6DEq98J615HL2A5UXP5DVPmEtet7DXAsqQHEBvfbEcwAC9PBKu9cG3tCkU5fXkiaJkeQzc81YiY6DDUg82eGx2dr7NpvBXstZvw5M6wisVo"}
	addressIndex := uint32(0)

	// whitelist
	pakEntry, err := pegoutApi.CreatePakEntry(&mainchainXpubkey, onlinePrivkey)
	assert.NoError(t, err)
	whitelist := pakEntry.ToHex()

	// pegout address
	pegoutAddr, desc, err := pegoutApi.CreatePegoutAddress(types.P2pkhAddress, &mainchainXpubkey, addressIndex)
	assert.NoError(t, err)
	assert.Equal(t, "1D4YiPF4k9qotSS3QWMa2E8Bt4jV9SZPmE", pegoutAddr.Address)
	assert.Equal(t, "pkh(xpub6DEq98J615HL2A5UXP5DVPmEtet7DXAsqQHEBvfbEcwAC9PBKu9cG3tCkU5fXkiaJkeQzc81YiY6DDUg82eGx2dr7NpvBXstZvw5M6wisVo)", desc.OutputDescriptor)

	// create pegout tx
	pegoutData := types.InputConfidentialTxOut{
		Amount: 1000000000,
		PegoutInput: &types.InputPegoutData{
			OnlineKey:               onlinePrivkey.Hex,
			BitcoinOutputDescriptor: desc.OutputDescriptor,
			Bip32Counter:            addressIndex,
			Whitelist:               whitelist,
		},
	}
	utxos := []*types.ElementsUtxoData{
		{
			OutPoint: types.OutPoint{
				Txid: "4aa201f333e80b8f62ba5b593edb47b4730212e2917b21279f389ba1c14588a3",
				Vout: 0,
			},
			Amount:     2100000000000000,
			Asset:      "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
			Descriptor: "wpkh([d7f351ee/" + utxoPath + "]" + utxoPubkey.Hex + ")",
		},
	}
	changeAddress := "lq1qqwqawne0jyc2swqv9qp8fstrgxuux2824zxkqew9gdak4yudxvwhha0kwdv2p3j0lyekhchrzmuekp94fpfp6fkeggjkerfr8"
	option := types.NewPegoutTxOption()
	option.KnapsackMinChange = 0
	tx, pegoutAddr, unblindTx, err := pegoutApi.CreatePegoutTransaction(utxos, pegoutData, nil, &changeAddress, &option)
	assert.NoError(t, err)
	assert.Equal(t, "1D4YiPF4k9qotSS3QWMa2E8Bt4jV9SZPmE", pegoutAddr.Address)

	// output check
	_, inList, outList, err := txApi.GetAll(tx, false)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(inList))
	assert.Equal(t, 4, len(outList)) // pegout, fee, change, dummy
	// If the dummy output is blinded, the rangeproof will be small because the CT value cannot be high.
	assert.Less(t, 15330, len(tx.Hex))
	assert.Greater(t, 15340, len(tx.Hex))
	_, _, unblindTxoutList, err := txApi.GetAll(unblindTx, false)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), unblindTxoutList[1].Amount)

	pegoutAddress, hasPegout, err := txApi.GetPegoutAddress(tx, uint32(0))
	assert.NoError(t, err)
	assert.True(t, hasPegout)
	assert.Equal(t, pegoutAddr.Address, pegoutAddress.Address)

	// get sighash
	signUtxos, err := txApi.FilterUtxoByTxInList(tx, utxos)
	assert.NoError(t, err)
	utxoDesc := &types.Descriptor{OutputDescriptor: signUtxos[0].Descriptor}
	sighash, err := txApi.GetSighash(tx, &utxos[0].OutPoint, types.SigHashTypeAll, signUtxos)
	assert.NoError(t, err)

	// calc signature
	signature, err := privkeyApi.CreateEcSignature(utxoPrivkey, sighash, &types.SigHashTypeAll)
	assert.NoError(t, err)

	// verify signature
	isVerify, err := pegoutApi.VerifyPubkeySignature(tx, utxos[0], signature)
	assert.NoError(t, err)
	assert.True(t, isVerify)

	// add sign
	err = txApi.AddPubkeySignByDescriptor(tx, &utxos[0].OutPoint, utxoDesc, signature.ToHex())
	assert.NoError(t, err)

	// verify (after sign)
	isVerify, reason, err := txApi.VerifySign(tx, &utxos[0].OutPoint, signUtxos)
	assert.NoError(t, err)
	assert.True(t, isVerify)
	assert.Equal(t, "", reason)
	// assert.Equal(t, "", tx.Hex)

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

func TestPegoutServiceOverrideApiByMock(t *testing.T) {
	config.SetCfdConfig(config.CfdConfig{
		Network:                 types.ElementsRegtest,
		BitcoinGenesisBlockHash: "000088f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
		BitcoinAssetId:          "0000f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
	})
	curConfig := config.CfdConfig{
		Network:                 types.NewNetworkTypeByString("liquidv1"),
		BitcoinGenesisBlockHash: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
		BitcoinAssetId:          "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
	}
	confOpts := curConfig.GetOptions()

	// pegoutApi := (Pegout)(NewPegoutService())
	// keyApi := (key.PrivkeyApi)(key.NewPrivkeyApi())
	myDescObj := NewDescriptorApiParserMock(curConfig.Network)
	xprvApi := key.NewExtPrivkeyApi(confOpts...)
	assert.NoError(t, xprvApi.GetError())
	for _, errItem := range cfdErrors.GetErrors(xprvApi.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}
	privkeyApi := key.NewPrivkeyApi(confOpts...)
	assert.NoError(t, privkeyApi.GetError())
	for _, errItem := range cfdErrors.GetErrors(privkeyApi.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}
	txApi := transaction.NewConfidentialTxApi(confOpts...)
	assert.NoError(t, txApi.GetError())
	for _, errItem := range cfdErrors.GetErrors(txApi.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}
	pegoutApi := NewPegoutService(confOpts...).WithElementsDescriptorApi(myDescObj)
	assert.NoError(t, pegoutApi.GetError())
	for _, errItem := range cfdErrors.GetErrors(pegoutApi.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}

	// key
	// root: xprv9s21ZrQH143K4SS9fUBooJcNan78y4SxCHjma2238tm8pGourqqBZh6pDJHEkksojBRQU4m4kgB1n1dK98tKHKPjxnLyLCUNRK7RgyqDZj7
	accountExtPriv := types.ExtPrivkey{
		Key: "xprv9zFUjcmCAhj2mYvQk1AAJGdrbMTciiBhabGLwLRtMuWjKu7Ab9qUvsjcySjGXZqjWHcZWyKRb92RXcXtCrj541Rr9vDv6WMrZ2vdbMQ98sZ"}
	utxoPath := "0/10"
	utxoExtPriv, err := xprvApi.GetExtPrivkeyByPath(&accountExtPriv, utxoPath)
	assert.NoError(t, err)
	utxoPubkey, err := xprvApi.GetPubkey(utxoExtPriv)
	assert.NoError(t, err)
	assert.Equal(t, "03e68167b077f06fdcef2b1c4b914df53fcdc4ea2ed43852cc3c2abf2b7992b729", utxoPubkey.Hex)
	utxoPrivkey, err := xprvApi.GetPrivkey(utxoExtPriv)
	assert.NoError(t, err)
	assert.Equal(t, "0d96bb6416bf243e35a9969316cbd303e5204be3fbce05c96b8bbc5d7a392c67", utxoPrivkey.Hex)
	assert.Equal(t, "Kwg8FCSKWKdwyKzYTheBAN2SvSNCSCudHBDYJBodidoSsXskGQ3S", utxoPrivkey.Wif)

	onlinePrivkeyWif := "L52AgshDAE14NHJuovwAw8hyrTNK4YQjuiPC9EES4sfM7oBPzU4o"
	onlinePrivkey, err := privkeyApi.GetPrivkeyFromWif(onlinePrivkeyWif)
	// pegoutApi.CreateOnlinePrivateKey()  // generate random privkey
	assert.NoError(t, err)

	// mainchain address descriptor
	// m/44h/0h/1h
	mainchainXpubkey := types.ExtPubkey{Key: "xpub6DEq98J615HL2A5UXP5DVPmEtet7DXAsqQHEBvfbEcwAC9PBKu9cG3tCkU5fXkiaJkeQzc81YiY6DDUg82eGx2dr7NpvBXstZvw5M6wisVo"}
	addressIndex := uint32(0)

	// whitelist
	pakEntry, err := pegoutApi.CreatePakEntry(&mainchainXpubkey, onlinePrivkey)
	assert.NoError(t, err)
	whitelist := pakEntry.ToHex()

	// pegout address
	pegoutAddr, desc, err := pegoutApi.CreatePegoutAddress(types.P2pkhAddress, &mainchainXpubkey, addressIndex)
	assert.NoError(t, err)
	assert.Equal(t, "1D4YiPF4k9qotSS3QWMa2E8Bt4jV9SZPmE", pegoutAddr.Address)
	assert.Equal(t, "pkh(xpub6DEq98J615HL2A5UXP5DVPmEtet7DXAsqQHEBvfbEcwAC9PBKu9cG3tCkU5fXkiaJkeQzc81YiY6DDUg82eGx2dr7NpvBXstZvw5M6wisVo)", desc.OutputDescriptor)

	// create pegout tx
	pegoutData := types.InputConfidentialTxOut{
		Amount: 1000000000,
		PegoutInput: &types.InputPegoutData{
			OnlineKey:               onlinePrivkey.Hex,
			BitcoinOutputDescriptor: desc.OutputDescriptor,
			Bip32Counter:            addressIndex,
			Whitelist:               whitelist,
		},
	}
	utxos := []*types.ElementsUtxoData{
		{
			OutPoint: types.OutPoint{
				Txid: "4aa201f333e80b8f62ba5b593edb47b4730212e2917b21279f389ba1c14588a3",
				Vout: 0,
			},
			Amount:     2100000000000000,
			Asset:      "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225",
			Descriptor: "wpkh([d7f351ee/" + utxoPath + "]" + utxoPubkey.Hex + ")",
		},
	}
	changeAddress := "lq1qqwqawne0jyc2swqv9qp8fstrgxuux2824zxkqew9gdak4yudxvwhha0kwdv2p3j0lyekhchrzmuekp94fpfp6fkeggjkerfr8"
	option := types.NewPegoutTxOption()
	option.KnapsackMinChange = 0
	tx, pegoutAddr, unblindTx, err := pegoutApi.CreatePegoutTransaction(utxos, pegoutData, nil, &changeAddress, &option)
	assert.NoError(t, err)
	assert.Equal(t, "1D4YiPF4k9qotSS3QWMa2E8Bt4jV9SZPmE", pegoutAddr.Address)

	// output check
	_, inList, outList, err := txApi.GetAll(tx, false)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(inList))
	assert.Equal(t, 4, len(outList)) // pegout, fee, change, dummy
	// If the dummy output is blinded, the rangeproof will be small because the CT value cannot be high.
	assert.Less(t, 15330, len(tx.Hex))
	assert.Greater(t, 15340, len(tx.Hex))
	_, _, unblindTxoutList, err := txApi.GetAll(unblindTx, false)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), unblindTxoutList[1].Amount)

	pegoutAddress, hasPegout, err := txApi.GetPegoutAddress(tx, uint32(0))
	assert.NoError(t, err)
	assert.True(t, hasPegout)
	assert.Equal(t, pegoutAddr.Address, pegoutAddress.Address)

	// get sighash
	signUtxos, err := txApi.FilterUtxoByTxInList(tx, utxos)
	assert.NoError(t, err)
	// utxoDesc := &types.Descriptor{OutputDescriptor: signUtxos[0].Descriptor}
	sighash, err := txApi.GetSighash(tx, &utxos[0].OutPoint, types.SigHashTypeAll, signUtxos)
	assert.NoError(t, err)

	// calc signature
	signature, err := privkeyApi.CreateEcSignature(utxoPrivkey, sighash, &types.SigHashTypeAll)
	assert.NoError(t, err)

	// verify signature
	isVerify, err := pegoutApi.VerifyPubkeySignature(tx, utxos[0], signature)
	assert.Error(t, err)
	// assert.NoError(t, err)
	assert.Contains(t, err.Error(), DescriptorParseMockErrorMessage)
	assert.False(t, isVerify)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestContainsPakEntry(t *testing.T) {
	opt := config.NetworkOption(types.LiquidV1)
	pegout := NewPegoutService(opt)
	assert.NoError(t, pegout.GetError())

	pakEntry := types.NewByteDataFromHexIgnoreError(
		"03f79461a5559f360c407069b92a8075958bf1f70918872d9dd702db145bccbd420395058fc702f126176ae13e0ebed05107288900a5a35b121f62923e58798b7b2f")

	whitelist1 := "02555f97c44ad9286ef060a02b00e8e6be2626ed3eb9230705d3ca2f977daae61e03cddbc847f64f898b883d717a7f637bedf9ac2ecd243721eada223f1b1790f75b033fad80bd2b818d1ca8a8d4a25dafcf5e740be07db6788be1f2f15266e3c6805d0253ff3f140ef8f594d54996eab810a82550c79204279920d95681afe699d00da503f2d35e88741f930a3938bfa7075377ec2da4f1d7699a779e2cbf7a389195dc67026132199a025299b5e0f4ab3f44294c81c5302f6d45ddda6316c18ae515793cf6036286d30d20ddcd3e867851936802dd8a2d84846c7e52aece0fc303c6deec9e0402c7581da9d9ac0001e1c560c348b5df07d42de166d74eccd4c3bda467fe84f8980327b1884b3d743f4859db7c2df07e6e346d61d77fbc46c1da6db113fbbd43d7c50383c832ec502cf0990b199a4e46a45a63bfa6c6eb3f4b231472f144e684d6e9f803075f118532928c7ef27a77644a12a87fbada3cd94cf67b2d2ae5cb169ddaefa402882c4fed938b20f3472af337cd7674a99f0aab0ae1803e27e978c52c417ce5e102b988448e337c15cd6ac82b4737e3e2b5e92947da2f7fa96a81db7f9be3fabeb202f660c7675a1ed4893df838a5c4c07a287997cbd7dc5d884044b338ed606231bc0245b763999e3152418b9cd08b5f54c410a072d5e486826823791848e1bb8790610259740ea12e953db0c5fd135c1a9564ce81a318729668811cf54f884c2f980eb8032f8814144351d5d05ca40c87cbbda67bb5f8b1920a38cf3bd008c1d266bb4682039eb3a0b89656b338c3f4a9fc7bba582dd21935f59471c18e6b43c57e063053d903d8b2ed1813370955cfb8dec24b7c5cb34b13fa4545d9e6d47d8c05af56a2c7d2026392f13fefce606c60adadfe9e729e0af84f5f8cb6a35b76be244351635b38f703e2a56e47f41eb83af34fb65c4dfb77ac442b01b5134fd92219bd3f4a999c7de5034e93391cea816e5141dace7e5477bbed90c9daa0670b68b7acc8a44af556bbc103156b39a4bce80e68c1582aa78f81f0252ccbb039766b5395ee9a0224f41c236d0399a5d1d42f5b6cb587560394e1581eb0c76916db317c0d644a1b9f509a06c4e6029797b15de24dc43a6556e58159c5aa0b69ea390ccdebcd7be10751d8085da08f03248e52371b2c3bce2478a3c3aaf37e4f0d6ba711e058ba407f44fdaaf280ac9503d6a14ab496777401e2eae7992404011537860af7b46c3a8fdea65d29fe4bf26c02dca82e552228f3808b1ea9b38b3342b51e9453dcb1414c551ce08bd726311e30035c9c770ed88e29b364038d68b1c623fbf71e93e6d5357e278e9b64160984ed3c02659aabb69b8413bc46026830ad1e2284901350a75c2bc97906f49cff01503f0f02a8300f0cff92b23e402459e83c52ec5824de82ee4004cf9d254e788304027ef60389cbda672fa9efea51706863f1d7ae5e5015b2e519003ef0178c99f71be6e8be03fcba7ecf41bc7e1be4ee122d9d22e3333671eb0a3a87b5cdf099d59874e1940f02b0fb4fe4670c68329441e47acaaa954ff00e3fd547b9ff4e0fe547df2e775ec50335f807a1bdc0906adda1a4166f9cdc2aa974a78b15fc29d79a8d7ca529a9600802228dfd7ff95506dd67b1118803eb8ab49352b2e24cd5f38da043847e722009ba03fcc2963daaf8249bfd220e52c693626254b9295ac4f947ae2e0cddb3046724c102dac03530ac9712a71eafb87766644b61cf4be85d0fdc6a859875b41e7a1dc8e602d67fcb027c5d8fe354fb36235192cb4fffabffdcc6ce74be255fe869f62d867503d61d857b2a8cb060fd4b9a98a862f250df5825068665a3c8d93f2ac8a708588802cddb51ea42acf38762418939be0a9227f0212ff96a870a2c1d85ec65905a762903d986a2181a38cfef5b5e2a1915aa2d37f193fcbafab9bf311d6138209f316f5b029ec6dd0c310513b3720800025a7ad9013d60a7fb041f6e9b9d3963485ba286570277247f28eb9481dd21d664093a2bc19a496c7ffebeca0026a1726a5041e671ba03f9dea372c4a667dcfe234ff8e0410c22341149ff7d8780c46954ff74998fbe440340c4e534906c06b73874cef00a880ab602641c7883de94296f0f601e6517ae7e027661f1530dfc88b34b0c8f606d215f30fb0edfa116b331ff44b2fbe040893c6f029d3160731eddc316121b2a31c82270baa4bbe7f08549891af3b444eb690b2df103f79461a5559f360c407069b92a8075958bf1f70918872d9dd702db145bccbd420395058fc702f126176ae13e0ebed05107288900a5a35b121f62923e58798b7b2f02d7f049d9e87c861fc9decfbe167cb13ccc87cce99113f69e3a5dca8bb71b6aed03e82197b2e9cc0ee11a59808cfdb52e824445f8fa99e44dc9c30d1e49950ff9d60281bfeffcc6841d1355dce039f5d64f72714a4c3adc4d351eaf3c28acbcee15f00270a16ee1cdfc78755a783efbdb66fe822605cc5f53af707e5038615e22b288e2022d58f7f198f3fe7e0ae45f93aa28fdb483ac25a258663ac593860e11ac1d1abc035049635f866b921f7cd0481c6165f19e14ba52c67f7c4fade1dcd22f9aacea2002d40ea20996c882a75fd8cd433484bd8af92791752b4c2d2f24660de36a9f3f8202d874a87df633068c2eacceed3345ce5fb2dbc9f94c30b93ef4c844a77f2651c0024158f76e16888a49492d4913e45c1b4cba19d87dd5bd24346ef601d31d0625370366e9ad4ce16b65a95fb63aae98fdff6bcbd31816d6336039e529a40a828e985102d2283a929584cdf557096a7f473ae25c04fd6f73467657c4bc49dfb3095892bd03599136ea1f66a80a2eb1a144458561f4791d2fc5fcd06e32a88c9cb2976c8aac036f4b5f3ae46163fb53b0d6c19c78ea2fdf49c8b419c354f3c24fa1ce9547e6b80340a79f2477ff2a077fb0b8ebb96714a9aaf242f4b96253260264ed031f2a7ee402d6825aaa063083567f6d4f35ea62c2af8d34f67ef4c2afa565791fd7efc5f3a602b1e0d671f91f756a7613797d84c33daddc1dc1df9badf68d4e2c2216a288c92303effb766a6f3729c220b0ffa156ffa66d656e5ec16f15bc513b8d0b1298c761d20252831192e573788271e235afca8f72736d97e26b3a1406cac34711b6ab670c26038c245fa632a0b6c2712cbadb6f6e346284ee0fba3202875abd774faee2deca29032ff781357db141528b1c7ea2cfed3ebe6bb9a028954665cfba355bbcf3d14c8e0356c22fab025b3e661331ed4dcf8645a4a4fd4a2cae69680339e05df209ef4556032d60805593864388d073193fb9fcf66c389813778dcd4a2e93c8fd164d387f7f0238de9c098e83c4d244294ac394355c8e80b49af10f7c1e23001e6c88be5d45b803bc04885be94ceffbac90178ef18d4dd6958d7488f7861f0994c659412d9e9463025651f14b6347a000e15473eaf631fd78c9307e07db85e177e31fcde0b3f2a57403d5303909fe1c6665cbc96a538b17274068c8e79757705f68db3df2b561a4c11003627a4855be1edc657927f30a4a869ad830041c1f0e74ab4670588af9532b8de803444cb85aef9fbba10b3e2662d533858db771010b57b7aedb1ecaa1c5a34918f1032d9af13c8d5f5316fd27a14bafb8ec55684ef2e3b5c64b2645e088f570e5d2cb0239590f39508465decfd8a1bdc61b42333297e80588ed826ddd43678edfa6caae"

	whitelist2 := "03f79461a5559f360c407069b92a8075958bf1f70918872d9dd702db145bccbd420395058fc702f126176ae13e0ebed05107288900a5a35b121f62923e58798b7b2c"
	whitelist3 := "03f79461a5559f360c40706903f79461a5559f360c407069b92a8075958bf1f70918872d9dd702db145bccbd420395058fc702f126176ae13e0ebed05107288900a5a35b121f62923e58798b7b2fb92a8075958bf1f70918872d9dd702db145bccbd420395058fc702f126176ae13e0ebed05107288900a5a35b121f62923e58798b7b2c"

	exist, err := pegout.ContainsPakEntry(pakEntry, whitelist1)
	assert.NoError(t, err)
	assert.True(t, exist)

	exist, err = pegout.ContainsPakEntry(pakEntry, whitelist2)
	assert.NoError(t, err)
	assert.False(t, exist)

	exist, err = pegout.ContainsPakEntry(pakEntry, whitelist3)
	assert.NoError(t, err)
	assert.False(t, exist)

	exist, err = pegout.ContainsPakEntry(pakEntry, "11112222")
	assert.Error(t, err)
	if err != nil {
		assert.Contains(t, err.Error(), "Invalid whitelist error")
	}
	assert.False(t, exist)

	exist, err = pegout.ContainsPakEntry(nil, whitelist3)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), cfdErrors.ErrParameterNil.Error())
	assert.False(t, exist)

	fmt.Printf("%s test done.\n", GetFuncName())
}
