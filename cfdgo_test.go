package cfdgo

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// first test
func TestInitialize(t *testing.T) {
	ret := CfdInitialize()
	assert.Equal(t, (int)(KCfdSuccess), ret)
	fmt.Print("TestInitialize test done.\n")
}

func TestCfdCreateHandle(t *testing.T) {
	ret := CfdCreateHandle(nil)
	assert.Equal(t, (int)(KCfdIllegalArgumentError), ret)

	handle, err := CfdGoCreateHandle()
	assert.NoError(t, err)

	err = CfdGoFreeHandle(handle)
	assert.NoError(t, err)
	fmt.Print("TestCfdCreateHandle test done.\n")
}

func TestCfdGetLastError(t *testing.T) {
	handle, err := CfdGoCreateHandle()
	assert.NoError(t, err)

	lastErr := CfdGetLastErrorCode(handle)
	assert.Equal(t, (int)(KCfdSuccess), lastErr)

	errMsg, err := CfdGoGetLastErrorMessage(handle)
	assert.NoError(t, err)
	assert.Equal(t, "", errMsg)

	_, _, _, err = CfdGoCreateAddress(handle, 200, "", "", 200)
	lastErr = CfdGetLastErrorCode(handle)
	assert.Equal(t, (int)(KCfdIllegalArgumentError), lastErr)
	assert.Error(t, err)
	errMsg, _ = CfdGoGetLastErrorMessage(handle)
	assert.Equal(t, "Illegal network type.", errMsg)

	err = CfdGoFreeHandle(handle)
	assert.NoError(t, err)
	fmt.Print("TestCfdGetLastError test done.\n")
}

func TestCfdGetSupportedFunction(t *testing.T) {
	handle, err := CfdGoCreateHandle()
	assert.NoError(t, err)

	flag, err := CfdGoGetSupportedFunction()
	assert.NoError(t, err)
	assert.Equal(t, uint64(1), (flag & 0x01))

	err = CfdGoFreeHandle(handle)
	assert.NoError(t, err)
	fmt.Print("TestCfdGetSupportedFunction test done.\n")
}

func TestCfdGoCreateAddress(t *testing.T) {
	handle, err := CfdGoCreateHandle()
	assert.NoError(t, err)

	hashType := (int)(KCfdP2pkh)
	networkType := (int)(KCfdNetworkLiquidv1)
	pubkey := "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
	address, lockingScript, segwitLockingScript, err := CfdGoCreateAddress(handle, hashType, pubkey, "", networkType)
	assert.NoError(t, err)
	assert.Equal(t, "Q7wegLt2qMGhm28vch6VTzvpzs8KXvs4X7", address)
	assert.Equal(t, "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac", lockingScript)
	assert.Equal(t, "", segwitLockingScript)
	if err != nil {
		errStr, _ := CfdGoGetLastErrorMessage(handle)
		fmt.Print("[error message] " + errStr + "\n")
	}

	hashType = (int)(KCfdP2sh)
	redeemScript := "210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac"
	address, lockingScript, segwitLockingScript, err = CfdGoCreateAddress(
		handle, hashType, "", redeemScript, networkType)
	assert.NoError(t, err)
	assert.Equal(t, "GkSEheszYzEBMgX9G9ueaAyLVg8gfZwiDY", address)
	assert.Equal(t, "a91423b0ad3477f2178bc0b3eed26e4e6316f4e83aa187", lockingScript)
	assert.Equal(t, "", segwitLockingScript)
	if err != nil {
		errStr, _ := CfdGoGetLastErrorMessage(handle)
		fmt.Print("[error message] " + errStr + "\n")
	}

	hashType = (int)(KCfdP2shP2wpkh)
	pubkey = "0205ffcdde75f262d66ada3dd877c7471f8f8ee9ee24d917c3e18d01cee458bafe"
	address, lockingScript, segwitLockingScript, err = CfdGoCreateAddress(
		handle, hashType, pubkey, "", networkType)
	assert.NoError(t, err)
	assert.Equal(t, "GsaK3GXnFAjdfZDBPPo9PD6UNyAJ53nS9Z", address)
	assert.Equal(t, "a9147200818f884ee12b964442b059c11d0712b6abe787", lockingScript)
	assert.Equal(t, "0014ef692e4bf0cd5ed05235a4fc582ec4a4ff9695b4", segwitLockingScript)
	if err != nil {
		errStr, _ := CfdGoGetLastErrorMessage(handle)
		fmt.Print("[error message] " + errStr + "\n")
	}

	hashType = (int)(KCfdP2wpkh)
	networkType = (int)(KCfdNetworkElementsRegtest)
	pubkey = "02bedf98a38247c1718fdff7e07561b4dc15f10323ebb0accab581778e72c2e995"
	address, lockingScript, segwitLockingScript, err = CfdGoCreateAddress(
		handle, hashType, pubkey, "", networkType)
	assert.NoError(t, err)
	assert.Equal(t, "ert1qs58jzsgjsteydejyhy32p2v2vm8llh9uns6d93", address)
	assert.Equal(t, "0014850f21411282f246e644b922a0a98a66cfffdcbc", lockingScript)
	assert.Equal(t, "", segwitLockingScript)
	if err != nil {
		errMsg, _ := CfdGoGetLastErrorMessage(handle)
		fmt.Print("[error message] " + errMsg + "\n")
	}

	err = CfdGoFreeHandle(handle)
	assert.NoError(t, err)
	fmt.Print("TestCfdGoCreateAddress test done.\n")
}

func TestCfdGoCreateMultisigScript(t *testing.T) {
	handle, err := CfdGoCreateHandle()
	assert.NoError(t, err)

	networkType := (int)(KCfdNetworkLiquidv1)
	hashType := (int)(KCfdP2shP2wsh)
	pubkeys := []string{"0205ffcdde75f262d66ada3dd877c7471f8f8ee9ee24d917c3e18d01cee458bafe", "02be61f4350b4ae7544f99649a917f48ba16cf48c983ac1599774958d88ad17ec5"}
	address, redeemScript, witnessScript, err := CfdGoCreateMultisigScript(handle, networkType, hashType, pubkeys, uint32(2))
	assert.NoError(t, err)
	assert.Equal(t, "H4PB6YPgiTmQLiMU7b772LMFY9vA4gSUC1", address)
	assert.Equal(t, "0020f39f6272ba6b57918eb047c5dc44fb475356b0f24c12fca39b19284e80008a42", redeemScript)
	assert.Equal(t, "52210205ffcdde75f262d66ada3dd877c7471f8f8ee9ee24d917c3e18d01cee458bafe2102be61f4350b4ae7544f99649a917f48ba16cf48c983ac1599774958d88ad17ec552ae", witnessScript)
	if err != nil {
		errMsg, _ := CfdGoGetLastErrorMessage(handle)
		fmt.Print("[error message] " + errMsg + "\n")
	}

	err = CfdGoFreeHandle(handle)
	assert.NoError(t, err)
	fmt.Print("TestCfdGoCreateMultisigScript test done.\n")
}

func TestCfdGoGetAddressesFromMultisig(t *testing.T) {
	handle, err := CfdGoCreateHandle()
	assert.NoError(t, err)

	networkType := (int)(KCfdNetworkLiquidv1)
	hashType := (int)(KCfdP2shP2wpkh)
	redeemScript := "52210205ffcdde75f262d66ada3dd877c7471f8f8ee9ee24d917c3e18d01cee458bafe2102be61f4350b4ae7544f99649a917f48ba16cf48c983ac1599774958d88ad17ec552ae"
	addressList, pubkeyList, err := CfdGoGetAddressesFromMultisig(handle, redeemScript, networkType, hashType)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(addressList))
	assert.Equal(t, 2, len(pubkeyList))
	if len(addressList) == 2 {
		assert.Equal(t, "GsaK3GXnFAjdfZDBPPo9PD6UNyAJ53nS9Z", addressList[0])
		assert.Equal(t, "GzGfkxAuJGSE7TL8KgMYmBRftjHPEFTSzS", addressList[1])
	}
	if len(pubkeyList) == 2 {
		assert.Equal(t, "0205ffcdde75f262d66ada3dd877c7471f8f8ee9ee24d917c3e18d01cee458bafe", pubkeyList[0])
		assert.Equal(t, "02be61f4350b4ae7544f99649a917f48ba16cf48c983ac1599774958d88ad17ec5", pubkeyList[1])
	}
	if err != nil {
		errMsg, _ := CfdGoGetLastErrorMessage(handle)
		fmt.Print("[error message] " + errMsg + "\n")
	}

	err = CfdGoFreeHandle(handle)
	assert.NoError(t, err)
	fmt.Print("TestCfdGoGetAddressesFromMultisig test done.\n")
}

func TestCfdGoGetAddressFromLockingScript(t *testing.T) {
	handle, err := CfdGoCreateHandle()
	assert.NoError(t, err)

	networkType := (int)(KCfdNetworkLiquidv1)
	lockingScript := "76a91449a011f97ba520dab063f309bad59daeb30de10188ac"
	address, err := CfdGoGetAddressFromLockingScript(handle, lockingScript, networkType)
	assert.NoError(t, err)
	assert.Equal(t, "Q3ygD4rfNT2npj341csKqxcgDkBMwyD5Z6", address)

	lockingScript = "a914f1b3a2cc24eba8a741f963b309a7686f3bb6bfb487"
	address, err = CfdGoGetAddressFromLockingScript(handle, lockingScript, networkType)
	assert.NoError(t, err)
	assert.Equal(t, "H5DXSnmWy4WuUU7Yr8bvtLa5nXgukNc3Z6", address)

	lockingScript = "0014925d4028880bd0c9d68fbc7fc7dfee976698629c"
	address, err = CfdGoGetAddressFromLockingScript(handle, lockingScript, networkType)
	assert.NoError(t, err)
	assert.Equal(t, "ex1qjfw5q2ygp0gvn450h3lu0hlwjanfsc5uh0r5gq", address)

	lockingScript = "002087cb0bc07de5b5befd7565b2c63fb1681efd8af7bd85a3f0f98a529a5c50a437"
	address, err = CfdGoGetAddressFromLockingScript(handle, lockingScript, networkType)
	assert.NoError(t, err)
	assert.Equal(t, "ex1qsl9shsrauk6malt4vkevv0a3dq00mzhhhkz68u8e3fff5hzs5sms77zw4m", address)

	err = CfdGoFreeHandle(handle)
	assert.NoError(t, err)
	fmt.Print("TestCfdGoGetAddressesFromMultisig test done.\n")
}

func TestCfdGoParseDescriptor(t *testing.T) {
	handle, err := CfdGoCreateHandle()
	assert.NoError(t, err)

	// PKH
	networkType := (int)(KCfdNetworkLiquidv1)
	descriptorDataList, multisigList, err := CfdGoParseDescriptor(handle,
		"pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)",
		networkType,
		"")
	assert.NoError(t, err)
	assert.Equal(t, 1, len(descriptorDataList))
	assert.Equal(t, 0, len(multisigList))
	if len(descriptorDataList) == 1 {
		assert.Equal(t, uint32(0), descriptorDataList[0].Depth)
		assert.Equal(t, (int)(KCfdDescriptorScriptPkh), descriptorDataList[0].ScriptType)
		assert.Equal(t, "76a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac", descriptorDataList[0].LockingScript)
		assert.Equal(t, "PwsjpD1YkjcfZ95WGVZuvGfypkKmpogoA3", descriptorDataList[0].Address)
		assert.Equal(t, (int)(KCfdP2pkh), descriptorDataList[0].HashType)
		assert.Equal(t, "", descriptorDataList[0].RedeemScript)
		assert.Equal(t, (int)(KCfdDescriptorKeyPublic), descriptorDataList[0].KeyType)
		assert.Equal(t, "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5", descriptorDataList[0].Pubkey)
		assert.Equal(t, "", descriptorDataList[0].ExtPubkey)
		assert.Equal(t, "", descriptorDataList[0].ExtPrivkey)
		assert.Equal(t, false, descriptorDataList[0].IsMultisig)
		assert.Equal(t, uint32(0), descriptorDataList[0].ReqSigNum)
	}
	if err != nil {
		errMsg, _ := CfdGoGetLastErrorMessage(handle)
		fmt.Print("[error message] " + errMsg + "\n")
	}

	// p2sh-p2wsh(pkh)
	networkType = (int)(KCfdNetworkLiquidv1)
	descriptorDataList, multisigList, err = CfdGoParseDescriptor(handle,
		"sh(wsh(pkh(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13)))",
		networkType, "")
	assert.NoError(t, err)
	assert.Equal(t, 3, len(descriptorDataList))
	assert.Equal(t, 0, len(multisigList))
	if len(descriptorDataList) == 3 {
		// 0
		assert.Equal(t, uint32(0), descriptorDataList[0].Depth)
		assert.Equal(t, (int)(KCfdDescriptorScriptSh), descriptorDataList[0].ScriptType)
		assert.Equal(t, "a91455e8d5e8ee4f3604aba23c71c2684fa0a56a3a1287", descriptorDataList[0].LockingScript)
		assert.Equal(t, "Gq1mmExLuSEwfzzk6YtUxJ769grv6T5Tak", descriptorDataList[0].Address)
		assert.Equal(t, (int)(KCfdP2shP2wsh), descriptorDataList[0].HashType)
		assert.Equal(t, "0020fc5acc302aab97f821f9a61e1cc572e7968a603551e95d4ba12b51df6581482f", descriptorDataList[0].RedeemScript)
		assert.Equal(t, (int)(KCfdDescriptorKeyNull), descriptorDataList[0].KeyType)
		assert.Equal(t, "", descriptorDataList[0].Pubkey)
		assert.Equal(t, "", descriptorDataList[0].ExtPubkey)
		assert.Equal(t, "", descriptorDataList[0].ExtPrivkey)
		assert.Equal(t, false, descriptorDataList[0].IsMultisig)
		assert.Equal(t, uint32(0), descriptorDataList[0].ReqSigNum)
		// 1
		assert.Equal(t, uint32(1), descriptorDataList[1].Depth)
		assert.Equal(t, (int)(KCfdDescriptorScriptWsh), descriptorDataList[1].ScriptType)
		assert.Equal(t, "0020fc5acc302aab97f821f9a61e1cc572e7968a603551e95d4ba12b51df6581482f", descriptorDataList[1].LockingScript)
		assert.Equal(t, "ex1ql3dvcvp24wtlsg0e5c0pe3tju7tg5cp428546jap9dga7evpfqhs0htdlf", descriptorDataList[1].Address)
		assert.Equal(t, (int)(KCfdP2wsh), descriptorDataList[1].HashType)
		assert.Equal(t, "76a914c42e7ef92fdb603af844d064faad95db9bcdfd3d88ac", descriptorDataList[1].RedeemScript)
		assert.Equal(t, (int)(KCfdDescriptorKeyNull), descriptorDataList[1].KeyType)
		assert.Equal(t, "", descriptorDataList[1].Pubkey)
		assert.Equal(t, "", descriptorDataList[1].ExtPubkey)
		assert.Equal(t, "", descriptorDataList[1].ExtPrivkey)
		assert.Equal(t, false, descriptorDataList[1].IsMultisig)
		assert.Equal(t, uint32(0), descriptorDataList[1].ReqSigNum)
		// 2
		assert.Equal(t, uint32(2), descriptorDataList[2].Depth)
		assert.Equal(t, (int)(KCfdDescriptorScriptPkh), descriptorDataList[2].ScriptType)
		assert.Equal(t, "76a914c42e7ef92fdb603af844d064faad95db9bcdfd3d88ac", descriptorDataList[2].LockingScript)
		assert.Equal(t, "QF9hGPQMVAPc8RxTHALgSvNPWEjGbL9bse", descriptorDataList[2].Address)
		assert.Equal(t, (int)(KCfdP2pkh), descriptorDataList[2].HashType)
		assert.Equal(t, "", descriptorDataList[2].RedeemScript)
		assert.Equal(t, (int)(KCfdDescriptorKeyPublic), descriptorDataList[2].KeyType)
		assert.Equal(t, "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13", descriptorDataList[2].Pubkey)
		assert.Equal(t, "", descriptorDataList[2].ExtPubkey)
		assert.Equal(t, "", descriptorDataList[2].ExtPrivkey)
		assert.Equal(t, false, descriptorDataList[2].IsMultisig)
		assert.Equal(t, uint32(0), descriptorDataList[2].ReqSigNum)
	}
	if err != nil {
		errMsg, _ := CfdGoGetLastErrorMessage(handle)
		fmt.Print("[error message] " + errMsg + "\n")
	}

	// multisig (bitcoin)
	networkType = (int)(KCfdNetworkMainnet)
	descriptorDataList, multisigList, err = CfdGoParseDescriptor(handle,
		"wsh(multi(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))",
		networkType,
		"0")
	assert.NoError(t, err)
	assert.Equal(t, 1, len(descriptorDataList))
	assert.Equal(t, 2, len(multisigList))
	if len(descriptorDataList) == 1 {
		assert.Equal(t, uint32(0), descriptorDataList[0].Depth)
		assert.Equal(t, (int)(KCfdDescriptorScriptWsh), descriptorDataList[0].ScriptType)
		assert.Equal(t, "002064969d8cdca2aa0bb72cfe88427612878db98a5f07f9a7ec6ec87b85e9f9208b", descriptorDataList[0].LockingScript)
		assert.Equal(t, "bc1qvjtfmrxu524qhdevl6yyyasjs7xmnzjlqlu60mrwepact60eyz9s9xjw0c", descriptorDataList[0].Address)
		assert.Equal(t, (int)(KCfdP2wsh), descriptorDataList[0].HashType)
		assert.Equal(t, "51210205f8f73d8a553ad3287a506dbd53ed176cadeb200c8e4f7d68a001b1aed871062102c04c4e03921809fcbef9a26da2d62b19b2b4eb383b3e6cfaaef6370e7514477452ae", descriptorDataList[0].RedeemScript)
		assert.Equal(t, (int)(KCfdDescriptorKeyNull), descriptorDataList[0].KeyType)
		assert.Equal(t, "", descriptorDataList[0].Pubkey)
		assert.Equal(t, "", descriptorDataList[0].ExtPubkey)
		assert.Equal(t, "", descriptorDataList[0].ExtPrivkey)
		assert.Equal(t, true, descriptorDataList[0].IsMultisig)
		assert.Equal(t, uint32(1), descriptorDataList[0].ReqSigNum)
	}
	if len(multisigList) == 2 {
		assert.Equal(t, (int)(KCfdDescriptorKeyBip32), multisigList[0].KeyType)
		assert.Equal(t, "0205f8f73d8a553ad3287a506dbd53ed176cadeb200c8e4f7d68a001b1aed87106", multisigList[0].Pubkey)
		assert.Equal(t, "xpub6BgWskLoyHmAUeKWgUXCGfDdCMRXseEjRCMEMvjkedmHpnvWtpXMaCRm8qcADw9einPR8o2c49ZpeHRZP4uYwGeMU2T63G7uf2Y1qJavrWQ", multisigList[0].ExtPubkey)
		assert.Equal(t, "", multisigList[0].ExtPrivkey)
		assert.Equal(t, (int)(KCfdDescriptorKeyBip32), multisigList[1].KeyType)
		assert.Equal(t, "02c04c4e03921809fcbef9a26da2d62b19b2b4eb383b3e6cfaaef6370e75144774", multisigList[1].Pubkey)
		assert.Equal(t, "xpub6EKMC2gSMfKgQJ3iNMZVNB4GLH1Dc4hNPah1iMbbztxdUPRo84MMcTgkPATWNRyzr7WifKrt5VvQi4GEqRwybCP1LHoXBKLN6cB15HuBKPE", multisigList[1].ExtPubkey)
		assert.Equal(t, "", multisigList[1].ExtPrivkey)
	}
	if err != nil {
		errMsg, _ := CfdGoGetLastErrorMessage(handle)
		fmt.Print("[error message] " + errMsg + "\n")
	}

	err = CfdGoFreeHandle(handle)
	assert.NoError(t, err)
	fmt.Print("TestCfdGoParseDescriptor test done.\n")
}

func TestCfdCreateRawTransaction(t *testing.T) {
	handle, err := CfdGoCreateHandle()
	assert.NoError(t, err)

	txHex, err := CfdGoInitializeConfidentialTx(handle, uint32(2), uint32(0))
	assert.NoError(t, err)
	assert.Equal(t, "0200000000000000000000", txHex)

	sequence := (uint32)(KCfdSequenceLockTimeDisable)
	if err == nil {
		txHex, err = CfdGoAddConfidentialTxIn(
			handle, txHex,
			"7461b02405414d79e79a5050684a333c922c1136f4bdff5fb94b551394edebbd", 0,
			sequence)
		assert.NoError(t, err)
		assert.Equal(t, "020000000001bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffff0000000000", txHex)
	}

	if err == nil {
		txHex, err = CfdGoAddConfidentialTxIn(
			handle, txHex,
			"1497e1f146bc5fe00b6268ea16a7069ecb90a2a41a183446d5df8965d2356dc1", 1,
			sequence)
		assert.NoError(t, err)
		assert.Equal(t, "020000000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff0000000000", txHex)
	}

	if err == nil {
		txHex, err = CfdGoAddConfidentialTxOut(
			handle, txHex,
			"ef47c42d34de1b06a02212e8061323f50d5f02ceed202f1cb375932aa299f751",
			int64(100000000), "",
			"CTEw7oSCUWDfmfhCEdsB3gsG7D9b4xLCZEq71H8JxRFeBu7yQN3CbSF6qT6J4F7qji4bq1jVSdVcqvRJ",
			"", "")
		assert.NoError(t, err)
		assert.Equal(t, "020000000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff010151f799a22a9375b31c2f20edce025f0df5231306e81222a0061bde342dc447ef010000000005f5e10003a630456ab6d50b57981e085abced70e2816289ae2b49a44c2f471b205134c12b1976a914d08f5ba8874d36cf97d19379b370f1f23ba36d5888ac00000000", txHex)
	}

	if err == nil {
		txHex, err = CfdGoAddConfidentialTxOut(
			handle, txHex,
			"6f1a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3",
			int64(1900500000), "",
			"2dxZw5iVZ6Pmqoc5Vn8gkUWDGB5dXuMBCmM", "", "")
		assert.NoError(t, err)
		assert.Equal(t, "020000000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff020151f799a22a9375b31c2f20edce025f0df5231306e81222a0061bde342dc447ef010000000005f5e10003a630456ab6d50b57981e085abced70e2816289ae2b49a44c2f471b205134c12b1976a914d08f5ba8874d36cf97d19379b370f1f23ba36d5888ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f010000000071475420001976a914fdd725970db682de970e7669646ed7afb8348ea188ac00000000", txHex)
	}

	if err == nil {
		txHex, err = CfdGoAddConfidentialTxOut(
			handle, txHex,
			"6f1a4b6bd5571b5f08ab79c314dc6483f9b952af2f5ef206cd6f8e68eb1186f3",
			int64(500000), "", "", "", "")
		assert.NoError(t, err)
		assert.Equal(t, "020000000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff030151f799a22a9375b31c2f20edce025f0df5231306e81222a0061bde342dc447ef010000000005f5e10003a630456ab6d50b57981e085abced70e2816289ae2b49a44c2f471b205134c12b1976a914d08f5ba8874d36cf97d19379b370f1f23ba36d5888ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f010000000071475420001976a914fdd725970db682de970e7669646ed7afb8348ea188ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f01000000000007a120000000000000", txHex)
	}

	if err == nil {
		txHex, err = CfdGoAddDestoryConfidentialTxOut(
			handle, txHex,
			"ef47c42d34de1b06a02212e8061323f50d5f02ceed202f1cb375932aa299f751",
			int64(50000000), "",
			"")
		assert.NoError(t, err)
		assert.Equal(t, "020000000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff040151f799a22a9375b31c2f20edce025f0df5231306e81222a0061bde342dc447ef010000000005f5e10003a630456ab6d50b57981e085abced70e2816289ae2b49a44c2f471b205134c12b1976a914d08f5ba8874d36cf97d19379b370f1f23ba36d5888ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f010000000071475420001976a914fdd725970db682de970e7669646ed7afb8348ea188ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f01000000000007a12000000151f799a22a9375b31c2f20edce025f0df5231306e81222a0061bde342dc447ef010000000002faf08000016a00000000", txHex)
	}

	if err != nil {
		errMsg, _ := CfdGoGetLastErrorMessage(handle)
		fmt.Print("[error message] " + errMsg + "\n")
	}

	err = CfdGoFreeHandle(handle)
	assert.NoError(t, err)
	fmt.Print("TestCfdCreateRawTransaction test done.\n")
}

func TestCfdGetTransaction(t *testing.T) {
	handle, err := CfdGoCreateHandle()
	assert.NoError(t, err)

	txHex := "0200000000020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570000000000ffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac00000000"

	count, err := CfdGoGetConfidentialTxInCount(handle, txHex)
	assert.NoError(t, err)
	assert.Equal(t, uint32(2), count)

	count, err = CfdGoGetConfidentialTxOutCount(handle, txHex)
	assert.NoError(t, err)
	assert.Equal(t, uint32(4), count)

	if err == nil {
		txData, err := CfdGoGetConfidentialTxData(handle, txHex)
		assert.NoError(t, err)
		assert.Equal(t, "cf7783b2b1de646e35186df988a219a17f0317b5c3f3c47fa4ab2d7463ea3992", txData.Txid)
		assert.Equal(t, "cf7783b2b1de646e35186df988a219a17f0317b5c3f3c47fa4ab2d7463ea3992", txData.Wtxid)
		assert.Equal(t, "938e3a9b5bac410e812d08db74c4ef2bc58d1ed99d94b637cab0ac2e9eb59df8", txData.WitHash)
		assert.Equal(t, uint32(512), txData.Size)
		assert.Equal(t, uint32(512), txData.Vsize)
		assert.Equal(t, uint32(2048), txData.Weight)
		assert.Equal(t, uint32(2), txData.Version)
		assert.Equal(t, uint32(0), txData.LockTime)
	}

	if err == nil {
		txid, vout, sequence, scriptSig, err := CfdGoGetConfidentialTxIn(handle, txHex, uint32(1))
		assert.NoError(t, err)
		assert.Equal(t, "57a15002d066ce52573d674df925c9bc0f1164849420705f2cfad8a68111230f", txid)
		assert.Equal(t, uint32(1), vout)
		assert.Equal(t, uint32(4294967295), sequence)
		assert.Equal(t, "", scriptSig)
	}

	if err == nil {
		entropy, nonce, assetAmount, assetValue, tokenAmount, tokenValue, assetRangeproof, tokenRangeproof, err := CfdGoGetTxInIssuanceInfo(handle, txHex, uint32(1))
		assert.NoError(t, err)
		assert.Equal(t, "6f9ccf5949eba5d6a08bff7a015e825c97824e82d57c8a0c77f9a41908fe8306", entropy)
		assert.Equal(t, "0b8954757234fd3ec9cf0dd6ef0a89d825ec56a9532e7da4b6cb90c51be3bbd8", nonce)
		assert.Equal(t, "010000000023c34600", assetValue)
		assert.Equal(t, "", tokenValue)
		assert.Equal(t, int64(600000000), assetAmount)
		assert.Equal(t, int64(0), tokenAmount)
		assert.Equal(t, "", assetRangeproof)
		assert.Equal(t, "", tokenRangeproof)
	}

	if err == nil {
		asset, satoshiValue, valueCommitment, nonce, lockingScript, surjectionProof, rangeproof, err := CfdGoGetConfidentialTxOut(handle, txHex, uint32(3))
		assert.NoError(t, err)
		assert.Equal(t, "accb7354c07974e00b32e4e5eef55078490141675592ac3610e6101831edb0cd", asset)
		assert.Equal(t, int64(600000000), satoshiValue)
		assert.Equal(t, "010000000023c34600", valueCommitment)
		assert.Equal(t, "03ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed879", nonce)
		assert.Equal(t, "76a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac", lockingScript)
		assert.Equal(t, "", surjectionProof)
		assert.Equal(t, "", rangeproof)
	}

	if err != nil {
		errMsg, _ := CfdGoGetLastErrorMessage(handle)
		fmt.Print("[error message] " + errMsg + "\n")
	}

	err = CfdGoFreeHandle(handle)
	assert.NoError(t, err)
	fmt.Print("TestCfdGetTransaction test done.\n")
}

func TestCfdSetRawReissueAsset(t *testing.T) {
	handle, err := CfdGoCreateHandle()
	assert.NoError(t, err)

	txHex := "0200000000020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570000000000ffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100000000ffffffff03017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000000000000"

	asset, outTxHex, err := CfdGoSetRawReissueAsset(
		handle, txHex, "57a15002d066ce52573d674df925c9bc0f1164849420705f2cfad8a68111230f",
		uint32(1),
		int64(600000000), "0b8954757234fd3ec9cf0dd6ef0a89d825ec56a9532e7da4b6cb90c51be3bbd8",
		"6f9ccf5949eba5d6a08bff7a015e825c97824e82d57c8a0c77f9a41908fe8306",
		"CTExCoUri8VzkxbbhqzgsruWJ5zYtmoFXxCWtjiSLAzcMbpEWhHmDrZ66bAb41VsmSKnvJWrq2cfjUw9",
		"")
	assert.NoError(t, err)
	assert.Equal(t, "accb7354c07974e00b32e4e5eef55078490141675592ac3610e6101831edb0cd", asset)
	assert.Equal(t, "0200000000020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570000000000ffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac00000000", outTxHex)

	if err != nil {
		errMsg, _ := CfdGoGetLastErrorMessage(handle)
		fmt.Print("[error message] " + errMsg + "\n")
	}

	err = CfdGoFreeHandle(handle)
	assert.NoError(t, err)
	fmt.Print("TestCfdSetRawReissueAsset test done.\n")
}

func TestCfdGetIssuanceBlindingKey(t *testing.T) {
	handle, err := CfdGoCreateHandle()
	assert.NoError(t, err)

	blindingKey, err := CfdGoGetIssuanceBlindingKey(
		handle, "ac2c1e4cce122139bb25abc50599e09738143cc4bc96e55f399a5e1e45d916a9",
		"57a15002d066ce52573d674df925c9bc0f1164849420705f2cfad8a68111230f", uint32(1))
	assert.NoError(t, err)
	assert.Equal(t, "7d65c7970d836a878a1080399a3c11de39a8e82493e12b1ad154e383661fb77f", blindingKey)

	if err != nil {
		errMsg, _ := CfdGoGetLastErrorMessage(handle)
		fmt.Print("[error message] " + errMsg + "\n")
	}

	err = CfdGoFreeHandle(handle)
	assert.NoError(t, err)
	fmt.Print("TestCfdGetIssuanceBlindingKey test done.\n")
}

func TestCfdBlindTransaction(t *testing.T) {
	handle, err := CfdGoCreateHandle()
	assert.NoError(t, err)

	txHex := "0200000000020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570000000000ffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac00000000"

	blindHandle, err := CfdGoInitializeBlindTx(handle)
	assert.NoError(t, err)

	if err == nil {
		err = CfdGoAddBlindTxInData(
			handle, blindHandle,
			"57a15002d066ce52573d674df925c9bc0f1164849420705f2cfad8a68111230f", uint32(0),
			"186c7f955149a5274b39e24b6a50d1d6479f552f6522d91f3a97d771f1c18179",
			"a10ecbe1be7a5f883d5d45d966e30dbc1beff5f21c55cec76cc21a2229116a9f",
			"ae0f46d1940f297c2dc3bbd82bf8ef6931a2431fbb05b3d3bc5df41af86ae808",
			int64(999637680), "", "")
		assert.NoError(t, err)
	}

	if err == nil {
		err = CfdGoAddBlindTxInData(
			handle, blindHandle,
			"57a15002d066ce52573d674df925c9bc0f1164849420705f2cfad8a68111230f", uint32(1),
			"ed6927df918c89b5e3d8b5062acab2c749a3291bb7451d4267c7daaf1b52ad0b",
			"0b8954757234fd3ec9cf0dd6ef0a89d825ec56a9532e7da4b6cb90c51be3bbd8",
			"62e36e1f0fa4916b031648a6b6903083069fa587572a88b729250cde528cfd3b",
			int64(700000000),
			"7d65c7970d836a878a1080399a3c11de39a8e82493e12b1ad154e383661fb77f",
			"7d65c7970d836a878a1080399a3c11de39a8e82493e12b1ad154e383661fb77f")
		assert.NoError(t, err)
	}

	if err == nil {
		err = CfdGoAddBlindTxOutData(
			handle, blindHandle, uint32(0),
			"02200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d")
		assert.NoError(t, err)
	}

	if err == nil {
		err = CfdGoAddBlindTxOutData(
			handle, blindHandle, uint32(1),
			"02cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a")
		assert.NoError(t, err)
	}

	if err == nil {
		err = CfdGoAddBlindTxOutData(
			handle, blindHandle, uint32(3),
			"03ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed879")
		assert.NoError(t, err)
	}

	if err == nil {
		txHex, err = CfdGoFinalizeBlindTx(handle, blindHandle, txHex)
		assert.NoError(t, err)
	}

	err2 := CfdGoFreeBlindHandle(handle, blindHandle) // release
	assert.NoError(t, err2)

	if err == nil {
		txData, err := CfdGoGetConfidentialTxData(handle, txHex)
		assert.NoError(t, err)
		assert.Equal(t, 64, len(txData.Txid))
		assert.Equal(t, 64, len(txData.Wtxid))
		assert.Equal(t, 64, len(txData.WitHash))
		assert.Equal(t, uint32(12589), txData.Size)
		assert.Equal(t, uint32(3604), txData.Vsize)
		assert.Equal(t, uint32(14413), txData.Weight)
		assert.Equal(t, uint32(2), txData.Version)
		assert.Equal(t, uint32(0), txData.LockTime)
	}

	// unblind test
	if err == nil {
		asset, assetValue, aabf, avbf, token, tokenValue, tabf, tvbf, err := CfdGoUnblindIssuance(
			handle, txHex, uint32(1),
			"7d65c7970d836a878a1080399a3c11de39a8e82493e12b1ad154e383661fb77f",
			"7d65c7970d836a878a1080399a3c11de39a8e82493e12b1ad154e383661fb77f")
		assert.NoError(t, err)
		assert.Equal(t, "accb7354c07974e00b32e4e5eef55078490141675592ac3610e6101831edb0cd", asset)
		assert.Equal(t, int64(600000000), assetValue)
		assert.Equal(t, "0000000000000000000000000000000000000000000000000000000000000000", aabf)
		assert.NotEqual(t, "0000000000000000000000000000000000000000000000000000000000000000", avbf)
		assert.Equal(t, "", token)
		assert.Equal(t, int64(0), tokenValue)
		assert.Equal(t, "", tabf)
		assert.Equal(t, "", tvbf)
	}

	if err == nil {
		asset, value, abf, vbf, err := CfdGoUnblindTxOut(
			handle, txHex, uint32(0),
			"6a64f506be6e60b948987aa4d180d2ab05034a6a214146e06e28d4efe101d006")
		assert.NoError(t, err)
		assert.Equal(t, "186c7f955149a5274b39e24b6a50d1d6479f552f6522d91f3a97d771f1c18179", asset)
		assert.Equal(t, int64(999587680), value)
		assert.NotEqual(t, "0000000000000000000000000000000000000000000000000000000000000000", abf)
		assert.NotEqual(t, "0000000000000000000000000000000000000000000000000000000000000000", vbf)
	}

	if err == nil {
		asset, value, abf, vbf, err := CfdGoUnblindTxOut(
			handle, txHex, uint32(1),
			"94c85164605f589c4c572874f36b8301989c7fabfd44131297e95824d473681f")
		assert.NoError(t, err)
		assert.Equal(t, "ed6927df918c89b5e3d8b5062acab2c749a3291bb7451d4267c7daaf1b52ad0b", asset)
		assert.Equal(t, int64(700000000), value)
		assert.NotEqual(t, "0000000000000000000000000000000000000000000000000000000000000000", abf)
		assert.NotEqual(t, "0000000000000000000000000000000000000000000000000000000000000000", vbf)
	}

	if err == nil {
		asset, value, abf, vbf, err := CfdGoUnblindTxOut(
			handle, txHex, uint32(3),
			"0473d39aa6542e0c1bb6a2343b2319c3e92063dd019af4d47dbf50c460204f32")
		assert.NoError(t, err)
		assert.Equal(t, "accb7354c07974e00b32e4e5eef55078490141675592ac3610e6101831edb0cd", asset)
		assert.Equal(t, int64(600000000), value)
		assert.NotEqual(t, "0000000000000000000000000000000000000000000000000000000000000000", abf)
		assert.NotEqual(t, "0000000000000000000000000000000000000000000000000000000000000000", vbf)
	}

	if err != nil {
		errMsg, _ := CfdGoGetLastErrorMessage(handle)
		fmt.Print("[error message] " + errMsg + "\n")
	}

	err = CfdGoFreeHandle(handle)
	assert.NoError(t, err)
	fmt.Print("TestCfdBlindTransaction test done.\n")
}

func TestCfdAddSignConfidentialTx(t *testing.T) {
	handle, err := CfdGoCreateHandle()
	assert.NoError(t, err)

	kTxData := "0200000000020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570000000000ffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac00000000"

	pubkey := "03f942716865bb9b62678d99aa34de4632249d066d99de2b5a2e542e54908450d6"
	privkey := "cU4KjNUT7GjHm7CkjRjG46SzLrXHXoH3ekXmqa2jTCFPMkQ64sw1"
	privkeyWifNetworkType := (int)(KCfdNetworkRegtest)
	txid := "57a15002d066ce52573d674df925c9bc0f1164849420705f2cfad8a68111230f"
	vout := uint32(0)
	txHex := ""
	sigHashType := (int)(KCfdSigHashAll)
	hashType := (int)(KCfdP2wpkh)
	isWitness := true
	if (hashType == (int)(KCfdP2pkh)) || (hashType == (int)(KCfdP2sh)) {
		isWitness = false
	}

	sighash, err := CfdGoCreateConfidentialSighash(
		handle, kTxData, txid, vout, hashType,
		pubkey, "", int64(13000000000000), "", sigHashType, false)
	assert.NoError(t, err)
	assert.Equal(t, "c90939ef311f105806b401bcfa494921b8df297195fc125ebbd91a018c4066b9", sighash)

	signature, err := CfdGoCalculateEcSignature(
		handle, sighash, "", privkey, privkeyWifNetworkType, true)
	assert.NoError(t, err)
	assert.Equal(t, "0268633a57723c6612ef217c49bdf804c632a14be2967c76afec4fd5781ad4c2131f358b2381a039c8c502959c64fbfeccf287be7dae710b4446968553aefbea", signature)

	// add signature
	txHex, err = CfdGoAddConfidentialTxDerSign(
		handle, kTxData, txid, vout, isWitness, signature, sigHashType, false, true)
	assert.NoError(t, err)

	// add pubkey
	txHex, err = CfdGoAddConfidentialTxSign(
		handle, txHex, txid, vout, isWitness, pubkey, false)
	assert.NoError(t, err)
	assert.Equal(t, "0200000001020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570000000000ffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac0000000000000247304402200268633a57723c6612ef217c49bdf804c632a14be2967c76afec4fd5781ad4c20220131f358b2381a039c8c502959c64fbfeccf287be7dae710b4446968553aefbea012103f942716865bb9b62678d99aa34de4632249d066d99de2b5a2e542e54908450d600000000000000000000000000", txHex)

	count, err := CfdGoGetConfidentialTxInWitnessCount(handle, txHex, 0)
	assert.NoError(t, err)
	assert.Equal(t, uint32(2), count)

	stackData, err := CfdGoGetConfidentialTxInWitness(handle, txHex, 0, 1)
	assert.NoError(t, err)
	assert.Equal(t, pubkey, stackData)

	if err != nil {
		errMsg, _ := CfdGoGetLastErrorMessage(handle)
		fmt.Print("[error message] " + errMsg + "\n")
	}

	err = CfdGoFreeHandle(handle)
	assert.NoError(t, err)
	fmt.Print("TestCfdAddSignConfidentialTx test done.\n")
}

func TestCfdAddSignConfidentialTxPkh(t *testing.T) {
	handle, err := CfdGoCreateHandle()
	assert.NoError(t, err)

	kTxData := "0200000000020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570000000000ffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac00000000"

	pubkey := "03f942716865bb9b62678d99aa34de4632249d066d99de2b5a2e542e54908450d6"
	privkey := "cU4KjNUT7GjHm7CkjRjG46SzLrXHXoH3ekXmqa2jTCFPMkQ64sw1"
	privkeyWifNetworkType := (int)(KCfdNetworkRegtest)
	txid := "57a15002d066ce52573d674df925c9bc0f1164849420705f2cfad8a68111230f"
	vout := uint32(0)
	txHex := ""
	sigHashType := (int)(KCfdSigHashAll)
	hashType := (int)(KCfdP2pkh)
	isWitness := true
	if (hashType == (int)(KCfdP2pkh)) || (hashType == (int)(KCfdP2sh)) {
		isWitness = false
	}

	sighash, err := CfdGoCreateConfidentialSighash(
		handle, kTxData, txid, vout, hashType,
		pubkey, "", int64(13000000000000), "", sigHashType, false)
	assert.NoError(t, err)
	assert.Equal(t, "e955c2f4fa5077cd0ac724e2f626914c8286896eca30fcde405e051ea3443527", sighash)

	signature, err := CfdGoCalculateEcSignature(
		handle, sighash, "", privkey, privkeyWifNetworkType, true)
	assert.NoError(t, err)
	assert.Equal(t, "4c5f91208f79fe7c74a2b5d88573b6150ac1d4f18cef8051dff1260a37c272d81b97ecd5f83d16cfc3cb39d9bdd21d1f77665135c4230a3157d2045450528ff5", signature)

	// add signature
	txHex, err = CfdGoAddConfidentialTxDerSign(
		handle, kTxData, txid, vout, isWitness, signature, sigHashType, false, true)
	assert.NoError(t, err)

	// add pubkey
	txHex, err = CfdGoAddConfidentialTxSign(
		handle, txHex, txid, vout, isWitness, pubkey, false)
	assert.NoError(t, err)
	assert.Equal(t, "0200000000020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a157000000006a47304402204c5f91208f79fe7c74a2b5d88573b6150ac1d4f18cef8051dff1260a37c272d802201b97ecd5f83d16cfc3cb39d9bdd21d1f77665135c4230a3157d2045450528ff5012103f942716865bb9b62678d99aa34de4632249d066d99de2b5a2e542e54908450d6ffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac00000000", txHex)

	err = CfdGoFreeHandle(handle)
	assert.NoError(t, err)
	fmt.Print("TestCfdAddSignConfidentialTxPkh test done.\n")
}

func TestCfdGoAddConfidentialTxUnlockingScript_P2PKH(t *testing.T) {
	handle, err := CfdGoCreateHandle()
	assert.NoError(t, err)

	// txHex comes from TestCfdCreateRawTransaction result data
	const txHex string = "020000000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff030151f799a22a9375b31c2f20edce025f0df5231306e81222a0061bde342dc447ef010000000005f5e10003a630456ab6d50b57981e085abced70e2816289ae2b49a44c2f471b205134c12b1976a914d08f5ba8874d36cf97d19379b370f1f23ba36d5888ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f010000000071475420001976a914fdd725970db682de970e7669646ed7afb8348ea188ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f01000000000007a120000000000000"
	// unlockingScript comes from TestCfdParseScript PKH UnlockingScript source data
	const unlockingScript string = "47304402204b922f2dafdd926b22b0e669fd774a2d5f10f969b8089a1c3a0384ba7ce95f6e02204e71c2a620cf430fa6d7ceaeb40d5298f20eebae3ecb783714a6adc03c66717d0121038f5d4ee5a661c04de7b715c6b9ac935456419fa9f484470275d1d489f2793301"
	txHexByInput, err := CfdGoAddConfidentialTxUnlockingScript(handle, txHex, "7461b02405414d79e79a5050684a333c922c1136f4bdff5fb94b551394edebbd", (uint32)(0), false, unlockingScript, false)
	assert.NoError(t, err)
	assert.Equal(t, "020000000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b06174000000006a47304402204b922f2dafdd926b22b0e669fd774a2d5f10f969b8089a1c3a0384ba7ce95f6e02204e71c2a620cf430fa6d7ceaeb40d5298f20eebae3ecb783714a6adc03c66717d0121038f5d4ee5a661c04de7b715c6b9ac935456419fa9f484470275d1d489f2793301ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff030151f799a22a9375b31c2f20edce025f0df5231306e81222a0061bde342dc447ef010000000005f5e10003a630456ab6d50b57981e085abced70e2816289ae2b49a44c2f471b205134c12b1976a914d08f5ba8874d36cf97d19379b370f1f23ba36d5888ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f010000000071475420001976a914fdd725970db682de970e7669646ed7afb8348ea188ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f01000000000007a120000000000000", txHexByInput)
	// check adding script sig by index func
	txHexByIndex, err := CfdGoAddConfidentialTxUnlockingScriptByIndex(handle, txHex, (uint32)(0), false, unlockingScript, false)
	assert.NoError(t, err)
	assert.Equal(t, txHexByInput, txHexByIndex)

	err = CfdGoFreeHandle(handle)
	assert.NoError(t, err)
	fmt.Print("TestCfdGoAddConfidentialTxUnlockingScript test done.\n")
}

func TestCfdGoAddConfidentialTxUnlockingScript_P2MS(t *testing.T) {
	handle, err := CfdGoCreateHandle()
	assert.NoError(t, err)

	// txHex comes from TestCfdCreateRawTransaction result data
	const txHex string = "020000000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff030151f799a22a9375b31c2f20edce025f0df5231306e81222a0061bde342dc447ef010000000005f5e10003a630456ab6d50b57981e085abced70e2816289ae2b49a44c2f471b205134c12b1976a914d08f5ba8874d36cf97d19379b370f1f23ba36d5888ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f010000000071475420001976a914fdd725970db682de970e7669646ed7afb8348ea188ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f01000000000007a120000000000000"
	// unlockingScript comes from TestCfdCreateMultisigScriptSig
	const unlockingScript string = "00473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb0147522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52ae"
	txHexByInput, err := CfdGoAddConfidentialTxUnlockingScript(handle, txHex, "7461b02405414d79e79a5050684a333c922c1136f4bdff5fb94b551394edebbd", (uint32)(0), false, unlockingScript, false)
	assert.NoError(t, err)
	assert.Equal(t, "020000000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b0617400000000d900473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb0147522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52aeffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff030151f799a22a9375b31c2f20edce025f0df5231306e81222a0061bde342dc447ef010000000005f5e10003a630456ab6d50b57981e085abced70e2816289ae2b49a44c2f471b205134c12b1976a914d08f5ba8874d36cf97d19379b370f1f23ba36d5888ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f010000000071475420001976a914fdd725970db682de970e7669646ed7afb8348ea188ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f01000000000007a120000000000000", txHexByInput)

	err = CfdGoFreeHandle(handle)
	assert.NoError(t, err)
	fmt.Print("TestCfdGoAddConfidentialTxUnlockingScript test done.\n")
}

func TestCfdGoAddConfidentialTxUnlockingScript_P2SHP2WPKH(t *testing.T) {
	handle, err := CfdGoCreateHandle()
	assert.NoError(t, err)

	// txHex comes from TestCfdGoAddConfidentialTxUnlockingScript/Add_P2MS_UnlockingScript result data
	const txHex string = "020000000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b0617400000000d900473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb0147522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52aeffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff030151f799a22a9375b31c2f20edce025f0df5231306e81222a0061bde342dc447ef010000000005f5e10003a630456ab6d50b57981e085abced70e2816289ae2b49a44c2f471b205134c12b1976a914d08f5ba8874d36cf97d19379b370f1f23ba36d5888ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f010000000071475420001976a914fdd725970db682de970e7669646ed7afb8348ea188ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f01000000000007a120000000000000"

	// unlockingScript comes from TestCfdCreateMultisigScriptSig
	const scriptSig string = "0020fc5acc302aab97f821f9a61e1cc572e7968a603551e95d4ba12b51df6581482f"
	// Append ScriptSig
	txHexResult, err := CfdGoAddConfidentialTxUnlockingScript(handle, txHex, "7461b02405414d79e79a5050684a333c922c1136f4bdff5fb94b551394edebbd", (uint32)(0), false, scriptSig, true)
	assert.NoError(t, err)
	assert.Equal(t, "020000000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b0617400000000220020fc5acc302aab97f821f9a61e1cc572e7968a603551e95d4ba12b51df6581482fffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff030151f799a22a9375b31c2f20edce025f0df5231306e81222a0061bde342dc447ef010000000005f5e10003a630456ab6d50b57981e085abced70e2816289ae2b49a44c2f471b205134c12b1976a914d08f5ba8874d36cf97d19379b370f1f23ba36d5888ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f010000000071475420001976a914fdd725970db682de970e7669646ed7afb8348ea188ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f01000000000007a120000000000000", txHexResult)

	// dummy witness signatrues
	const witnessStackScript string = "00473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb0147522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52ae"
	// Append txinwitness
	txHexResult, err = CfdGoAddConfidentialTxUnlockingScript(handle, txHexResult, "7461b02405414d79e79a5050684a333c922c1136f4bdff5fb94b551394edebbd", (uint32)(0), true, witnessStackScript, true)
	assert.NoError(t, err)
	assert.Equal(t, "020000000102bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b0617400000000220020fc5acc302aab97f821f9a61e1cc572e7968a603551e95d4ba12b51df6581482fffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff030151f799a22a9375b31c2f20edce025f0df5231306e81222a0061bde342dc447ef010000000005f5e10003a630456ab6d50b57981e085abced70e2816289ae2b49a44c2f471b205134c12b1976a914d08f5ba8874d36cf97d19379b370f1f23ba36d5888ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f010000000071475420001976a914fdd725970db682de970e7669646ed7afb8348ea188ac01f38611eb688e6fcd06f25e2faf52b9f98364dc14c379ab085f1b57d56b4b1a6f01000000000007a1200000000000000000040100473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb0147522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52ae0000000000000000000000", txHexResult)

	err = CfdGoFreeHandle(handle)
	assert.NoError(t, err)
	fmt.Print("TestCfdGoAddConfidentialTxUnlockingScript test done.\n")
}

func TestCfdAddMultisigSignConfidentialTx(t *testing.T) {
	handle, err := CfdGoCreateHandle()
	assert.NoError(t, err)

	kTxData := "0200000000020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570000000000ffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac00000000"

	txid := "57a15002d066ce52573d674df925c9bc0f1164849420705f2cfad8a68111230f"
	vout := uint32(0)

	pubkey1 := "02715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad"
	privkey1 := "cRVLMWHogUo51WECRykTbeLNbm5c57iEpSegjdxco3oef6o5dbFi"
	pubkey2 := "02bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d71"
	privkey2 := "cQUTZ8VbWNYBEtrB7xwe41kqiKMQPRZshTvBHmkoJGaUfmS5pxzR"
	networkType := (int)(KCfdNetworkRegtest)
	sigHashType := (int)(KCfdSigHashAll)
	hashType := (int)(KCfdP2sh)

	// create multisig address
	pubkeys := []string{pubkey2, pubkey1}
	addr, multisigScript, _, err := CfdGoCreateMultisigScript(
		handle, networkType, hashType, pubkeys, uint32(2))
	assert.NoError(t, err)
	assert.Equal(t, "2MtG4TZaMXCNdEyUYAyJDraQRFwYC5j4S9U", addr)
	assert.Equal(t, "522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52ae", multisigScript)

	// sign multisig
	multiSignHandle, err := CfdGoInitializeMultisigSign(handle)
	assert.NoError(t, err)
	if err == nil {
		satoshi := int64(13000000000000)
		sighash, err := CfdGoCreateConfidentialSighash(handle, kTxData, txid, vout,
			hashType, "", multisigScript, satoshi, "", sigHashType, false)
		assert.NoError(t, err)
		assert.Equal(t, "64878cbcd5c1805659d0747097cbf4b9ec5c187ebd80afa996c8fc95bd650b70", sighash)

		// user1
		signature1, err := CfdGoCalculateEcSignature(
			handle, sighash, "", privkey1, networkType, true)
		assert.NoError(t, err)

		err = CfdGoAddMultisigSignDataToDer(
			handle, multiSignHandle, signature1, sigHashType, false, pubkey1)
		assert.NoError(t, err)

		// user2
		signature2, err := CfdGoCalculateEcSignature(
			handle, sighash, "", privkey2, networkType, true)
		assert.NoError(t, err)

		err = CfdGoAddMultisigSignDataToDer(
			handle, multiSignHandle, signature2, sigHashType, false, pubkey2)
		assert.NoError(t, err)

		// generate
		txHex, err := CfdGoFinalizeElementsMultisigSign(
			handle, multiSignHandle, kTxData, txid, vout, hashType, "", multisigScript, true)
		assert.NoError(t, err)
		assert.Equal(t, "0200000000020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a15700000000d90047304402206fc4cc7e489208a2f4d24f5d35466debab2ce7aa34b5d00e0a9426c9d63529cf02202ec744939ef0b4b629c7d87bc2d017714b52bb86dccb0fd0f10148f62b7a09ba01473044022073ea24720b24c736bcb305a5de2fd8117ca2f0a85d7da378fae5b90dc361d227022004c0088bf1b73a56ae5ec407cf9c330d7206ffbcd0c9bb1c72661726fd4990390147522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52aeffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac00000000", txHex)

		err = CfdGoFreeMultisigSignHandle(handle, multiSignHandle)
		assert.NoError(t, err)
	}

	if err != nil {
		errMsg, _ := CfdGoGetLastErrorMessage(handle)
		fmt.Print("[error message] " + errMsg + "\n")
	}

	err = CfdGoFreeHandle(handle)
	assert.NoError(t, err)
	fmt.Print("TestCfdAddMultisigSignConfidentialTx test done.\n")
}

func TestCfdAddSignConfidentialTxOpCode(t *testing.T) {
	handle, err := CfdGoCreateHandle()
	assert.NoError(t, err)

	kTxData := "0200000000020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570000000000ffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac00000000"

	txid := "57a15002d066ce52573d674df925c9bc0f1164849420705f2cfad8a68111230f"
	vout := uint32(0)

	pubkey1 := "02715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad"
	pubkey2 := "02bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d71"
	networkType := (int)(KCfdNetworkRegtest)
	hashType := (int)(KCfdP2sh)
	isWitness := true
	if (hashType == (int)(KCfdP2pkh)) || (hashType == (int)(KCfdP2sh)) {
		isWitness = false
	}

	// create multisig address
	pubkeys := []string{pubkey2, pubkey1}
	addr, multisigScript, _, err := CfdGoCreateMultisigScript(
		handle, networkType, hashType, pubkeys, uint32(2))
	assert.NoError(t, err)
	assert.Equal(t, "2MtG4TZaMXCNdEyUYAyJDraQRFwYC5j4S9U", addr)
	assert.Equal(t, "522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52ae", multisigScript)

	// add multisig sign (manual)
	txHex := kTxData
	txHex, err = CfdGoAddConfidentialTxSign(
		handle, txHex, txid, vout, isWitness, "OP_0", true)
	assert.NoError(t, err)

	txHex, err = CfdGoAddConfidentialTxSign(
		handle, txHex, txid, vout, isWitness, "304402206fc4cc7e489208a2f4d24f5d35466debab2ce7aa34b5d00e0a9426c9d63529cf02202ec744939ef0b4b629c7d87bc2d017714b52bb86dccb0fd0f10148f62b7a09ba01", false)
	assert.NoError(t, err)

	txHex, err = CfdGoAddConfidentialTxSign(
		handle, txHex, txid, vout, isWitness, "3044022073ea24720b24c736bcb305a5de2fd8117ca2f0a85d7da378fae5b90dc361d227022004c0088bf1b73a56ae5ec407cf9c330d7206ffbcd0c9bb1c72661726fd49903901", false)
	assert.NoError(t, err)

	txHex, err = CfdGoAddConfidentialTxSign(
		handle, txHex, txid, vout, isWitness, "522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52ae", false)
	assert.NoError(t, err)

	assert.Equal(t, "0200000000020f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a15700000000d90047304402206fc4cc7e489208a2f4d24f5d35466debab2ce7aa34b5d00e0a9426c9d63529cf02202ec744939ef0b4b629c7d87bc2d017714b52bb86dccb0fd0f10148f62b7a09ba01473044022073ea24720b24c736bcb305a5de2fd8117ca2f0a85d7da378fae5b90dc361d227022004c0088bf1b73a56ae5ec407cf9c330d7206ffbcd0c9bb1c72661726fd4990390147522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52aeffffffff0f231181a6d8fa2c5f7020948464110fbcc925f94d673d5752ce66d00250a1570100008000ffffffffd8bbe31bc590cbb6a47d2e53a956ec25d8890aefd60dcfc93efd34727554890b0683fe0819a4f9770c8a7cd5824e82975c825e017aff8ba0d6a5eb4959cf9c6f010000000023c346000004017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000003b947f6002200d8510dfcf8e2330c0795c771d1e6064daab2f274ac32a6e2708df9bfa893d17a914ef3e40882e17d6e477082fcafeb0f09dc32d377b87010bad521bafdac767421d45b71b29a349c7b2ca2a06b5d8e3b5898c91df2769ed010000000029b9270002cc645552109331726c0ffadccab21620dd7a5a33260c6ac7bd1c78b98cb1e35a1976a9146c22e209d36612e0d9d2a20b814d7d8648cc7a7788ac017981c1f171d7973a1fd922652f559f47d6d1506a4be2394b27a54951957f6c1801000000000000c350000001cdb0ed311810e61036ac9255674101497850f5eee5e4320be07479c05473cbac010000000023c3460003ce4c4eac09fe317f365e45c00ffcf2e9639bc0fd792c10f72cdc173c4e5ed8791976a9149bdcb18911fa9faad6632ca43b81739082b0a19588ac00000000", txHex)

	err = CfdGoFreeHandle(handle)
	assert.NoError(t, err)
	fmt.Print("TestCfdAddSignConfidentialTxOpCode test done.\n")
}

func TestCfdConfidentialAddress(t *testing.T) {
	handle, err := CfdGoCreateHandle()
	assert.NoError(t, err)

	kAddress := "Q7wegLt2qMGhm28vch6VTzvpzs8KXvs4X7"
	kConfidentialKey := "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357"
	kConfidentialAddr := "VTpvKKc1SNmLG4H8CnR1fGJdHdyWGEQEvdP9gfeneJR7n81S5kiwNtgF7vrZjC8mp63HvwxM81nEbTxU"
	kNetworkType := (int)(KCfdNetworkLiquidv1)

	confidentialAddr, err := CfdGoCreateConfidentialAddress(handle, kAddress, kConfidentialKey)
	assert.NoError(t, err)
	assert.Equal(t, kConfidentialAddr, confidentialAddr)

	addr, key, netType, err := CfdGoParseConfidentialAddress(handle, confidentialAddr)
	assert.NoError(t, err)
	assert.Equal(t, kAddress, addr)
	assert.Equal(t, kConfidentialKey, key)
	assert.Equal(t, kNetworkType, netType)

	if err != nil {
		errMsg, _ := CfdGoGetLastErrorMessage(handle)
		fmt.Print("[error message] " + errMsg + "\n")
	}

	err = CfdGoFreeHandle(handle)
	assert.NoError(t, err)
	fmt.Print("TestCfdConfidentialAddress test done.\n")
}

func TestCfdCalculateEcSignature(t *testing.T) {
	handle, err := CfdGoCreateHandle()
	assert.NoError(t, err)

	kSighash := "9b169f5af064cc2a0dac08d8be3c9e8bc3d3e1a3f3e2a44f0c3e4ecf23d56cf2"
	kPrivkey := "cU4KjNUT7GjHm7CkjRjG46SzLrXHXoH3ekXmqa2jTCFPMkQ64sw1"
	kExtSignature := "0bc7f08a2a8a5446e7483db1b46184ba3cc79d78a3452a72c5bc712cc7efb51f58af044d646c1fd4f755d49db26faa203937bc66c569047a7d3d3da531826060"
	kNetwork := (int)(KCfdNetworkRegtest)

	signature, err := CfdGoCalculateEcSignature(handle, kSighash, "", kPrivkey, kNetwork, true)
	assert.NoError(t, err)
	assert.Equal(t, kExtSignature, signature)

	if err != nil {
		errMsg, _ := CfdGoGetLastErrorMessage(handle)
		fmt.Print("[error message] " + errMsg + "\n")
	}

	err = CfdGoFreeHandle(handle)
	assert.NoError(t, err)
	fmt.Print("TestCfdCalculateEcSignature test done.\n")
}

func TestCfdPrivkeyAndPubkey(t *testing.T) {
	handle, err := CfdGoCreateHandle()
	assert.NoError(t, err)

	kNetwork := (int)(KCfdNetworkRegtest)

	// compress
	pubkey, privkey, wif, err := CfdGoCreateKeyPair(handle, true, kNetwork)
	assert.NoError(t, err)
	assert.Equal(t, 66, len(pubkey))
	assert.Equal(t, 64, len(privkey))
	assert.Equal(t, 52, len(wif))

	privkey2, err := CfdGoGetPrivkeyFromWif(handle, wif, kNetwork)
	assert.NoError(t, err)
	assert.Equal(t, privkey, privkey2)

	pubkey2 := ""
	pubkey2, err = CfdGoGetPubkeyFromPrivkey(handle, privkey, "", true)
	assert.NoError(t, err)
	assert.Equal(t, pubkey, pubkey2)

	// uncompress
	pubkey, privkey, wif, err = CfdGoCreateKeyPair(handle, false, kNetwork)
	assert.NoError(t, err)
	assert.Equal(t, 130, len(pubkey))
	assert.Equal(t, 64, len(privkey))
	assert.Equal(t, 51, len(wif))

	privkey2, err = CfdGoGetPrivkeyFromWif(handle, wif, kNetwork)
	assert.NoError(t, err)
	assert.Equal(t, privkey, privkey2)

	pubkey2, err = CfdGoGetPubkeyFromPrivkey(handle, privkey, "", false)
	assert.NoError(t, err)
	assert.Equal(t, pubkey, pubkey2)

	if err != nil {
		errMsg, _ := CfdGoGetLastErrorMessage(handle)
		fmt.Print("[error message] " + errMsg + "\n")
	}

	err = CfdGoFreeHandle(handle)
	assert.NoError(t, err)
	fmt.Print("TestCfdPrivkeyAndPubkey test done.\n")
}

func TestCfdExtkey(t *testing.T) {
	handle, err := CfdGoCreateHandle()
	assert.NoError(t, err)

	kSeed := "0e09fbdd00e575b654d480ae979f24da45ef4dee645c7dc2e3b30b2e093d38dda0202357754cc856f8920b8e31dd02e9d34f6a2b20dc825c6ba90f90009085e1"
	kNetwork := (int)(KCfdNetworkMainnet)

	extprivkey1, err := CfdGoCreateExtkeyFromSeed(handle, kSeed, kNetwork, (int)(KCfdExtPrivkey))
	assert.NoError(t, err)
	assert.Equal(t, "xprv9s21ZrQH143K38XAstQ4D3hCGbgydJgNff6CcwmkrWTBxksb2G4CsqAywJCKbTdywfCpmpJyxqf77iKK1ju1J982iP2PriifaNZLMbyPQCx", extprivkey1)

	extprivkey2, err := CfdGoCreateExtkeyFromParentPath(handle, extprivkey1, "m/44'", kNetwork, (int)(KCfdExtPrivkey))
	assert.NoError(t, err)
	assert.Equal(t, "xprv9tviYANkXM1CY831VtMFKFn6LP6aMHf1kvtCZyTL9YbyMwTR2BSmJaEoqw59BZdQhLSx9ZxyKsRUeCetxA2xZ34eupBqZUsifnWyLJJ16j3", extprivkey2)

	extpubkey1, err := CfdGoCreateExtPubkey(handle, extprivkey2, kNetwork)
	assert.NoError(t, err)
	assert.Equal(t, "xpub67v4wfueMiZVkc7UbutFgPiptQw4kkNs89ooNMrwht8xEjnZZim1rNZHhEdrLejB99fiBdnWNNAB8hmUK7tCo5Ua6UtHzwVLj2Bzpch7vB2", extpubkey1)

	extprivkey3, err := CfdGoCreateExtkeyFromParentPath(handle, extprivkey2, "0h/0h/2", kNetwork, (int)(KCfdExtPrivkey))
	assert.NoError(t, err)
	assert.Equal(t, "xprvA1YYKkMiZaDHRY4dmXjcP3js7ATJQAwt9gozTvi69etziyBAAENQN4w7sS3uBaF7rgXvP3sUtKFju7p3PosjNkRDuqqSFfxTjjEhgx6ejVZ", extprivkey3)

	privkey, wif, err := CfdGoGetPrivkeyFromExtkey(handle, extprivkey3, kNetwork)
	assert.NoError(t, err)
	assert.Equal(t, "597da1afc4218445ba9428c1c790a30fd21d5c4a932fa580b99dda7ec0887472", privkey)
	assert.Equal(t, "KzDfmSzt1XqZh5m4sQPBqhpiTGncQ2xvXuWnKGMqR9gVHGSbVJP2", wif)

	pubkey, err := CfdGoGetPubkeyFromExtkey(handle, extprivkey3, kNetwork)
	assert.NoError(t, err)
	assert.Equal(t, "031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1", pubkey)

	if err != nil {
		errMsg, _ := CfdGoGetLastErrorMessage(handle)
		fmt.Print("[error message] " + errMsg + "\n")
	}

	err = CfdGoFreeHandle(handle)
	assert.NoError(t, err)
	fmt.Print("TestCfdExtkey test done.\n")
}

func TestCfdParseScript(t *testing.T) {
	handle, err := CfdGoCreateHandle()
	assert.NoError(t, err)

	t.Run("PKH Locking Script", func(t *testing.T) {
		script := "76a9142e3f2c7e30abce5b22451184c5e531a1e23c6e1288ac"
		items, err := CfdGoParseScript(handle, script)
		assert.NoError(t, err)
		assert.Equal(t, int(5), len(items))
		assert.Equal(t, "OP_DUP", items[0])
		assert.Equal(t, "OP_HASH160", items[1])
		assert.Equal(t, "2e3f2c7e30abce5b22451184c5e531a1e23c6e12", items[2])
		assert.Equal(t, "OP_EQUALVERIFY", items[3])
		assert.Equal(t, "OP_CHECKSIG", items[4])
	})

	t.Run("PKH UnlockingScript", func(t *testing.T) {
		script := "47304402204b922f2dafdd926b22b0e669fd774a2d5f10f969b8089a1c3a0384ba7ce95f6e02204e71c2a620cf430fa6d7ceaeb40d5298f20eebae3ecb783714a6adc03c66717d0121038f5d4ee5a661c04de7b715c6b9ac935456419fa9f484470275d1d489f2793301"
		items, err := CfdGoParseScript(handle, script)
		assert.NoError(t, err)
		assert.Equal(t, int(2), len(items))
		assert.Equal(t, "304402204b922f2dafdd926b22b0e669fd774a2d5f10f969b8089a1c3a0384ba7ce95f6e02204e71c2a620cf430fa6d7ceaeb40d5298f20eebae3ecb783714a6adc03c66717d01", items[0])
		assert.Equal(t, "038f5d4ee5a661c04de7b715c6b9ac935456419fa9f484470275d1d489f2793301", items[1])
	})

	err = CfdGoFreeHandle(handle)
	assert.NoError(t, err)
	fmt.Print("TestCfdParseScript test done.\n")
}

func TestCfdEncodeSignatureToDer(t *testing.T) {
	handle, err := CfdGoCreateHandle()
	assert.NoError(t, err)

	signature := "47ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb"

	derSignature, err := CfdGoEncodeSignatureByDer(handle, signature, (int)(KCfdSigHashAll), false)
	assert.NoError(t, err)
	assert.Equal(t, derSignature, "3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01")

	err = CfdGoFreeHandle(handle)
	assert.NoError(t, err)
	fmt.Print("TestCfdEncodeSignatureToDer test done.\n")
}

func TestCfdGoCreateScript(t *testing.T) {
	handle, err := CfdGoCreateHandle()
	assert.NoError(t, err)
	defer CfdGoFreeHandle(handle)

	t.Run("TestCfdGoCreateScript_UnlockingScript_pkh", func(t *testing.T) {
		scriptItems := make([]string, 0, 2)
		scriptItems = append(scriptItems, "304402204b922f2dafdd926b22b0e669fd774a2d5f10f969b8089a1c3a0384ba7ce95f6e02204e71c2a620cf430fa6d7ceaeb40d5298f20eebae3ecb783714a6adc03c66717d01")
		scriptItems = append(scriptItems, "038f5d4ee5a661c04de7b715c6b9ac935456419fa9f484470275d1d489f2793301")
		script, err := CfdGoCreateScript(handle, scriptItems)
		assert.NoError(t, err)
		assert.Equal(t, script, "47304402204b922f2dafdd926b22b0e669fd774a2d5f10f969b8089a1c3a0384ba7ce95f6e02204e71c2a620cf430fa6d7ceaeb40d5298f20eebae3ecb783714a6adc03c66717d0121038f5d4ee5a661c04de7b715c6b9ac935456419fa9f484470275d1d489f2793301")
		scriptAsm := strings.Join(scriptItems, " ")
		scriptHex, err := CfdGoConvertScriptAsmToHex(handle, scriptAsm)
		assert.NoError(t, err)
		assert.Equal(t, script, scriptHex)
	})

	t.Run("TestCfdGoCreateScript_SimpleScript", func(t *testing.T) {
		scriptItems := make([]string, 0, 2)
		scriptItems = append(scriptItems, "OP_9")
		scriptItems = append(scriptItems, "OP_15")
		scriptItems = append(scriptItems, "OP_ADD")
		scriptItems = append(scriptItems, strconv.Itoa(24))
		scriptItems = append(scriptItems, "OP_EQUAL")
		script, err := CfdGoCreateScript(handle, scriptItems)
		assert.NoError(t, err)
		assert.Equal(t, script, "595f93011887")
		scriptAsm := strings.Join(scriptItems, " ")
		scriptHex, err := CfdGoConvertScriptAsmToHex(handle, scriptAsm)
		assert.NoError(t, err)
		assert.Equal(t, script, scriptHex)
	})
}

func TestCfdCreateMultisigScriptSig(t *testing.T) {
	handle, err := CfdGoCreateHandle()
	assert.NoError(t, err)
	defer CfdGoFreeHandle(handle)

	redeemScript := "522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52ae"
	signItems := []CfdMultisigSignData{
		{
			Signature:           "47ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb",
			IsDerEncode:         true,
			SighashType:         (int)(KCfdSigHashAll),
			SighashAnyoneCanPay: false,
			RelatedPubkey:       "02715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad",
		},
		{
			Signature:           "3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01",
			IsDerEncode:         false,
			SighashType:         0,
			SighashAnyoneCanPay: false,
			RelatedPubkey:       "02bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d71",
		},
	}

	scriptsig, err := CfdGoCreateMultisigScriptSig(handle, signItems, redeemScript)
	assert.NoError(t, err)
	assert.Equal(t, scriptsig, "00473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb0147522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52ae")

	items, err := CfdGoParseScript(handle, scriptsig)
	assert.NoError(t, err)
	assert.Equal(t, int(4), len(items))
	if len(items) == int(4) {
		assert.Equal(t, "OP_0", items[0])
		assert.Equal(t, "3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01", items[1])
		assert.Equal(t, "3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01", items[2])
		assert.Equal(t, "522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52ae", items[3])
	}

	fmt.Print("TestCfdCreateMultisigScriptSig test done.\n")
}

func TestCfdCoinSelection(t *testing.T) {
	assets, utxos := GetCoinSelectionTestData()
	targets := []CfdTargetAmount{
		{
			Amount: int64(115800000),
			Asset:  assets[0],
		},
		{
			Amount: int64(347180040),
			Asset:  assets[1],
		},
		{
			Amount: int64(37654100),
			Asset:  assets[2],
		},
	}

	option := NewCfdCoinSelectionOption()
	option.TxFeeAmount = int64(2000)
	option.FeeAsset = assets[0]

	selectUtxos, totalAmounts, utxoFee, err := CfdGoCoinSelection(uintptr(0), utxos, targets, option)
	assert.NoError(t, err)
	assert.Equal(t, int64(9000), utxoFee)
	assert.Equal(t, 5, len(selectUtxos))
	assert.Equal(t, 3, len(totalAmounts))

	if len(selectUtxos) == 5 {
		assert.Equal(t, utxos[8].Amount, selectUtxos[0].Amount)
		assert.Equal(t, utxos[7].Amount, selectUtxos[1].Amount)
		assert.Equal(t, utxos[10].Amount, selectUtxos[2].Amount)
		assert.Equal(t, utxos[1].Amount, selectUtxos[3].Amount)
		assert.Equal(t, utxos[3].Amount, selectUtxos[4].Amount)
	}
	if len(totalAmounts) == 3 {
		assert.Equal(t, int64(117187500), totalAmounts[0].Amount)
		assert.Equal(t, targets[0].Asset, totalAmounts[0].Asset)
		assert.Equal(t, int64(347180050), totalAmounts[1].Amount)
		assert.Equal(t, targets[1].Asset, totalAmounts[1].Asset)
		assert.Equal(t, int64(37654200), totalAmounts[2].Amount)
		assert.Equal(t, targets[2].Asset, totalAmounts[2].Asset)
	}

	fmt.Print("TestCfdCoinSelection test done.\n")
}

func TestCfdCoinSelectionUnuseFee(t *testing.T) {
	assets, utxos := GetCoinSelectionTestData()
	targets := []CfdTargetAmount{
		{
			Amount: int64(115800000),
			Asset:  assets[0],
		},
		{
			Amount: int64(347180040),
			Asset:  assets[1],
		},
		{
			Amount: int64(37654100),
			Asset:  assets[2],
		},
	}

	option := NewCfdCoinSelectionOption()
	option.EffectiveFeeRate = 0
	option.LongTermFeeRate = 0
	option.DustFeeRate = 0
	option.KnapsackMinChange = 0

	selectUtxos, totalAmounts, utxoFee, err := CfdGoCoinSelection(uintptr(0), utxos, targets, option)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), utxoFee)
	assert.Equal(t, 5, len(selectUtxos))
	assert.Equal(t, 3, len(totalAmounts))

	if len(selectUtxos) == 5 {
		assert.Equal(t, utxos[1].Amount, selectUtxos[0].Amount)
		assert.Equal(t, utxos[3].Amount, selectUtxos[1].Amount)
		assert.Equal(t, utxos[8].Amount, selectUtxos[2].Amount)
		assert.Equal(t, utxos[7].Amount, selectUtxos[3].Amount)
		assert.Equal(t, utxos[10].Amount, selectUtxos[4].Amount)
	}
	if len(totalAmounts) == 3 {
		assert.Equal(t, int64(117187500), totalAmounts[0].Amount)
		assert.Equal(t, targets[0].Asset, totalAmounts[0].Asset)
		assert.Equal(t, int64(347180050), totalAmounts[1].Amount)
		assert.Equal(t, targets[1].Asset, totalAmounts[1].Asset)
		assert.Equal(t, int64(37654200), totalAmounts[2].Amount)
		assert.Equal(t, targets[2].Asset, totalAmounts[2].Asset)
	}

	fmt.Print("TestCfdCoinSelectionUnuseFee test done.\n")
}

func GetCoinSelectionTestData() (assets []string, utxos []CfdUtxo) {
	assets = []string{
		"aa00000000000000000000000000000000000000000000000000000000000000",
		"bb00000000000000000000000000000000000000000000000000000000000000",
		"cc00000000000000000000000000000000000000000000000000000000000000",
	}
	utxos = []CfdUtxo{
		{
			Txid:       "7ca81dd22c934747f4f5ab7844178445fe931fb248e0704c062b8f4fbd3d500a",
			Vout:       uint32(0),
			Amount:     int64(312500000),
			Asset:      assets[0],
			Descriptor: "sh(wpkh(037ca81dd22c934747f4f5ab7844178445fe931fb248e0704c062b8f4fbd3d500a))",
		},
		{
			Txid:       "30f71f39d210f7ee291b0969c6935debf11395b0935dca84d30c810a75339a0a",
			Vout:       uint32(0),
			Amount:     int64(78125000),
			Asset:      assets[0],
			Descriptor: "sh(wpkh(0330f71f39d210f7ee291b0969c6935debf11395b0935dca84d30c810a75339a0a))",
		},
		{
			Txid:       "9e1ead91c432889cb478237da974dd1e9009c9e22694fd1e3999c40a1ef59b0a",
			Vout:       uint32(0),
			Amount:     int64(1250000000),
			Asset:      assets[0],
			Descriptor: "sh(wpkh(039e1ead91c432889cb478237da974dd1e9009c9e22694fd1e3999c40a1ef59b0a))",
		},
		{
			Txid:       "8f4af7ee42e62a3d32f25ca56f618fb2f5df3d4c3a9c59e2c3646c5535a3d40a",
			Vout:       uint32(0),
			Amount:     int64(39062500),
			Asset:      assets[0],
			Descriptor: "sh(wpkh(038f4af7ee42e62a3d32f25ca56f618fb2f5df3d4c3a9c59e2c3646c5535a3d40a))",
		},
		{
			Txid:       "4d97d0119b90421818bff4ec9033e5199199b53358f56390cb20f8148e76f40a",
			Vout:       uint32(0),
			Amount:     int64(156250000),
			Asset:      assets[0],
			Descriptor: "sh(wpkh(034d97d0119b90421818bff4ec9033e5199199b53358f56390cb20f8148e76f40a))",
		},
		{
			Txid:       "b9720ed2265a4ced42425bffdb4ef90a473b4106811a802fce53f7c57487fa0b",
			Vout:       uint32(0),
			Amount:     int64(2500000000),
			Asset:      assets[0],
			Descriptor: "sh(wpkh(03b9720ed2265a4ced42425bffdb4ef90a473b4106811a802fce53f7c57487fa0b))",
		},
		{
			Txid:       "0000000000000000000000000000000000000000000000000000000000000b01",
			Vout:       uint32(0),
			Amount:     int64(26918400),
			Asset:      assets[1],
			Descriptor: "sh(wpkh(030000000000000000000000000000000000000000000000000000000000000b01))",
		},
		{
			Txid:       "0000000000000000000000000000000000000000000000000000000000000b02",
			Vout:       uint32(0),
			Amount:     int64(750000),
			Asset:      assets[1],
			Descriptor: "sh(wpkh(030000000000000000000000000000000000000000000000000000000000000b02))",
		},
		{
			Txid:       "0000000000000000000000000000000000000000000000000000000000000b03",
			Vout:       uint32(0),
			Amount:     int64(346430050),
			Asset:      assets[1],
			Descriptor: "sh(wpkh(030000000000000000000000000000000000000000000000000000000000000b03))",
		},
		{
			Txid:       "0000000000000000000000000000000000000000000000000000000000000b04",
			Vout:       uint32(0),
			Amount:     int64(18476350),
			Asset:      assets[1],
			Descriptor: "sh(wpkh(030000000000000000000000000000000000000000000000000000000000000b04))",
		},
		{
			Txid:       "0000000000000000000000000000000000000000000000000000000000000c01",
			Vout:       uint32(0),
			Amount:     int64(37654200),
			Asset:      assets[2],
			Descriptor: "sh(wpkh(030000000000000000000000000000000000000000000000000000000000000c01))",
		},
		{
			Txid:       "0000000000000000000000000000000000000000000000000000000000000c02",
			Vout:       uint32(0),
			Amount:     int64(127030000),
			Asset:      assets[2],
			Descriptor: "sh(wpkh(030000000000000000000000000000000000000000000000000000000000000c02))",
		},
	}

	return
}

func TestCfdGoEstimateFee(t *testing.T) {
	asset, inputs := GetEstimateFeeTestData()
	t.Run("BitcoinTest", func(t *testing.T) {
		handle, err := CfdGoCreateHandle()
		assert.NoError(t, err)
		defer CfdGoFreeHandle(handle)

		txHex := "02000000014cdeada737db97af334f0fa4e87432d6068759eea65a3067d1f14a979e5a9dea0000000000ffffffff0101000000000000002200201863143c14c5166804bd19203356da136c985678cd4d27a1b8c632960490326200000000"
		option := NewCfdEstimateFeeOption()
		option.EffectiveFeeRate = float64(20.0)
		option.UseElements = false
		option.RequireBlind = false
		totalFee, txFee, inputFee, err := CfdGoEstimateFee(handle, txHex, inputs, option)
		assert.NoError(t, err)
		assert.Equal(t, int64(12580), totalFee)
		assert.Equal(t, int64(1060), txFee)
		assert.Equal(t, int64(11520), inputFee)
	})

	t.Run("ElementsTest", func(t *testing.T) {
		handle, err := CfdGoCreateHandle()
		assert.NoError(t, err)
		defer CfdGoFreeHandle(handle)

		txHex := "020000000002d4b91f8ea0be3d89d33f9588884a843e78688152f4dff8aca5abc6f5973a83ae0000000000ffffffff140510708ffd1fc8bea09e204d36b0d5b9402a31767a4f6c36f23b40cd0cbaf70000000000ffffffff030100000000000000000000000000000000000000000000000000000000000000aa01000000003b9328e0001976a9146d715ab3da8090fd8f9e7aada1588e531b16b7da88ac0100000000000000000000000000000000000000000000000000000000000000bb010000000008f0d180001976a9147cafacbfc72f3682b1055b3a6b8711f3622eabfd88ac0100000000000000000000000000000000000000000000000000000000000000aa01000000000007a120000000000000"
		option := NewCfdEstimateFeeOption()
		option.EffectiveFeeRate = float64(20.0)
		option.FeeAsset = asset[0]
		totalFee, txFee, inputFee, err := CfdGoEstimateFee(handle, txHex, inputs, option)
		assert.NoError(t, err)
		assert.Equal(t, int64(47940), totalFee)
		assert.Equal(t, int64(36400), txFee)
		assert.Equal(t, int64(11540), inputFee)
	})
}

func GetEstimateFeeTestData() (assets []string, inputs []CfdEstimateFeeInput) {
	assets = []string{
		"aa00000000000000000000000000000000000000000000000000000000000000",
		"bb00000000000000000000000000000000000000000000000000000000000000",
	}
	inputs = []CfdEstimateFeeInput{
		{
			Utxo: CfdUtxo{
				Txid:       "aa00000000000000000000000000000000000000000000000000000000000001",
				Vout:       uint32(0),
				Amount:     int64(100000000),
				Asset:      assets[0],
				Descriptor: "pkh(030000000000000000000000000000000000000000000000000000000000000a01)",
			},
			IsIssuance:      false,
			IsBlindIssuance: false,
			IsPegin:         false,
			PeginBtcTxSize:  uint32(0),
			FedpegScript:    "",
		},
		{
			Utxo: CfdUtxo{
				Txid:       "aa00000000000000000000000000000000000000000000000000000000000002",
				Vout:       uint32(0),
				Amount:     int64(200000000),
				Asset:      assets[0],
				Descriptor: "sh(multi(1,020000000000000000000000000000000000000000000000000000000000000a02,030000000000000000000000000000000000000000000000000000000000000a02))",
			},
			IsIssuance:      false,
			IsBlindIssuance: false,
			IsPegin:         false,
			PeginBtcTxSize:  uint32(0),
			FedpegScript:    "",
		},
		{
			Utxo: CfdUtxo{
				Txid:       "bb00000000000000000000000000000000000000000000000000000000000001",
				Vout:       uint32(1),
				Amount:     int64(30000000),
				Asset:      assets[1],
				Descriptor: "wpkh(030000000000000000000000000000000000000000000000000000000000000b01)",
			},
			IsIssuance:      false,
			IsBlindIssuance: false,
			IsPegin:         false,
			PeginBtcTxSize:  uint32(0),
			FedpegScript:    "",
		},
		{
			Utxo: CfdUtxo{
				Txid:       "bb00000000000000000000000000000000000000000000000000000000000002",
				Vout:       uint32(2),
				Amount:     int64(40000000),
				Asset:      assets[1],
				Descriptor: "wsh(multi(1,020000000000000000000000000000000000000000000000000000000000000b02,030000000000000000000000000000000000000000000000000000000000000b02))",
			},
			IsIssuance:      false,
			IsBlindIssuance: false,
			IsPegin:         false,
			PeginBtcTxSize:  uint32(0),
			FedpegScript:    "",
		},
	}

	return
}

func TestCfdGoVerifyConfidentialTxSignature(t *testing.T) {

	t.Run("PKHSignature", func(t *testing.T) {
		handle, err := CfdGoCreateHandle()
		assert.NoError(t, err)
		defer CfdGoFreeHandle(handle)

		txHex := "02000000000117c10bbfcd4e89f6c33864ed627aa113f249343f4b2bbe6e86dcc725e0d06cfc010000006a473044022038527c96efaaa29b862c8fe8aa4e96602b03035505ebe1f166dd8b9f3731b7b502207e75d937ca1bb2e2f4208618051eb8aad02ad88a71477d7a6e7ec257f72cb6500121036b70f6598ee5c00ad068c9b86c7a1d5c433767a46db3bc3f9d53417171db1782fdffffff0301bdc7073c43d37ace6b66b02268ece4754fe6c39a985a16ccbe6cf05b89014d7201000000001dcd6500001976a91479975e7d3775b748cbcd5500804518280a2ebbae88ac01bdc7073c43d37ace6b66b02268ece4754fe6c39a985a16ccbe6cf05b89014d7201000000001dcccde80017a9141cd92b989652fbc4c2a92eb1d56456d0ef17d4158701bdc7073c43d37ace6b66b02268ece4754fe6c39a985a16ccbe6cf05b89014d7201000000000000971800000a000000"
		txid := "fc6cd0e025c7dc866ebe2b4b3f3449f213a17a62ed6438c3f6894ecdbf0bc117"
		vout := uint32(1)

		// prepare pkh signature
		pubkey, _, wif, err := CfdGoCreateKeyPair(handle, true, (int)(KCfdNetworkElementsRegtest))
		assert.NoError(t, err)
		sighashType := (int)(KCfdSigHashAll)
		satoshiValue := int64(1000000000)
		sighash, err := CfdGoCreateConfidentialSighash(handle, txHex, txid, vout,
			(int)(KCfdP2pkh), pubkey, "", satoshiValue, "", sighashType, false)
		assert.NoError(t, err)
		signature, err := CfdGoCalculateEcSignature(handle, sighash, "", wif, (int)(KCfdNetworkElementsRegtest), true)
		assert.NoError(t, err)

		// check signature
		result, err := CfdGoVerifyConfidentialTxSignature(handle, txHex, signature, pubkey, "", txid, vout, sighashType, false, satoshiValue, "", (int)(KCfdWitnessVersionNone))
		assert.NoError(t, err)
		assert.True(t, result)
		// check signature
		result, err = CfdGoVerifyConfidentialTxSignatureByIndex(handle, txHex, signature, pubkey, "", 0, sighashType, false, satoshiValue, "", (int)(KCfdWitnessVersionNone))
		assert.NoError(t, err)
		assert.True(t, result)
	})

	t.Run("PKHSignatureFail", func(t *testing.T) {
		handle, err := CfdGoCreateHandle()
		assert.NoError(t, err)
		defer CfdGoFreeHandle(handle)

		txHex := "02000000000117c10bbfcd4e89f6c33864ed627aa113f249343f4b2bbe6e86dcc725e0d06cfc010000006a473044022038527c96efaaa29b862c8fe8aa4e96602b03035505ebe1f166dd8b9f3731b7b502207e75d937ca1bb2e2f4208618051eb8aad02ad88a71477d7a6e7ec257f72cb6500121036b70f6598ee5c00ad068c9b86c7a1d5c433767a46db3bc3f9d53417171db1782fdffffff0301bdc7073c43d37ace6b66b02268ece4754fe6c39a985a16ccbe6cf05b89014d7201000000001dcd6500001976a91479975e7d3775b748cbcd5500804518280a2ebbae88ac01bdc7073c43d37ace6b66b02268ece4754fe6c39a985a16ccbe6cf05b89014d7201000000001dcccde80017a9141cd92b989652fbc4c2a92eb1d56456d0ef17d4158701bdc7073c43d37ace6b66b02268ece4754fe6c39a985a16ccbe6cf05b89014d7201000000000000971800000a000000"
		txid := "fc6cd0e025c7dc866ebe2b4b3f3449f213a17a62ed6438c3f6894ecdbf0bc117"
		vout := uint32(1)

		// prepare pkh signature
		pubkey, _, wif, err := CfdGoCreateKeyPair(handle, true, (int)(KCfdNetworkElementsRegtest))
		assert.NoError(t, err)
		sighashType := (int)(KCfdSigHashAll)
		satoshiValue := int64(1000000000)
		sighash, err := CfdGoCreateConfidentialSighash(handle, txHex, txid, vout,
			(int)(KCfdP2pkh), pubkey, "", satoshiValue, "", sighashType, false)
		assert.NoError(t, err)
		signature, err := CfdGoCalculateEcSignature(handle, sighash, "", wif, (int)(KCfdNetworkElementsRegtest), true)
		assert.NoError(t, err)

		// check signature
		invalidSighashType := (int)(KCfdSigHashSingle)
		result, err := CfdGoVerifyConfidentialTxSignature(handle, txHex, signature, pubkey, "", txid, vout, invalidSighashType, false, satoshiValue, "", (int)(KCfdWitnessVersionNone))
		assert.NoError(t, err)
		assert.False(t, result)
		// check signature
		result, err = CfdGoVerifyConfidentialTxSignatureByIndex(handle, txHex, signature, pubkey, "", 0, invalidSighashType, false, satoshiValue, "", (int)(KCfdWitnessVersionNone))
		assert.NoError(t, err)
		assert.False(t, result)
	})

	t.Run("WSHSignature", func(t *testing.T) {
		handle, err := CfdGoCreateHandle()
		assert.NoError(t, err)
		defer CfdGoFreeHandle(handle)

		txHex := "02000000010117c10bbfcd4e89f6c33864ed627aa113f249343f4b2bbe6e86dcc725e0d06cfc010000006a473044022038527c96efaaa29b862c8fe8aa4e96602b03035505ebe1f166dd8b9f3731b7b502207e75d937ca1bb2e2f4208618051eb8aad02ad88a71477d7a6e7ec257f72cb6500121036b70f6598ee5c00ad068c9b86c7a1d5c433767a46db3bc3f9d53417171db1782fdffffff030bc7b2b8da0c30f37b12580e0bd092bfbe16e28494fe30feab1769ab4135d30a7609c8e4c3012d90840dbed48eeebc253399645119c01125488640f415285e6e7663031651fe4267cf54e606a83e4c741a01df124d4eb915ae37ad9d5191661d74310b1976a91479975e7d3775b748cbcd5500804518280a2ebbae88ac0b8f78a97d70ad5799c1ef2ca5f7f553ec30fdc87392eb2b5a9acc42d72f5900250978d7a93a301c65b0759c8e7f4b4424ff2a4c124ee2467b08e266423faa3afef30249a8537d641e728c2192f66433e125041341b36fa3e3cde5578ad1acb9a3944b17a9141cd92b989652fbc4c2a92eb1d56456d0ef17d4158701bdc7073c43d37ace6b66b02268ece4754fe6c39a985a16ccbe6cf05b89014d7201000000000000971800000a0000000000000043010001cd72e3aa85cc53ce42edd91e03a6b4d3cd6b08d2125f019639f0ae6ee29e7f8539232c60e68020ab948d95e5c70da679309e8a511a1a0ef65c7b5e5f4dfb83c7fd4d0b60230000000000000001c39d00a796090bd9872e87a9d5f06b5c73c4fe64104a59c25536f90813b311c90de520f63a57875a2e9b6111f41f5fb7b4a253c76027af35fbcf7ddb9e5688ebefb04948f349e48e2ef4cd73b17f1d5786822222f2a1e5367bd1d39b139283800bfc4b7d50ce927469541151be53b3518b0fa1e9acb8089072976b1d659e8136c666f0b57cec51775ccd40998ee57ace137e25ee7e066d9d434c0e54304913019db87855de47f7f1e974578dfedb95a92048fafe0dca541bd917ea22d9c02fd58fafc8ee35f016b4b1ebf0051a314038201163b3fc6fa09b7ac0bf45474b216f8e152433433193b6e5db6da465ddd5c0e7d23b6a2e153998e0e936539aa3ce4f1ed448157dff1f420c404c019ec5e86ab18a9b859cc3165a7f104f3a7a9abb6835a62834750f110730e7d16de16cbb7f6607fc4ae04de5baec980e3137766c23568f8bb03473d3e043d3a8d8da0a2613bf27d0ce388ed44b8e1a217b2ef5193d19fb6b943c1b8a1bebfb02b9cea87fec0edbe03ee63a3a1168c53456af1fed9fe7707b2fb58159922cb84e1e28a29d26e036c12c91666096d556eefada060c530a28837f37a456847a26fcee92092837c14144ac3e1f3a84763e40cced0d77dcfe76f537825e08d2441d612d5e80eef617ffa6b96e30825d8905bef96dd4da8457f8d43e3f3c0294443c0b5a5a2a1b2f32f6402873c7de17276ec66b0fddf246fcb305e88a09c45e1c1322d5e152216d09a02654e83b503454dfeacd52129b4956ad300a9d52ca9f955f1babb56a1a676f243ce7ef69cacbfb23cb71907a6b8ff1a42c4769c5298d5fd5027e1c352a582231a5323b02da24ba5c2df5e125554ed0ee1cb5e9e65eda5c683469d264c9f0adbfc5fcbb3459da30ef31dd7cb32a9d5d6d2b412db81df3345f09065151b0190ec07ff0c5573d4c783be1f8aeb27d8042387352d62e808b24b834fef27d1c986da5207e5c9645026bff40577fc167b321fa17b31872bc0f796dc834f66f9302a4ce505f3f1e865a0ba9be615efe25dbdb2c3b61bc03206e6891469ce11c4065a2fcf03cb436d9182d66ce452038ac5f4fd8dc61e20f4a4f8cb7ad81e9a66c8b12d592c445ffe905495bf1e277de55a10da8c48dfdb0db1c2d2be9077c47326d0611dff08131063680fd858ad72e53d3eafe0a85f436eb3e03100a0f98057ddf1c47372ff318bad1b3cae928aeaf98608e397e4d8aa0c2fa594eaa9386e6fc8642077cc6c2f81a3e59704269a556eeb90161ef0f7271b798a5ac6430e0986d6c6c5b0ddeb2ef22c873a338824ba46bd3b634cd30143d66237eed3d89041e38e178f1dee6a5c0da039804face0a90c6c8b58a5b86b402e964678029a71c8c4c82ffba9fdef3c055493eef3e61b5e3aef9cc73816eb3360d2c719b198428f5a904ee1f241b20712aa67f4737fe56ba3884bc0aaaee8faa2d39ccf125f92c35877bb0ecccf0d95376a30464873475f62faadb18013e3cc879c4e42b166d20042980b84aa9be48ef7578664464956caabcbf3ab2cec3f87b0ae1c7d3ebe2234489491ceb0f4b3445308dc4c41f68ada861c95e9f0b0ed2da0b9bdc882923a4ec7118fe6eb1af554aa018c7df6f6987c353ef63017add74324b46c5a6910f8d929ff3d2ec271207fa7220ddaec2c3746fb8a12d49b2b0e8896a08f44e49c58ebe7eae582982e7bd5abd9289da25cddeb8e14c56faf1443be3a51516ac8eb463b643b10bec77052b48397bdae8a3948b19a58a98c2ded30b54abad2d930fcbb4ac74e6557b8764bafc566988071e74e1f516b367fcb6cbc23ce4171dbe8bbdfd8347f121e509052bc1870dd22bdfcbfca952ccd751005dd11649a3ee9db35a65d1975166a29a1186381f4055db5940ffc4034c68360f1c3ef6a20a7aece3e084d8c67eb48dddb3ec4c964c11826172edf44bae8676b2cfcf81cdf2f16e642081944a46bd2ddfffcb0b1862d83ef5592e57409c8f7b6d359a2d0cb1d1fd0d2f55428144764f0127ad78d202c0fdbc6ee5139d33fc78183199115dc21a4a7a006559deda04f01a21d32a41950d324f1b728583daaadd4c355c04a9496e485393803099ce10627f214bf872f1dd3848afe1e884e21db791a596cd7e9eb5cb1ed24ddaee49b90baf83425f48067c367b7038db82ba50ecc5363cc9ef954c583e3eaaaa9579e34a8f28acdc51f857154bfa3db2cbff5b0513f5d91de7195922e4f092602b0c4e2efae95f00030cb8f9a9f717917e279d5c4139f54866e765b3db872b7a6085452bb9a548c3613b458bb41aa80b56e6b47bcc1af86ea391ad446a5d1f3552255645ac224653a52e0ac112c84455979a58bac88eccd346ed99a6ab7fccb98daa062e387fe31501be23406cbd48e44f11801b75dfe93efadc49564ce57afd4cfd39cd1616f8e50b16e8e06311c04e4c98ba4fed7496666e6526cfbc5a9d3121fb25e9744914bfad8c3de1a18b942f7f0dccd89d0ed3a3e4d84d2664acf781e365bb3c2b3e9340db66b8b2a5850535898113f0e9e1e215c70c5241e82c005b2e45e1d73f51b6cc8adf2a0f5e6a931005fd6bd5e572937f79f75b0bc09e6e606e3769b23ee96ddeb3058d7f7fc9c9c0dfce5486032be1478fa5452d9ed019025760543179b002e68f1e9483e35d50bbab770b2639ad95f6667a59451de23f45cc7e50f1ec55374426e16a9ab3d6f8d16da2c7ff020e7972a66bb05bd707ac78c51c2238442eb24cad8db44439388e979714d5a5146c5c1609dbdcce2f5d8040f50dd2b83f57577c6e4795b6e753a58075939429cc4afce88e212e0fb09fe462b81c2b53cf0e7f8c483e5bebc3ed9dd29302d527a8994bf1564d80c5f93e724256f5462eceddfb42643c0f9626c16f04f438ce1838037620a5cb25347603955a29c6ca4a9cc9ca7a6f4b0f70c31bce11a30ddb456284df75774f1e7a43fcece176d91681ecaaaf03163d214a0164ce8408346e32548b04c050ad536e030bd5937a889faf49e58a7541c4a851f7d7e3033cb67736922bd501c9e3f9874ccb15d83814b2289e5b189e465b8e2bf2e2c7fd3809acbb3006c6cc52794efe490c81a9aa47e70041fe83d665501755fdb58aec42b0868bacccc64cdc93718357292a1194bae59dd878d0652a8f3617ac27d70bad6a13ed603dd5cbaa3bad81be71080d5d83b17e17268ab2886305dd1255f71513bfec828b09d8fec5747cdbb04fbac230328554f5c5a1447767be43e3478e6656470df605b8f8f6da8e1180d27ba691e81544c70ee865be596a9189474a4ecd5d747c1dce7b13d6d87548f365e261e9614fa0f23092eadc4736c507735cda4de06d0d26cc1b56e5f73ee90fe5b98bdb13da7deaa2b69ef45ebff11fb996f05bf20da22bf8b0ad42c709a66a96826330468621c11aec2037653676fdff88b8608620c6b66fd6dfe32d9a26e78ddc30af791353018d8ac8932c02750c4c65b7521b5b06ac67c6cfb7208c566e936a22c975542f898bd21c323633dd88de7e2cce6fcac321427616fd0251a4021bba684ec211d086d77c260b34f90e7e5fb6e8fc5d13093d206e968f90bc1ba4d81be9ce628240f45d6b2304d4325e584ff26ffce6c750a8ed717023314394d85522536ecad24329a5accbc07f729b420e51ae2376b91332372ca31340978f92efb651519a5c1b1a51bbe36937cbcc03d275f0b47b24268367116e3e10abd1c3309aa7ce34948cf71e28532a5461e677178b8b502a872a9fd2ce9dcc32ade49e6eacc2fd0d45b5eed217d5dc4eaee1285f7b84273722c11b31e6e5883a2cfafe1ddd932416dd370154dad23cf2cbf19fc457127ac0f798dc4c897baab75e5bdd9b716cc75960b63c046be1ac5899491715399e02e764b5843470cbeecb09593c3fcc219174af4ae3676e42474086de66af619367f2f2d8c35debf4c05e30d977b927c859106e93881eabd412cdb1e9fe57a888a887baa68f1430eb8b024a2cff4e1261862564c41c691fb2a6f23698ac59b337049a9fa7f181aa0e3097da72004ad10cf102e94399b59230e8144be80b3c615a3181e8c5d3a04301000180a7ad67c40d615de0cd11824b672a8de6c641f3838ffff23d44b5bacc7c4c388d2a7f424b83ca04c468823634b0efc5f267a281d2e13bc9d30604a6688062aefd4d0b60230000000000000001199a003a0c07eb5fc7ff995a228aacd2ec3719819a9dec0aa26d10adc9c1a58d836093180ca76a3f8f67ac72668e909264852a2d1427ec85a02544219dc00181ec605ec8cbaa7af879501cd3a4e7398d78af3aaba9d5d6ea0504404ea1312b90c3628bea1d458c296594d773e3fa86b0ae1bd70845a8ac82e8c9386ff2da6d2739f74b221bcd68e3412a20d16bcc951869942da413f7a2cedb06c4fbcf3a89e5898314c35e6ddf3dc657f24f4c828f2c73604d14b312b2962e1b50494d294751f861c9343fcc2e3734545f25219cc48a099881d3bde6cfc64f54a21c934388a1c93f0a396b4cfd356a86e36e63dd9ea10196a10cdac69fc7f38a36fcf91521af60918d3083e57ee9413edec7f660af704e966b45a84cc14e0c56831ca27ef5082c291852f60a31305a36238daee77bb447e988319135e4fc2be7fa0db7b145874164f90589bff507f32f8c4ef27b4697283c955e84925552e8d61419ad08b2b40b55fb729b76034610f5606c930b6d4eb5578b27547554200e9185c27ec84169f2db8341783bbbaffc76b80e557974ae40de2acac657b8d1f03e49ed4ddf298083bcfdea14d01f7a31ea731dd2cfaf2a5a229847ac227d7c14ec1a68e2d748b63182515571c4e41dc69b95c6467316b0be33da252a32b27cf35e0d0a9a759cf9c7ee84489ed1254214c586d8ddb6a228e6498dc7379c49b344b160447c7e01cbfcbe92eab3eba4da9664b5db003486ddfca31864d16fe51851bb043f62723d3ef03452a263e4dd11da93ce9f7dc2db5ae16b64a2ce07d81d4a2bd35d62abbe05ec7b2af6327c99a04c0b9316942fa74878bd91b96bc1304e6f2be7e50ccf7bc866ad37fb34effe83700d3ea93e220d5251dfad1af156b84f4fa9d97dcc62f140c26f8369716d9ceaa5ffc69a9ee647fbdc648da9eabbd6e36a271a00840ce75e9addee57074b866429b98547c3c380b9defef2b65742ed5fa4b4acaa59324ed8cc491e51f4c15a34a3b712c91acb9c5cad43be2e481206f5e8be006eb6d632a31df1bc2bce4e267ae48c75c10d7ad7d54b4a3579bdc8c27cee6f7067a63acba681a34eeaeebee359d82ba0bea46baecdc40c641f9995ca3f7daa9c5679ed160fad6b3755466cd463d3e7a117ba3c311ba7aba451b288a02c3b0c462f21dbc0dfd1cd805d40bcf85d78bfa7a1a689edb599f5d54956d3a11d5f3f2b0b0cb72851605cb7e90f9401e9be9f6f1014a43502dec2291f3b583c99ad4192ee5c3bb01024aebed7d3276cf61bf5bbc495174c6bd8a9ab37a166e9b48da9216d7f476199566827a329ec3ed48892a4b19d7c2be4aa7f0bd1843aea86869615df5ad8cb327874ab9d297270140cf519994c425c4d08700360dd3427e7be91521cfd671f844e28d3e1298c1b81be596e2aafc42e727697b30c981eb70a104d8277cdedf55dccd4ceb95657ddf30d9990ba1d2c67b6ae863c7dbb7d1898cf90181f3375bc7c7ca42fbd6a51d30ea19331fd9fd93a0b68d985505296c89e0d2f38871546c9d6805459f9c26e8f503673823d34a03ba63090c499ad21a1629197f772dea62f4989e8ebde6e18cedfcba7ab3956df479d59a2e19d86b1a3c0ed8fc298871b270a720b6853f6609bc33d095ce2d506b7b32c4f63ea30b4b484c29c616ff6a800aaa080f1374c5f72cb6e186e56b6ecd9de8bbdc79a4282182867eaf41e1e789caadb4a01dd9eafadab1035396434112db932e3d4a9a7c2d5ab635e2917c1ee3242bc98e6b36499a588b90abd7224619e9421c53f710f3bad74db88305c1af4d4bb97438d49a8d46257d7adc3290e96bb05029f78f1cc54cabc21da94c768400a0a7ddcb147df8dc2b6353d261b48a47eccca5ffaff80e9fb5ecea1efa940806777c16c0ccebf5d5c9c8d3d64afc1ceb72aad306390ee4e1ce418317d229547cf7d96fa6c3e72624d138438ac3df68b6cdf4bb54812cd31dac2e5ab2d4090ca8a01de888199b205ab31933227646c8b6e8faddf08dd94438cc0fdf5b4c8ef7c48123b8c9d16a09162895c75469447ee4630a5c52f716ceb3fc73653f56fc90753dcde00c7e1b4e46a9a1f40674fd130dea42f935d9e811261057871e4367ec42b9b6127f3687e10e6777b3e4d537695d01a5053c14a70b6435c624cdcc93c4b9fc68726590d64d8ed3ac9b74609851f868e03568ced113968babeef5d4eb95b33d0c0d196d55f58bb394ed9109c89f3f8317cfdbac738aaeed72afcf146dd5e3f2555e77f0d959263961c55989b01dc47172103c1a27050ffd5272ef700aa1cf24ef2e2c1c640251b64567a55ba813389e5b851764ab6966fcd08f2e33ef77eadaf83d7c734dd849e5ff0e9a18b5739d7322600b0d8b459cefb9eb424a481043e0bd67af17fe15de1269f3f96173925ef0dfef6b39fccf35d9a961f682dd9d976e735c6fc7139e7c398e0af4488a0760766e5dca6d1a3d8641d872ee1614d55d9a31929207adc0e813594f2571eac8160f882ee9ccefdeeb3cb98a2b885871ce17a4262b4c0bc53b21491d86866e5bcce058aa978bd84b0a21ff4e03a6547054e8f41b5b24926ee808c50f6f857bf09e070612b9816cd79eb18cc7ce58f84404d031fd7f8d9433880ec5a40090625e6580337ff84b10de7331a9cf93aa81768fccda2efaa8a9617c788540726662194d17be8cbb7e5799a7766294fa11fcfa34955f5ffefeca4356a58b255104b5a84822789dbab7f99393410eb356dd2694b5c5068566c572c11ca4aac9820461560488691bb11ee2dffbe5b87118ed017d3e4a1fe9c4f1c9bd18b70ccac6691ca104b90d376d6763537ba767caef629d3c940b5f96857d7bd3e1927193e4daba0b6c0c99ed89e2a177e3cc80cd37bfb9613ca9a4aea47eb311353aae84e5fd231531428635178a05e7c59251305c8a0c9ea66d8ad73ea7288379e49ce1f6afd59c13163f00720105810681fe57ca8980f0945c4d8d490e2fd70141485ade4b2f1c9434b7d2593490810b5018c06cdf8729c17cbc17f44a2bbe242e4e6a905e53910139375dfe05f48baa0d5f13ea1830c85c5188206ff68c3578b860fd201b8aa8ef87cbbfc2784d2f0db470bcfe9b693cf2286d7c1834746159e7710e00878ba814ace639765b08fc36a0862b80a06445a05b85e71fa5132e8697a73085afc1ea11a91d8373be39ea60b0e7d6a7cd66872eb91a3dd24aeedaac82f9f3c459f0020dc636b42b55f5b379b50bbca6a6fe80aaa7c8cd629cd735675787f82905eb5139e79337ab0da46a0f56ad6abcf7af9cb0b7f5a9675aae6e9bb11918fbb2f5a9c7efefb8b610ba55b748b4e5b5f58b67a188fbee42e3ddd57a34bf696e9720081e4f510c6b4e928984ac75525bf3c7b22c2dd21e4a2a292e1497b69aa7843fd23f00aee321abfd59a821126e2df88e1bda8a4d6d2dfca3702cb24933b0692a3430e5839663da12b4223ec334fa7be72640c1e7554ad58b08962059cd29270021daef264b0269a24b79b18f041fb8ffc78bf491c9f2665fae997f2373bc4616cf269cdadedd061ed983c076130897e4a43b0db1214a83c18e5be77642fad84e66cc0dfcff4cbc22d025c9c23ad1472a32b77f0b7c3fb9bc85e23ec498baf3cafb14b341699ae65e257835e1b8ceffed3f958077e0678d959e03c4cffdf5baef730b5697f042d1e7d869e3b34c318c2928f56a78bbdb5fcf9ec0db2ad0ebab630a0b010114bea72c5017667021a311fab8a7ac1fee3587624b2561e447ef9f0bdac31e2e923fd5b2affb3d2efc9ce16bd2930682caaeea2b3197b142cab7767c1a043fc3e39ddfcdff3f520d89efd43d06bfbd95055df25bb55a0138bd187ba99cdc4c469f1e4d8da05f68117cbe6c0f56be0b3b2605c4185adf48df8b113210e2752070a1c2409eeda7764c4c0bb66b6c3ef6e1e02de7c13f19ff730edd70fdca25d76c77c839d19665156b6c8a3dee400f68abe17a270fee5207ae82137719936ce29e9351f7cedf02b14a6033d228b2edb522104eca5c27a7567bba3b8ca80b3f1aa8cb9e9e5464a7a73bf09606ecc6d2c9390cdb20000"
		txid := "fc6cd0e025c7dc866ebe2b4b3f3449f213a17a62ed6438c3f6894ecdbf0bc117"
		vout := uint32(1)

		// prepare signature
		pubkey, privkey, _, err := CfdGoCreateKeyPair(
			handle, true, (int)(KCfdNetworkElementsRegtest))
		assert.NoError(t, err)
		dummyPubkey := "0229ebd1cac7855ca60b0846bd179ff3d411f807f3f3a43abf498e0a415c94d622"
		redeemScript, err := CfdGoCreateScript(
			handle, []string{"OP_1", pubkey, dummyPubkey, "OP_2", "OP_CHECKMULTISIG"})
		assert.NoError(t, err)
		sighashType := (int)(KCfdSigHashAll)
		valueCommitment := "0993c069270bf8d090ce8695b82e52fb2959a9765d987d4ffd7a767b0c5b1c4cbc"
		sighash, err := CfdGoCreateConfidentialSighash(handle, txHex, txid, vout,
			(int)(KCfdP2wsh), "", redeemScript, int64(0), valueCommitment, sighashType, false)
		assert.NoError(t, err)
		signature, err := CfdGoCalculateEcSignature(handle, sighash, privkey, "", 0, true)
		assert.NoError(t, err)

		// check signature
		result, err := CfdGoVerifyConfidentialTxSignature(handle, txHex, signature, pubkey, redeemScript, txid, vout, sighashType, false, int64(0), valueCommitment, (int)(KCfdWitnessVersion0))
		assert.NoError(t, err)
		assert.True(t, result)
		// check signature
		result, err = CfdGoVerifyConfidentialTxSignatureByIndex(handle, txHex, signature, pubkey, redeemScript, 0, sighashType, false, 0, valueCommitment, (int)(KCfdWitnessVersion0))
		assert.NoError(t, err)
		assert.True(t, result)
	})
}

func TestCfdGoNormalizeSignature(t *testing.T) {
	handle, err := CfdGoCreateHandle()
	assert.NoError(t, err)
	defer CfdGoFreeHandle(handle)

	signature := "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5f67f6cf81a19873091aa7c9578fa2e96490e9bfc78ae7e9798004e8252c06287"
	expectedSig := "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee509809307e5e678cf6e55836a8705d16871a040ea369a21a427d2100a7d75deba"

	// prepare pkh signature
	normalized, err := CfdGoNormalizeSignature(handle, signature)
	assert.NoError(t, err)
	assert.Equal(t, expectedSig, normalized)
}

// last test
/* comment out.
func TestFinalize(t *testing.T) {
	ret := CfdFinalize(false)
	assert.NoError(t, err)
	fmt.Print("TestFinalize test done.\n")
}
*/
