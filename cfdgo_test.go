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

// last test
/* comment out.
func TestFinalize(t *testing.T) {
	ret := CfdFinalize(false)
	assert.NoError(t, err)
	fmt.Print("TestFinalize test done.\n")
}
*/
