package cfdgo

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
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

	handle, ret := CfdGoCreateHandle()
	assert.Equal(t, (int)(KCfdSuccess), ret)

	ret = CfdFreeHandle(handle)
	assert.Equal(t, (int)(KCfdSuccess), ret)
	fmt.Print("TestCfdCreateHandle test done.\n")
}

func TestCfdGetLastError(t *testing.T) {
	handle, ret := CfdGoCreateHandle()
	assert.Equal(t, (int)(KCfdSuccess), ret)

	lastErr := CfdGetLastErrorCode(handle)
	assert.Equal(t, (int)(KCfdSuccess), lastErr)

	errStr, strret := CfdGoGetLastErrorMessage(handle)
	assert.Equal(t, (int)(KCfdSuccess), strret)
	assert.Equal(t, "", errStr)

	_, _, _, strret = CfdGoCreateAddress(handle, 200, "", "", 200)
	lastErr = CfdGetLastErrorCode(handle)
	assert.Equal(t, (int)(KCfdIllegalArgumentError), lastErr)
	assert.Equal(t, strret, lastErr)
	errStr, _ = CfdGoGetLastErrorMessage(handle)
	assert.Equal(t, "Illegal network type.", errStr)

	ret = CfdFreeHandle(handle)
	assert.Equal(t, (int)(KCfdSuccess), ret)
	fmt.Print("TestCfdGetLastError test done.\n")
}

func TestCfdGetSupportedFunction(t *testing.T) {
	handle, ret := CfdGoCreateHandle()
	assert.Equal(t, (int)(KCfdSuccess), ret)

	flag, cfdRet := CfdGoGetSupportedFunction()
	assert.Equal(t, (int)(KCfdSuccess), cfdRet)
	assert.Equal(t, uint64(1), (flag & 0x01))

	ret = CfdFreeHandle(handle)
	assert.Equal(t, (int)(KCfdSuccess), ret)
	fmt.Print("TestCfdGetSupportedFunction test done.\n")
}

func TestCfdGoCreateAddress(t *testing.T) {
	handle, ret := CfdGoCreateHandle()
	assert.Equal(t, (int)(KCfdSuccess), ret)

	hashType := (int)(KCfdP2pkh)
	networkType := (int)(KCfdNetworkLiquidv1)
	pubkey := "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
	address, lockingScript, segwitLockingScript, cfdRet := CfdGoCreateAddress(handle, hashType, pubkey, "", networkType)
	assert.Equal(t, (int)(KCfdSuccess), cfdRet)
	assert.Equal(t, "Q7wegLt2qMGhm28vch6VTzvpzs8KXvs4X7", address)
	assert.Equal(t, "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac", lockingScript)
	assert.Equal(t, "", segwitLockingScript)
	if cfdRet != (int)(KCfdSuccess) {
		errStr, _ := CfdGoGetLastErrorMessage(handle)
		fmt.Print("[error message] " + errStr + "\n")
	}

	hashType = (int)(KCfdP2sh)
	redeemScript := "210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac"
	address, lockingScript, segwitLockingScript, cfdRet = CfdGoCreateAddress(
		handle, hashType, "", redeemScript, networkType)
	assert.Equal(t, (int)(KCfdSuccess), cfdRet)
	assert.Equal(t, "GkSEheszYzEBMgX9G9ueaAyLVg8gfZwiDY", address)
	assert.Equal(t, "a91423b0ad3477f2178bc0b3eed26e4e6316f4e83aa187", lockingScript)
	assert.Equal(t, "", segwitLockingScript)
	if cfdRet != (int)(KCfdSuccess) {
		errStr, _ := CfdGoGetLastErrorMessage(handle)
		fmt.Print("[error message] " + errStr + "\n")
	}

	hashType = (int)(KCfdP2shP2wpkh)
	pubkey = "0205ffcdde75f262d66ada3dd877c7471f8f8ee9ee24d917c3e18d01cee458bafe"
	address, lockingScript, segwitLockingScript, cfdRet = CfdGoCreateAddress(
		handle, hashType, pubkey, "", networkType)
	assert.Equal(t, (int)(KCfdSuccess), cfdRet)
	assert.Equal(t, "GsaK3GXnFAjdfZDBPPo9PD6UNyAJ53nS9Z", address)
	assert.Equal(t, "a9147200818f884ee12b964442b059c11d0712b6abe787", lockingScript)
	assert.Equal(t, "0014ef692e4bf0cd5ed05235a4fc582ec4a4ff9695b4", segwitLockingScript)
	if cfdRet != (int)(KCfdSuccess) {
		errStr, _ := CfdGoGetLastErrorMessage(handle)
		fmt.Print("[error message] " + errStr + "\n")
	}

	hashType = (int)(KCfdP2wpkh)
	networkType = (int)(KCfdNetworkElementsRegtest)
	pubkey = "02bedf98a38247c1718fdff7e07561b4dc15f10323ebb0accab581778e72c2e995"
	address, lockingScript, segwitLockingScript, cfdRet = CfdGoCreateAddress(
		handle, hashType, pubkey, "", networkType)
	assert.Equal(t, (int)(KCfdSuccess), cfdRet)
	assert.Equal(t, "ert1qs58jzsgjsteydejyhy32p2v2vm8llh9uns6d93", address)
	assert.Equal(t, "0014850f21411282f246e644b922a0a98a66cfffdcbc", lockingScript)
	assert.Equal(t, "", segwitLockingScript)
	if cfdRet != (int)(KCfdSuccess) {
		errStr, _ := CfdGoGetLastErrorMessage(handle)
		fmt.Print("[error message] " + errStr + "\n")
	}

	ret = CfdFreeHandle(handle)
	assert.Equal(t, (int)(KCfdSuccess), ret)
	fmt.Print("TestCfdGoCreateAddress test done.\n")
}

func TestCfdGoCreateMultisigScript(t *testing.T) {
	handle, ret := CfdGoCreateHandle()
	assert.Equal(t, (int)(KCfdSuccess), ret)

	networkType := (int)(KCfdNetworkLiquidv1)
	hashType := (int)(KCfdP2shP2wsh)
	pubkeys := []string{"0205ffcdde75f262d66ada3dd877c7471f8f8ee9ee24d917c3e18d01cee458bafe", "02be61f4350b4ae7544f99649a917f48ba16cf48c983ac1599774958d88ad17ec5"}
	address, redeemScript, witnessScript, cfdRet := CfdGoCreateMultisigScript(handle, networkType, hashType, pubkeys, uint32(2))
	assert.Equal(t, (int)(KCfdSuccess), cfdRet)
	assert.Equal(t, "H4PB6YPgiTmQLiMU7b772LMFY9vA4gSUC1", address)
	assert.Equal(t, "0020f39f6272ba6b57918eb047c5dc44fb475356b0f24c12fca39b19284e80008a42", redeemScript)
	assert.Equal(t, "52210205ffcdde75f262d66ada3dd877c7471f8f8ee9ee24d917c3e18d01cee458bafe2102be61f4350b4ae7544f99649a917f48ba16cf48c983ac1599774958d88ad17ec552ae", witnessScript)
	if cfdRet != (int)(KCfdSuccess) {
		errStr, _ := CfdGoGetLastErrorMessage(handle)
		fmt.Print("[error message] " + errStr + "\n")
	}

	ret = CfdFreeHandle(handle)
	assert.Equal(t, (int)(KCfdSuccess), ret)
	fmt.Print("TestCfdGoCreateMultisigScript test done.\n")
}

func TestCfdGoGetAddressesFromMultisig(t *testing.T) {
	handle, ret := CfdGoCreateHandle()
	assert.Equal(t, (int)(KCfdSuccess), ret)

	networkType := (int)(KCfdNetworkLiquidv1)
	hashType := (int)(KCfdP2shP2wpkh)
	redeemScript := "52210205ffcdde75f262d66ada3dd877c7471f8f8ee9ee24d917c3e18d01cee458bafe2102be61f4350b4ae7544f99649a917f48ba16cf48c983ac1599774958d88ad17ec552ae"
	addressList, pubkeyList, cfdRet := CfdGoGetAddressesFromMultisig(handle, redeemScript, networkType, hashType)
	assert.Equal(t, (int)(KCfdSuccess), cfdRet)
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
	if cfdRet != (int)(KCfdSuccess) {
		errStr, _ := CfdGoGetLastErrorMessage(handle)
		fmt.Print("[error message] " + errStr + "\n")
	}

	ret = CfdFreeHandle(handle)
	assert.Equal(t, (int)(KCfdSuccess), ret)
	fmt.Print("TestCfdGoGetAddressesFromMultisig test done.\n")
}

func TestCfdGoParseDescriptor(t *testing.T) {
	handle, ret := CfdGoCreateHandle()
	assert.Equal(t, (int)(KCfdSuccess), ret)

	// PKH
	networkType := (int)(KCfdNetworkLiquidv1)
	descriptorDataList, multisigList, cfdRet := CfdGoParseDescriptor(handle,
		"pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)",
		networkType,
		"")
	assert.Equal(t, (int)(KCfdSuccess), cfdRet)
	assert.Equal(t, 1, len(descriptorDataList))
	assert.Equal(t, 0, len(multisigList))
	if len(descriptorDataList) == 1 {
		assert.Equal(t, uint32(0), descriptorDataList[0].depth)
		assert.Equal(t, (int)(KCfdDescriptorScriptPkh), descriptorDataList[0].scriptType)
		assert.Equal(t, "76a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac", descriptorDataList[0].lockingScript)
		assert.Equal(t, "PwsjpD1YkjcfZ95WGVZuvGfypkKmpogoA3", descriptorDataList[0].address)
		assert.Equal(t, (int)(KCfdP2pkh), descriptorDataList[0].hashType)
		assert.Equal(t, "", descriptorDataList[0].redeemScript)
		assert.Equal(t, (int)(KCfdDescriptorKeyPublic), descriptorDataList[0].keyType)
		assert.Equal(t, "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5", descriptorDataList[0].pubkey)
		assert.Equal(t, "", descriptorDataList[0].extPubkey)
		assert.Equal(t, "", descriptorDataList[0].extPrivkey)
		assert.Equal(t, false, descriptorDataList[0].isMultisig)
	}
	if cfdRet != (int)(KCfdSuccess) {
		errStr, _ := CfdGoGetLastErrorMessage(handle)
		fmt.Print("[error message] " + errStr + "\n")
	}

	// p2sh-p2wsh(pkh)
	networkType = (int)(KCfdNetworkLiquidv1)
	descriptorDataList, multisigList, cfdRet = CfdGoParseDescriptor(handle,
		"sh(wsh(pkh(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13)))",
		networkType, "")
	assert.Equal(t, (int)(KCfdSuccess), cfdRet)
	assert.Equal(t, 3, len(descriptorDataList))
	assert.Equal(t, 0, len(multisigList))
	if len(descriptorDataList) == 3 {
		// 0
		assert.Equal(t, uint32(0), descriptorDataList[0].depth)
		assert.Equal(t, (int)(KCfdDescriptorScriptSh), descriptorDataList[0].scriptType)
		assert.Equal(t, "a91455e8d5e8ee4f3604aba23c71c2684fa0a56a3a1287", descriptorDataList[0].lockingScript)
		assert.Equal(t, "Gq1mmExLuSEwfzzk6YtUxJ769grv6T5Tak", descriptorDataList[0].address)
		assert.Equal(t, (int)(KCfdP2shP2wsh), descriptorDataList[0].hashType)
		assert.Equal(t, "0020fc5acc302aab97f821f9a61e1cc572e7968a603551e95d4ba12b51df6581482f", descriptorDataList[0].redeemScript)
		assert.Equal(t, (int)(KCfdDescriptorKeyNull), descriptorDataList[0].keyType)
		assert.Equal(t, "", descriptorDataList[0].pubkey)
		assert.Equal(t, "", descriptorDataList[0].extPubkey)
		assert.Equal(t, "", descriptorDataList[0].extPrivkey)
		assert.Equal(t, false, descriptorDataList[0].isMultisig)
		// 1
		assert.Equal(t, uint32(1), descriptorDataList[1].depth)
		assert.Equal(t, (int)(KCfdDescriptorScriptWsh), descriptorDataList[1].scriptType)
		assert.Equal(t, "0020fc5acc302aab97f821f9a61e1cc572e7968a603551e95d4ba12b51df6581482f", descriptorDataList[1].lockingScript)
		assert.Equal(t, "ex1ql3dvcvp24wtlsg0e5c0pe3tju7tg5cp428546jap9dga7evpfqhs0htdlf", descriptorDataList[1].address)
		assert.Equal(t, (int)(KCfdP2wsh), descriptorDataList[1].hashType)
		assert.Equal(t, "76a914c42e7ef92fdb603af844d064faad95db9bcdfd3d88ac", descriptorDataList[1].redeemScript)
		assert.Equal(t, (int)(KCfdDescriptorKeyNull), descriptorDataList[1].keyType)
		assert.Equal(t, "", descriptorDataList[1].pubkey)
		assert.Equal(t, "", descriptorDataList[1].extPubkey)
		assert.Equal(t, "", descriptorDataList[1].extPrivkey)
		assert.Equal(t, false, descriptorDataList[1].isMultisig)
		// 2
		assert.Equal(t, uint32(2), descriptorDataList[2].depth)
		assert.Equal(t, (int)(KCfdDescriptorScriptPkh), descriptorDataList[2].scriptType)
		assert.Equal(t, "76a914c42e7ef92fdb603af844d064faad95db9bcdfd3d88ac", descriptorDataList[2].lockingScript)
		assert.Equal(t, "QF9hGPQMVAPc8RxTHALgSvNPWEjGbL9bse", descriptorDataList[2].address)
		assert.Equal(t, (int)(KCfdP2pkh), descriptorDataList[2].hashType)
		assert.Equal(t, "", descriptorDataList[2].redeemScript)
		assert.Equal(t, (int)(KCfdDescriptorKeyPublic), descriptorDataList[2].keyType)
		assert.Equal(t, "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13", descriptorDataList[2].pubkey)
		assert.Equal(t, "", descriptorDataList[2].extPubkey)
		assert.Equal(t, "", descriptorDataList[2].extPrivkey)
		assert.Equal(t, false, descriptorDataList[2].isMultisig)
	}
	if cfdRet != (int)(KCfdSuccess) {
		errStr, _ := CfdGoGetLastErrorMessage(handle)
		fmt.Print("[error message] " + errStr + "\n")
	}

	// multisig (bitcoin)
	networkType = (int)(KCfdNetworkMainnet)
	descriptorDataList, multisigList, cfdRet = CfdGoParseDescriptor(handle,
		"wsh(multi(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))",
		networkType,
		"0")
	assert.Equal(t, (int)(KCfdSuccess), cfdRet)
	assert.Equal(t, 1, len(descriptorDataList))
	assert.Equal(t, 2, len(multisigList))
	if len(descriptorDataList) == 1 {
		assert.Equal(t, uint32(0), descriptorDataList[0].depth)
		assert.Equal(t, (int)(KCfdDescriptorScriptWsh), descriptorDataList[0].scriptType)
		assert.Equal(t, "002064969d8cdca2aa0bb72cfe88427612878db98a5f07f9a7ec6ec87b85e9f9208b", descriptorDataList[0].lockingScript)
		assert.Equal(t, "bc1qvjtfmrxu524qhdevl6yyyasjs7xmnzjlqlu60mrwepact60eyz9s9xjw0c", descriptorDataList[0].address)
		assert.Equal(t, (int)(KCfdP2wsh), descriptorDataList[0].hashType)
		assert.Equal(t, "51210205f8f73d8a553ad3287a506dbd53ed176cadeb200c8e4f7d68a001b1aed871062102c04c4e03921809fcbef9a26da2d62b19b2b4eb383b3e6cfaaef6370e7514477452ae", descriptorDataList[0].redeemScript)
		assert.Equal(t, (int)(KCfdDescriptorKeyNull), descriptorDataList[0].keyType)
		assert.Equal(t, "", descriptorDataList[0].pubkey)
		assert.Equal(t, "", descriptorDataList[0].extPubkey)
		assert.Equal(t, "", descriptorDataList[0].extPrivkey)
		assert.Equal(t, true, descriptorDataList[0].isMultisig)
	}
	if len(multisigList) == 2 {
		assert.Equal(t, (int)(KCfdDescriptorKeyBip32), multisigList[0].keyType)
		assert.Equal(t, "0205f8f73d8a553ad3287a506dbd53ed176cadeb200c8e4f7d68a001b1aed87106", multisigList[0].pubkey)
		assert.Equal(t, "xpub6BgWskLoyHmAUeKWgUXCGfDdCMRXseEjRCMEMvjkedmHpnvWtpXMaCRm8qcADw9einPR8o2c49ZpeHRZP4uYwGeMU2T63G7uf2Y1qJavrWQ", multisigList[0].extPubkey)
		assert.Equal(t, "", multisigList[0].extPrivkey)
		assert.Equal(t, (int)(KCfdDescriptorKeyBip32), multisigList[1].keyType)
		assert.Equal(t, "02c04c4e03921809fcbef9a26da2d62b19b2b4eb383b3e6cfaaef6370e75144774", multisigList[1].pubkey)
		assert.Equal(t, "xpub6EKMC2gSMfKgQJ3iNMZVNB4GLH1Dc4hNPah1iMbbztxdUPRo84MMcTgkPATWNRyzr7WifKrt5VvQi4GEqRwybCP1LHoXBKLN6cB15HuBKPE", multisigList[1].extPubkey)
		assert.Equal(t, "", multisigList[1].extPrivkey)
	}
	if cfdRet != (int)(KCfdSuccess) {
		errStr, _ := CfdGoGetLastErrorMessage(handle)
		fmt.Print("[error message] " + errStr + "\n")
	}

	ret = CfdFreeHandle(handle)
	assert.Equal(t, (int)(KCfdSuccess), ret)
	fmt.Print("TestCfdGoParseDescriptor test done.\n")
}

// last test
func TestFinalize(t *testing.T) {
	ret := CfdFinalize(false)
	assert.Equal(t, (int)(KCfdSuccess), ret)
	fmt.Print("TestFinalize test done.\n")
}
