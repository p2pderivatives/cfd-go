package cfdgo

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// GetFuncName
func GetFuncName() string {
	pc, _, _, _ := runtime.Caller(1)
	funcName := runtime.FuncForPC(pc).Name()
	index := strings.LastIndex(funcName, ".")
	return funcName[index+1:]
}

// first test
func TestInitialize(t *testing.T) {
	ret := CfdInitialize()
	assert.Equal(t, (int)(KCfdSuccess), ret)
	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdCreateHandle(t *testing.T) {
	ret := CfdCreateHandle(nil)
	assert.Equal(t, (int)(KCfdIllegalArgumentError), ret)

	handle, err := CfdGoCreateHandle()
	assert.NoError(t, err)

	err = CfdGoFreeHandle(handle)
	assert.NoError(t, err)
	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdGetLastError(t *testing.T) {
	handle, err := CfdGoCreateHandle()
	assert.NoError(t, err)

	lastErr := CfdGetLastErrorCode(handle)
	assert.Equal(t, (int)(KCfdSuccess), lastErr)

	_, _, _, err = CfdGoCreateAddress(200, "", "", 200)
	assert.Contains(t, err.Error(), fmt.Sprintf("code=[%d]", KCfdIllegalArgumentError))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Illegal network type.")

	err = CfdGoFreeHandle(handle)
	assert.NoError(t, err)
	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdGetSupportedFunction(t *testing.T) {
	handle, err := CfdGoCreateHandle()
	assert.NoError(t, err)

	flag, err := CfdGoGetSupportedFunction()
	assert.NoError(t, err)
	assert.Equal(t, uint64(1), (flag & 0x01))

	err = CfdGoFreeHandle(handle)
	assert.NoError(t, err)
	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdGoCreateAddress(t *testing.T) {
	hashType := (int)(KCfdP2pkh)
	networkType := (int)(KCfdNetworkLiquidv1)
	pubkey := "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
	address, lockingScript, segwitLockingScript, err := CfdGoCreateAddress(hashType, pubkey, "", networkType)
	assert.NoError(t, err)
	assert.Equal(t, "Q7wegLt2qMGhm28vch6VTzvpzs8KXvs4X7", address)
	assert.Equal(t, "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac", lockingScript)
	assert.Equal(t, "", segwitLockingScript)
	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	hashType = (int)(KCfdP2sh)
	redeemScript := "210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac"
	address, lockingScript, segwitLockingScript, err = CfdGoCreateAddress(
		hashType, "", redeemScript, networkType)
	assert.NoError(t, err)
	assert.Equal(t, "GkSEheszYzEBMgX9G9ueaAyLVg8gfZwiDY", address)
	assert.Equal(t, "a91423b0ad3477f2178bc0b3eed26e4e6316f4e83aa187", lockingScript)
	assert.Equal(t, "", segwitLockingScript)
	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	hashType = (int)(KCfdP2shP2wpkh)
	pubkey = "0205ffcdde75f262d66ada3dd877c7471f8f8ee9ee24d917c3e18d01cee458bafe"
	address, lockingScript, segwitLockingScript, err = CfdGoCreateAddress(
		hashType, pubkey, "", networkType)
	assert.NoError(t, err)
	assert.Equal(t, "GsaK3GXnFAjdfZDBPPo9PD6UNyAJ53nS9Z", address)
	assert.Equal(t, "a9147200818f884ee12b964442b059c11d0712b6abe787", lockingScript)
	assert.Equal(t, "0014ef692e4bf0cd5ed05235a4fc582ec4a4ff9695b4", segwitLockingScript)
	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	hashType = (int)(KCfdP2wpkh)
	networkType = (int)(KCfdNetworkElementsRegtest)
	pubkey = "02bedf98a38247c1718fdff7e07561b4dc15f10323ebb0accab581778e72c2e995"
	address, lockingScript, segwitLockingScript, err = CfdGoCreateAddress(
		hashType, pubkey, "", networkType)
	assert.NoError(t, err)
	assert.Equal(t, "ert1qs58jzsgjsteydejyhy32p2v2vm8llh9uns6d93", address)
	assert.Equal(t, "0014850f21411282f246e644b922a0a98a66cfffdcbc", lockingScript)
	assert.Equal(t, "", segwitLockingScript)
	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdGoCreateMultisigScript(t *testing.T) {
	networkType := (int)(KCfdNetworkLiquidv1)
	hashType := (int)(KCfdP2shP2wsh)
	pubkeys := []string{"0205ffcdde75f262d66ada3dd877c7471f8f8ee9ee24d917c3e18d01cee458bafe", "02be61f4350b4ae7544f99649a917f48ba16cf48c983ac1599774958d88ad17ec5"}
	address, redeemScript, witnessScript, err := CfdGoCreateMultisigScript(networkType, hashType, pubkeys, uint32(2))
	assert.NoError(t, err)
	assert.Equal(t, "H4PB6YPgiTmQLiMU7b772LMFY9vA4gSUC1", address)
	assert.Equal(t, "0020f39f6272ba6b57918eb047c5dc44fb475356b0f24c12fca39b19284e80008a42", redeemScript)
	assert.Equal(t, "52210205ffcdde75f262d66ada3dd877c7471f8f8ee9ee24d917c3e18d01cee458bafe2102be61f4350b4ae7544f99649a917f48ba16cf48c983ac1599774958d88ad17ec552ae", witnessScript)
	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdGoGetAddressesFromMultisig(t *testing.T) {
	networkType := (int)(KCfdNetworkLiquidv1)
	hashType := (int)(KCfdP2shP2wpkh)
	redeemScript := "52210205ffcdde75f262d66ada3dd877c7471f8f8ee9ee24d917c3e18d01cee458bafe2102be61f4350b4ae7544f99649a917f48ba16cf48c983ac1599774958d88ad17ec552ae"
	addressList, pubkeyList, err := CfdGoGetAddressesFromMultisig(redeemScript, networkType, hashType)
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
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdGoGetAddressFromLockingScript(t *testing.T) {
	networkType := (int)(KCfdNetworkLiquidv1)
	lockingScript := "76a91449a011f97ba520dab063f309bad59daeb30de10188ac"
	address, err := CfdGoGetAddressFromLockingScript(lockingScript, networkType)
	assert.NoError(t, err)
	assert.Equal(t, "Q3ygD4rfNT2npj341csKqxcgDkBMwyD5Z6", address)

	lockingScript = "a914f1b3a2cc24eba8a741f963b309a7686f3bb6bfb487"
	address, err = CfdGoGetAddressFromLockingScript(lockingScript, networkType)
	assert.NoError(t, err)
	assert.Equal(t, "H5DXSnmWy4WuUU7Yr8bvtLa5nXgukNc3Z6", address)

	lockingScript = "0014925d4028880bd0c9d68fbc7fc7dfee976698629c"
	address, err = CfdGoGetAddressFromLockingScript(lockingScript, networkType)
	assert.NoError(t, err)
	assert.Equal(t, "ex1qjfw5q2ygp0gvn450h3lu0hlwjanfsc5uh0r5gq", address)

	lockingScript = "002087cb0bc07de5b5befd7565b2c63fb1681efd8af7bd85a3f0f98a529a5c50a437"
	address, err = CfdGoGetAddressFromLockingScript(lockingScript, networkType)
	assert.NoError(t, err)
	assert.Equal(t, "ex1qsl9shsrauk6malt4vkevv0a3dq00mzhhhkz68u8e3fff5hzs5sms77zw4m", address)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdGoGetAddressInfo(t *testing.T) {
	addr := "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
	info, err := CfdGoGetAddressInfo(addr)
	assert.NoError(t, err)
	assert.Equal(t, addr, info.Address)
	assert.Equal(t, (int)(KCfdNetworkMainnet), info.NetworkType)
	assert.Equal(t, (int)(KCfdP2pkh), info.HashType)
	assert.Equal(t, (int)(KCfdWitnessVersionNone), info.WitnessVersion)
	assert.Equal(t, "76a914f54a5851e9372b87810a8e60cdd2e7cfd80b6e3188ac", info.LockingScript)
	assert.Equal(t, "f54a5851e9372b87810a8e60cdd2e7cfd80b6e31", info.Hash)

	addr = "mjawtDFWiNppWUqczgQevgyg6Hg7J8Uxcg"
	info, err = CfdGoGetAddressInfo(addr)
	assert.NoError(t, err)
	assert.Equal(t, addr, info.Address)
	assert.Equal(t, (int)(KCfdNetworkTestnet), info.NetworkType)
	assert.Equal(t, (int)(KCfdP2pkh), info.HashType)
	assert.Equal(t, (int)(KCfdWitnessVersionNone), info.WitnessVersion)
	assert.Equal(t, "76a9142ca1d2e7214b16725cf6310867460633a061edcb88ac", info.LockingScript)

	addr = "QKXGAM4Cvd1fvLEz5tbq4YwNRzTjdMWi2q"
	info, err = CfdGoGetAddressInfo(addr)
	assert.NoError(t, err)
	assert.Equal(t, addr, info.Address)
	assert.Equal(t, (int)(KCfdNetworkLiquidv1), info.NetworkType)
	assert.Equal(t, (int)(KCfdP2pkh), info.HashType)
	assert.Equal(t, (int)(KCfdWitnessVersionNone), info.WitnessVersion)
	assert.Equal(t, "76a914f42331c418ef4517ba644ad6e9fc99681ad4393788ac", info.LockingScript)

	addr = "XRpicZNrFZumBMhRV5BSYW28pGX7JyY1ua"
	info, err = CfdGoGetAddressInfo(addr)
	assert.NoError(t, err)
	assert.Equal(t, addr, info.Address)
	assert.Equal(t, (int)(KCfdNetworkElementsRegtest), info.NetworkType)
	assert.Equal(t, (int)(KCfdP2sh), info.HashType)
	assert.Equal(t, (int)(KCfdWitnessVersionNone), info.WitnessVersion)
	assert.Equal(t, "a9149ec42b6cfa1b0bc3f55f07af29867057cb0b8a2e87", info.LockingScript)

	addr = "ert1q57etrknhl75e64jmqrvl0vwzu39xjpagaw9ynw"
	info, err = CfdGoGetAddressInfo(addr)
	assert.NoError(t, err)
	assert.Equal(t, addr, info.Address)
	assert.Equal(t, (int)(KCfdNetworkElementsRegtest), info.NetworkType)
	assert.Equal(t, (int)(KCfdP2wpkh), info.HashType)
	assert.Equal(t, (int)(KCfdWitnessVersion0), info.WitnessVersion)
	assert.Equal(t, "0014a7b2b1da77ffa99d565b00d9f7b1c2e44a6907a8", info.LockingScript)

	addr = "ex1q6tayh53l97qhs7fr98x8msgmn82egptfhpkyn53vkt22lrxswztsgnpmxp"
	info, err = CfdGoGetAddressInfo(addr)
	assert.NoError(t, err)
	assert.Equal(t, addr, info.Address)
	assert.Equal(t, (int)(KCfdNetworkLiquidv1), info.NetworkType)
	assert.Equal(t, (int)(KCfdP2wsh), info.HashType)
	assert.Equal(t, (int)(KCfdWitnessVersion0), info.WitnessVersion)
	assert.Equal(t, "0020d2fa4bd23f2f8178792329cc7dc11b99d5940569b86c49d22cb2d4af8cd07097", info.LockingScript)

	addr = "tb1pzamhq9jglfxaj0r5ahvatr8uc77u973s5tm04yytdltsey5r8naskf8ee6"
	info, err = CfdGoGetAddressInfo(addr)
	assert.NoError(t, err)
	assert.Equal(t, addr, info.Address)
	assert.Equal(t, (int)(KCfdNetworkTestnet), info.NetworkType)
	assert.Equal(t, (int)(KCfdTaproot), info.HashType)
	assert.Equal(t, (int)(KCfdWitnessVersion1), info.WitnessVersion)
	assert.Equal(t, "51201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb", info.LockingScript)
	assert.Equal(t, "1777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb", info.Hash)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdGoParseDescriptor(t *testing.T) {
	// PKH
	networkType := (int)(KCfdNetworkLiquidv1)
	descriptorDataList, multisigList, err := CfdGoParseDescriptor(
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
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	// p2sh-p2wsh(pkh)
	networkType = (int)(KCfdNetworkLiquidv1)
	descriptorDataList, multisigList, err = CfdGoParseDescriptor(
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
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	// multisig (bitcoin)
	networkType = (int)(KCfdNetworkMainnet)
	descriptorDataList, multisigList, err = CfdGoParseDescriptor(
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
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	// miniscript wsh
	networkType = (int)(KCfdNetworkMainnet)
	descriptorDataList, multisigList, err = CfdGoParseDescriptor(
		"wsh(thresh(2,multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00),a:multi(1,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00),ac:pk_k(022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01)))",
		networkType,
		"0")
	assert.NoError(t, err)
	assert.Equal(t, 1, len(descriptorDataList))
	assert.Equal(t, 0, len(multisigList))
	if len(descriptorDataList) == 1 {
		assert.Equal(t, uint32(0), descriptorDataList[0].Depth)
		assert.Equal(t, (int)(KCfdDescriptorScriptWsh), descriptorDataList[0].ScriptType)
		assert.Equal(t, "00206a6c42f62db9fab091ffaf930e0a847646898d225e1ad94ff43226e20180b9d1", descriptorDataList[0].LockingScript)
		assert.Equal(t, "bc1qdfky9a3dh8atpy0l47fsuz5ywergnrfztcddjnl5xgnwyqvqh8gschn2ch", descriptorDataList[0].Address)
		assert.Equal(t, (int)(KCfdP2wsh), descriptorDataList[0].HashType)
		assert.Equal(t, "522103a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c721036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a0052ae6b5121036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a0051ae6c936b21022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01ac6c935287", descriptorDataList[0].RedeemScript)
		assert.Equal(t, (int)(KCfdDescriptorKeyNull), descriptorDataList[0].KeyType)
		assert.Equal(t, "", descriptorDataList[0].Pubkey)
		assert.Equal(t, "", descriptorDataList[0].ExtPubkey)
		assert.Equal(t, "", descriptorDataList[0].ExtPrivkey)
		assert.Equal(t, false, descriptorDataList[0].IsMultisig)
		assert.Equal(t, uint32(0), descriptorDataList[0].ReqSigNum)
	}
	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	// miniscript wsh derive
	networkType = (int)(KCfdNetworkMainnet)
	descriptorDataList, multisigList, err = CfdGoParseDescriptor(
		"sh(wsh(c:or_i(andor(c:pk_h(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*),pk_h(xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*),pk_h(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)),pk_k(02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e))))",
		networkType,
		"44")
	assert.NoError(t, err)
	assert.Equal(t, 2, len(descriptorDataList))
	assert.Equal(t, 0, len(multisigList))
	if len(descriptorDataList) == 2 {
		assert.Equal(t, uint32(0), descriptorDataList[0].Depth)
		assert.Equal(t, (int)(KCfdDescriptorScriptSh), descriptorDataList[0].ScriptType)
		assert.Equal(t, "a914a7a9f411001e3e3db96d7f02fc9ab1d0dc6aa69187", descriptorDataList[0].LockingScript)
		assert.Equal(t, "3GyYN9WnJBoMn8M5tuqVcFJq1BvbAcdPAt", descriptorDataList[0].Address)
		assert.Equal(t, (int)(KCfdP2shP2wsh), descriptorDataList[0].HashType)
		assert.Equal(t, "0020e29b7f3e543d581c99c92b59d45218b008b82c2d406bba3c7384d52e568124aa", descriptorDataList[0].RedeemScript)

		assert.Equal(t, uint32(1), descriptorDataList[1].Depth)
		assert.Equal(t, (int)(KCfdDescriptorScriptWsh), descriptorDataList[1].ScriptType)
		assert.Equal(t, "0020e29b7f3e543d581c99c92b59d45218b008b82c2d406bba3c7384d52e568124aa", descriptorDataList[1].LockingScript)
		assert.Equal(t, "bc1qu2dh70j584vpexwf9dvag5sckqytstpdgp4m50rnsn2ju45pyj4qudazmh", descriptorDataList[1].Address)
		assert.Equal(t, (int)(KCfdP2wsh), descriptorDataList[1].HashType)
		assert.Equal(t, "6376a914520e6e72bcd5b616bc744092139bd759c31d6bbe88ac6476a91406afd46bcdfd22ef94ac122aa11f241244a37ecc886776a9145ab62f0be26fe9d6205a155403f33e2ad2d31efe8868672102d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e68ac", descriptorDataList[1].RedeemScript)
		assert.Equal(t, (int)(KCfdDescriptorKeyNull), descriptorDataList[1].KeyType)
		assert.Equal(t, "", descriptorDataList[1].Pubkey)
		assert.Equal(t, "", descriptorDataList[1].ExtPubkey)
		assert.Equal(t, "", descriptorDataList[1].ExtPrivkey)
		assert.Equal(t, false, descriptorDataList[1].IsMultisig)
		assert.Equal(t, uint32(0), descriptorDataList[1].ReqSigNum)
	}
	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdGoParseDescriptorData(t *testing.T) {
	// PKH
	networkType := (int)(KCfdNetworkLiquidv1)
	rootData, _, _, err := CfdGoParseDescriptorData(
		"pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)",
		networkType,
		"")
	assert.NoError(t, err)
	assert.Equal(t, uint32(0), rootData.Depth)
	assert.Equal(t, (int)(KCfdDescriptorScriptPkh), rootData.ScriptType)
	assert.Equal(t, "76a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac", rootData.LockingScript)
	assert.Equal(t, "PwsjpD1YkjcfZ95WGVZuvGfypkKmpogoA3", rootData.Address)
	assert.Equal(t, (int)(KCfdP2pkh), rootData.HashType)
	assert.Equal(t, "", rootData.RedeemScript)
	assert.Equal(t, (int)(KCfdDescriptorKeyPublic), rootData.KeyType)
	assert.Equal(t, "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5", rootData.Pubkey)
	assert.Equal(t, "", rootData.ExtPubkey)
	assert.Equal(t, "", rootData.ExtPrivkey)
	assert.Equal(t, false, rootData.IsMultisig)
	assert.Equal(t, uint32(0), rootData.ReqSigNum)
	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	// p2sh-p2wsh(pkh)
	networkType = (int)(KCfdNetworkLiquidv1)
	rootData, _, _, err = CfdGoParseDescriptorData(
		"sh(wsh(pkh(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13)))",
		networkType, "")
	assert.NoError(t, err)
	assert.Equal(t, uint32(0), rootData.Depth)
	assert.Equal(t, (int)(KCfdDescriptorScriptSh), rootData.ScriptType)
	assert.Equal(t, "a91455e8d5e8ee4f3604aba23c71c2684fa0a56a3a1287", rootData.LockingScript)
	assert.Equal(t, "Gq1mmExLuSEwfzzk6YtUxJ769grv6T5Tak", rootData.Address)
	assert.Equal(t, (int)(KCfdP2shP2wsh), rootData.HashType)
	assert.Equal(t, "76a914c42e7ef92fdb603af844d064faad95db9bcdfd3d88ac", rootData.RedeemScript)
	assert.Equal(t, (int)(KCfdDescriptorKeyPublic), rootData.KeyType)
	assert.Equal(t, "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13", rootData.Pubkey)
	assert.Equal(t, "", rootData.ExtPubkey)
	assert.Equal(t, "", rootData.ExtPrivkey)
	assert.Equal(t, false, rootData.IsMultisig)
	assert.Equal(t, uint32(0), rootData.ReqSigNum)
	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	// multisig (bitcoin)
	networkType = (int)(KCfdNetworkMainnet)
	rootData, _, _, err = CfdGoParseDescriptorData(
		"wsh(multi(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))",
		networkType,
		"0")
	assert.NoError(t, err)
	assert.Equal(t, uint32(0), rootData.Depth)
	assert.Equal(t, (int)(KCfdDescriptorScriptWsh), rootData.ScriptType)
	assert.Equal(t, "002064969d8cdca2aa0bb72cfe88427612878db98a5f07f9a7ec6ec87b85e9f9208b", rootData.LockingScript)
	assert.Equal(t, "bc1qvjtfmrxu524qhdevl6yyyasjs7xmnzjlqlu60mrwepact60eyz9s9xjw0c", rootData.Address)
	assert.Equal(t, (int)(KCfdP2wsh), rootData.HashType)
	assert.Equal(t, "51210205f8f73d8a553ad3287a506dbd53ed176cadeb200c8e4f7d68a001b1aed871062102c04c4e03921809fcbef9a26da2d62b19b2b4eb383b3e6cfaaef6370e7514477452ae", rootData.RedeemScript)
	assert.Equal(t, (int)(KCfdDescriptorKeyNull), rootData.KeyType)
	assert.Equal(t, "", rootData.Pubkey)
	assert.Equal(t, "", rootData.ExtPubkey)
	assert.Equal(t, "", rootData.ExtPrivkey)
	assert.Equal(t, true, rootData.IsMultisig)
	assert.Equal(t, uint32(1), rootData.ReqSigNum)
	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	// miniscript wsh
	networkType = (int)(KCfdNetworkMainnet)
	rootData, _, _, err = CfdGoParseDescriptorData(
		"wsh(thresh(2,multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00),a:multi(1,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00),ac:pk_k(022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01)))",
		networkType,
		"0")
	assert.NoError(t, err)
	assert.Equal(t, uint32(0), rootData.Depth)
	assert.Equal(t, (int)(KCfdDescriptorScriptWsh), rootData.ScriptType)
	assert.Equal(t, "00206a6c42f62db9fab091ffaf930e0a847646898d225e1ad94ff43226e20180b9d1", rootData.LockingScript)
	assert.Equal(t, "bc1qdfky9a3dh8atpy0l47fsuz5ywergnrfztcddjnl5xgnwyqvqh8gschn2ch", rootData.Address)
	assert.Equal(t, (int)(KCfdP2wsh), rootData.HashType)
	assert.Equal(t, "522103a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c721036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a0052ae6b5121036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a0051ae6c936b21022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01ac6c935287", rootData.RedeemScript)
	assert.Equal(t, (int)(KCfdDescriptorKeyNull), rootData.KeyType)
	assert.Equal(t, "", rootData.Pubkey)
	assert.Equal(t, "", rootData.ExtPubkey)
	assert.Equal(t, "", rootData.ExtPrivkey)
	assert.Equal(t, false, rootData.IsMultisig)
	assert.Equal(t, uint32(0), rootData.ReqSigNum)
	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	// miniscript wsh derive
	networkType = (int)(KCfdNetworkMainnet)
	rootData, _, _, err = CfdGoParseDescriptorData(
		"sh(wsh(c:or_i(andor(c:pk_h(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*),pk_h(xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*),pk_h(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)),pk_k(02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e))))",
		networkType,
		"44")
	assert.NoError(t, err)
	assert.Equal(t, uint32(0), rootData.Depth)
	assert.Equal(t, (int)(KCfdDescriptorScriptSh), rootData.ScriptType)
	assert.Equal(t, "a914a7a9f411001e3e3db96d7f02fc9ab1d0dc6aa69187", rootData.LockingScript)
	assert.Equal(t, "3GyYN9WnJBoMn8M5tuqVcFJq1BvbAcdPAt", rootData.Address)
	assert.Equal(t, (int)(KCfdP2shP2wsh), rootData.HashType)
	assert.Equal(t, "6376a914520e6e72bcd5b616bc744092139bd759c31d6bbe88ac6476a91406afd46bcdfd22ef94ac122aa11f241244a37ecc886776a9145ab62f0be26fe9d6205a155403f33e2ad2d31efe8868672102d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e68ac", rootData.RedeemScript)
	assert.Equal(t, (int)(KCfdDescriptorKeyNull), rootData.KeyType)
	assert.Equal(t, "", rootData.Pubkey)
	assert.Equal(t, "", rootData.ExtPubkey)
	assert.Equal(t, "", rootData.ExtPrivkey)
	assert.Equal(t, false, rootData.IsMultisig)
	assert.Equal(t, uint32(0), rootData.ReqSigNum)
	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdGoCreateDescriptor(t *testing.T) {
	// add checksum
	{
		networkType := (int)(KCfdNetworkLiquidv1)
		descriptor := "wsh(multi(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))"
		outputDescriptor, err := CfdGoGetDescriptorChecksum(networkType, descriptor)
		assert.NoError(t, err)
		assert.Equal(t, descriptor+"#t2zpj2eu", outputDescriptor)
	}

	{
		// generate parent extkey path
		networkType := (int)(KCfdNetworkLiquidv1)
		parentExtkey := "xprv9tviYANkXM1CY831VtMFKFn6LP6aMHf1kvtCZyTL9YbyMwTR2BSmJaEoqw59BZdQhLSx9ZxyKsRUeCetxA2xZ34eupBqZUsifnWyLJJ16j3"
		pathFromParent := "0'/1'"
		keyPathData, childExtkey, err := CfdGoGetParentExtkeyPathData(parentExtkey, pathFromParent, (int)(KCfdExtPrivkey))
		assert.NoError(t, err)
		assert.Equal(t, "[03af54a0/0'/1']", keyPathData)
		assert.Equal(t, "xprv9xhdg2NYoNDWKNnSrgamt2MrugMHPYDYAgfkiC7wMJh9rexbf2C49ZGfiF4X9iCbenr6RbyBAe3RGweoAU69LfWkpLfQ7hari4aood9DD6T", childExtkey)

		extpubkey, err := CfdGoCreateExtPubkey(childExtkey, (int)(KCfdNetworkMainnet))
		assert.NoError(t, err)
		assert.Equal(t, "xpub6Bgz5XuSdjmoXrruxi7nFAJbTiBmnzwPXubMWaXYueE8jTHkCZWJhMb9ZWEVFKcmC7XEaejUtrQv5HhHg1DzSw6tcbdbQpsBrBLch4zvTLP", extpubkey)

		// add checksum
		descriptor := "wsh(multi(1,[03af54a0/0'/1']xpub6Bgz5XuSdjmoXrruxi7nFAJbTiBmnzwPXubMWaXYueE8jTHkCZWJhMb9ZWEVFKcmC7XEaejUtrQv5HhHg1DzSw6tcbdbQpsBrBLch4zvTLP/1/0/*,[d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/0/0/*))"
		outputDescriptor, err := CfdGoGetDescriptorChecksum(networkType, descriptor)
		assert.NoError(t, err)
		assert.Equal(t, descriptor+"#ek3mykpf", outputDescriptor)
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdCalculateEcSignature(t *testing.T) {
	kSighash := "9b169f5af064cc2a0dac08d8be3c9e8bc3d3e1a3f3e2a44f0c3e4ecf23d56cf2"
	kPrivkey := "cU4KjNUT7GjHm7CkjRjG46SzLrXHXoH3ekXmqa2jTCFPMkQ64sw1"
	kExtSignature := "0bc7f08a2a8a5446e7483db1b46184ba3cc79d78a3452a72c5bc712cc7efb51f58af044d646c1fd4f755d49db26faa203937bc66c569047a7d3d3da531826060"
	kNetwork := (int)(KCfdNetworkRegtest)

	signature, err := CfdGoCalculateEcSignature(kSighash, "", kPrivkey, kNetwork, true)
	assert.NoError(t, err)
	assert.Equal(t, kExtSignature, signature)

	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdPrivkeyAndPubkey(t *testing.T) {
	kNetwork := (int)(KCfdNetworkRegtest)

	// compress
	pubkey, privkey, wif, err := CfdGoCreateKeyPair(true, kNetwork)
	assert.NoError(t, err)
	assert.Equal(t, 66, len(pubkey))
	assert.Equal(t, 64, len(privkey))
	assert.Equal(t, 52, len(wif))

	privkey2, err := CfdGoGetPrivkeyFromWif(wif, kNetwork)
	assert.NoError(t, err)
	assert.Equal(t, privkey, privkey2)

	privkey3, wifNetwork, wifCompressed, err := CfdGoParsePrivkeyWif(wif)
	assert.NoError(t, err)
	assert.Equal(t, privkey, privkey3)
	assert.Equal(t, (int)(KCfdNetworkTestnet), wifNetwork)
	assert.Equal(t, true, wifCompressed)

	wif2, err := CfdGoGetPrivkeyWif(privkey, kNetwork, true)
	assert.NoError(t, err)
	assert.Equal(t, wif, wif2)

	pubkey2 := ""
	pubkey2, err = CfdGoGetPubkeyFromPrivkey(privkey, "", true)
	assert.NoError(t, err)
	assert.Equal(t, pubkey, pubkey2)

	// uncompress
	pubkey, privkey, wif, err = CfdGoCreateKeyPair(false, kNetwork)
	assert.NoError(t, err)
	assert.Equal(t, 130, len(pubkey))
	assert.Equal(t, 64, len(privkey))
	assert.Equal(t, 51, len(wif))

	privkey2, err = CfdGoGetPrivkeyFromWif(wif, kNetwork)
	assert.NoError(t, err)
	assert.Equal(t, privkey, privkey2)

	privkey3, wifNetwork, wifCompressed, err = CfdGoParsePrivkeyWif(wif)
	assert.NoError(t, err)
	assert.Equal(t, privkey, privkey3)
	assert.Equal(t, (int)(KCfdNetworkTestnet), wifNetwork)
	assert.Equal(t, false, wifCompressed)

	wif2, err = CfdGoGetPrivkeyWif(privkey, kNetwork, false)
	assert.NoError(t, err)
	assert.Equal(t, wif, wif2)

	pubkey2, err = CfdGoGetPubkeyFromPrivkey(privkey, "", false)
	assert.NoError(t, err)
	assert.Equal(t, pubkey, pubkey2)

	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdExtkey(t *testing.T) {
	kSeed := "0e09fbdd00e575b654d480ae979f24da45ef4dee645c7dc2e3b30b2e093d38dda0202357754cc856f8920b8e31dd02e9d34f6a2b20dc825c6ba90f90009085e1"
	kNetwork := (int)(KCfdNetworkMainnet)

	extprivkey1, err := CfdGoCreateExtkeyFromSeed(kSeed, kNetwork, (int)(KCfdExtPrivkey))
	assert.NoError(t, err)
	assert.Equal(t, "xprv9s21ZrQH143K38XAstQ4D3hCGbgydJgNff6CcwmkrWTBxksb2G4CsqAywJCKbTdywfCpmpJyxqf77iKK1ju1J982iP2PriifaNZLMbyPQCx", extprivkey1)

	extprivkey2, err := CfdGoCreateExtkeyFromParentPath(extprivkey1, "m/44'", kNetwork, (int)(KCfdExtPrivkey))
	assert.NoError(t, err)
	assert.Equal(t, "xprv9tviYANkXM1CY831VtMFKFn6LP6aMHf1kvtCZyTL9YbyMwTR2BSmJaEoqw59BZdQhLSx9ZxyKsRUeCetxA2xZ34eupBqZUsifnWyLJJ16j3", extprivkey2)

	extpubkey1, err := CfdGoCreateExtPubkey(extprivkey2, kNetwork)
	assert.NoError(t, err)
	assert.Equal(t, "xpub67v4wfueMiZVkc7UbutFgPiptQw4kkNs89ooNMrwht8xEjnZZim1rNZHhEdrLejB99fiBdnWNNAB8hmUK7tCo5Ua6UtHzwVLj2Bzpch7vB2", extpubkey1)

	extprivkey3, err := CfdGoCreateExtkeyFromParentPath(extprivkey2, "0h/0h/2", kNetwork, (int)(KCfdExtPrivkey))
	assert.NoError(t, err)
	assert.Equal(t, "xprvA1YYKkMiZaDHRY4dmXjcP3js7ATJQAwt9gozTvi69etziyBAAENQN4w7sS3uBaF7rgXvP3sUtKFju7p3PosjNkRDuqqSFfxTjjEhgx6ejVZ", extprivkey3)

	privkey, wif, err := CfdGoGetPrivkeyFromExtkey(extprivkey3, kNetwork)
	assert.NoError(t, err)
	assert.Equal(t, "597da1afc4218445ba9428c1c790a30fd21d5c4a932fa580b99dda7ec0887472", privkey)
	assert.Equal(t, "KzDfmSzt1XqZh5m4sQPBqhpiTGncQ2xvXuWnKGMqR9gVHGSbVJP2", wif)

	pubkey, err := CfdGoGetPubkeyFromExtkey(extprivkey3, kNetwork)
	assert.NoError(t, err)
	assert.Equal(t, "031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1", pubkey)

	data, err := CfdGoGetExtkeyInformation(extprivkey2)
	assert.NoError(t, err)
	if err == nil {
		assert.Equal(t, "0488ade4", data.Version)
		assert.Equal(t, "03af54a0", data.Fingerprint)
		assert.Equal(t, "16ddac07d3c3110f0292136af4bc476323e87b6da49ac0b8eef5bcde17e8a672", data.ChainCode)
		assert.Equal(t, (uint32)(1), data.Depth)
		assert.Equal(t, (uint32)(2147483692), data.ChildNumber)
	}

	data, keyType, networkType, err := CfdGoGetExtkeyInfo(extprivkey2)
	assert.NoError(t, err)
	if err == nil {
		assert.Equal(t, "0488ade4", data.Version)
		assert.Equal(t, "03af54a0", data.Fingerprint)
		assert.Equal(t, "16ddac07d3c3110f0292136af4bc476323e87b6da49ac0b8eef5bcde17e8a672", data.ChainCode)
		assert.Equal(t, (uint32)(1), data.Depth)
		assert.Equal(t, (uint32)(2147483692), data.ChildNumber)
		assert.Equal(t, (int)(KCfdExtPrivkey), keyType)
		assert.Equal(t, kNetwork, networkType)
	}

	extkey, err := CfdGoCreateExtkey(int(KCfdNetworkMainnet), int(KCfdExtPrivkey), "03af54a0", "a0467585c122e8c2c59d2a10dbe073533cbe887758b05c23f281c9bf873998f6", "16ddac07d3c3110f0292136af4bc476323e87b6da49ac0b8eef5bcde17e8a672", byte(1), uint32(2147483692))
	assert.NoError(t, err)
	assert.Equal(t, "xprv9tviYANkXM1CY831VtMFKFn6LP6aMHf1kvtCZyTL9YbyMwTR2BSmJaEoqw59BZdQhLSx9ZxyKsRUeCetxA2xZ34eupBqZUsifnWyLJJ16j3", extkey)

	// xprv9xhdg2NYoNDWJ2EaCaAafhgm7BenUsEjqM4PrG5wuPvTM7jvo1bL5dXwj8TCwiB1A52bKk5N78xQ3hFVBTYxRxLfEm2po5RyQNaFy2kPXZ4/0h/0h/2
	extkey, err = CfdGoCreateExtkeyFromParent(int(KCfdNetworkMainnet), int(KCfdExtPubkey), "03459e03adb3c86131f9d9d35b299cd2c45638bb77c3fa8d1da16b2b5a16a71067", "031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1", "a3d58c40ac9c588529edb6cf9576241a6c2c919843bd97c3c26b35538d91a292", byte(4), uint32(2))
	assert.NoError(t, err)
	assert.Equal(t, "xpub6EXtjFtcPwmae296sZGckBgbfCHnodfjWujbGK7hhzRybmWJhmgeusFbiiZyG1iSeiBcQ7diPeUC9vtP9wLS44bWpqH4kuQQD5N4gA3LaFE", extkey)

	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdParseScript(t *testing.T) {
	t.Run("PKH Locking Script", func(t *testing.T) {
		script := "76a9142e3f2c7e30abce5b22451184c5e531a1e23c6e1288ac"
		items, err := CfdGoParseScript(script)
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
		items, err := CfdGoParseScript(script)
		assert.NoError(t, err)
		assert.Equal(t, int(2), len(items))
		assert.Equal(t, "304402204b922f2dafdd926b22b0e669fd774a2d5f10f969b8089a1c3a0384ba7ce95f6e02204e71c2a620cf430fa6d7ceaeb40d5298f20eebae3ecb783714a6adc03c66717d01", items[0])
		assert.Equal(t, "038f5d4ee5a661c04de7b715c6b9ac935456419fa9f484470275d1d489f2793301", items[1])
	})

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdEncodeSignatureToDer(t *testing.T) {
	signature := "47ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb"

	derSignature, err := CfdGoEncodeSignatureByDer(signature, (int)(KCfdSigHashAll), false)
	assert.NoError(t, err)
	assert.Equal(t, derSignature, "3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01")

	sig, sighash, anyoneCanPay, err := CfdGoDecodeSignatureFromDer(derSignature)
	assert.NoError(t, err)
	assert.Equal(t, signature, sig)
	assert.Equal(t, int(KCfdSigHashAll), sighash)
	assert.Equal(t, false, anyoneCanPay)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdGoCreateScript(t *testing.T) {
	t.Run("TestCfdGoCreateScript_UnlockingScript_pkh", func(t *testing.T) {
		scriptItems := make([]string, 0, 2)
		scriptItems = append(scriptItems, "304402204b922f2dafdd926b22b0e669fd774a2d5f10f969b8089a1c3a0384ba7ce95f6e02204e71c2a620cf430fa6d7ceaeb40d5298f20eebae3ecb783714a6adc03c66717d01")
		scriptItems = append(scriptItems, "038f5d4ee5a661c04de7b715c6b9ac935456419fa9f484470275d1d489f2793301")
		script, err := CfdGoCreateScript(scriptItems)
		assert.NoError(t, err)
		assert.Equal(t, script, "47304402204b922f2dafdd926b22b0e669fd774a2d5f10f969b8089a1c3a0384ba7ce95f6e02204e71c2a620cf430fa6d7ceaeb40d5298f20eebae3ecb783714a6adc03c66717d0121038f5d4ee5a661c04de7b715c6b9ac935456419fa9f484470275d1d489f2793301")
		scriptAsm := strings.Join(scriptItems, " ")
		scriptHex, err := CfdGoConvertScriptAsmToHex(scriptAsm)
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
		script, err := CfdGoCreateScript(scriptItems)
		assert.NoError(t, err)
		assert.Equal(t, script, "595f93011887")
		scriptAsm := strings.Join(scriptItems, " ")
		scriptHex, err := CfdGoConvertScriptAsmToHex(scriptAsm)
		assert.NoError(t, err)
		assert.Equal(t, script, scriptHex)
	})

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdCreateMultisigScriptSig(t *testing.T) {
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

	scriptsig, err := CfdGoCreateMultisigScriptSig(signItems, redeemScript)
	assert.NoError(t, err)
	assert.Equal(t, scriptsig, "00473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb0147522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52ae")

	items, err := CfdGoParseScript(scriptsig)
	assert.NoError(t, err)
	assert.Equal(t, int(4), len(items))
	if len(items) == int(4) {
		assert.Equal(t, "OP_0", items[0])
		assert.Equal(t, "3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01", items[1])
		assert.Equal(t, "3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01", items[2])
		assert.Equal(t, "522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52ae", items[3])
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdGoEstimateFee(t *testing.T) {
	asset, inputs := GetEstimateFeeTestData()
	t.Run("BitcoinTest", func(t *testing.T) {
		txHex := "02000000014cdeada737db97af334f0fa4e87432d6068759eea65a3067d1f14a979e5a9dea0000000000ffffffff0101000000000000002200201863143c14c5166804bd19203356da136c985678cd4d27a1b8c632960490326200000000"
		option := NewCfdEstimateFeeOption()
		option.EffectiveFeeRate = float64(20.0)
		option.UseElements = false
		option.RequireBlind = false
		totalFee, txFee, inputFee, err := CfdGoEstimateFee(txHex, inputs, option)
		assert.NoError(t, err)
		assert.Equal(t, int64(10840), totalFee)
		assert.Equal(t, int64(1100), txFee)
		assert.Equal(t, int64(9740), inputFee)
	})

	t.Run("ElementsTest", func(t *testing.T) {
		txHex := "020000000002d4b91f8ea0be3d89d33f9588884a843e78688152f4dff8aca5abc6f5973a83ae0000000000ffffffff140510708ffd1fc8bea09e204d36b0d5b9402a31767a4f6c36f23b40cd0cbaf70000000000ffffffff030100000000000000000000000000000000000000000000000000000000000000aa01000000003b9328e0001976a9146d715ab3da8090fd8f9e7aada1588e531b16b7da88ac0100000000000000000000000000000000000000000000000000000000000000bb010000000008f0d180001976a9147cafacbfc72f3682b1055b3a6b8711f3622eabfd88ac0100000000000000000000000000000000000000000000000000000000000000aa01000000000007a120000000000000"
		option := NewCfdEstimateFeeOption()
		option.EffectiveFeeRate = float64(20.0)
		option.FeeAsset = asset[0]
		totalFee, txFee, inputFee, err := CfdGoEstimateFee(txHex, inputs, option)
		assert.NoError(t, err)
		assert.Equal(t, int64(46160), totalFee)
		assert.Equal(t, int64(36360), txFee)
		assert.Equal(t, int64(9800), inputFee)
	})

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCfdGoNormalizeSignature(t *testing.T) {
	signature := "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5f67f6cf81a19873091aa7c9578fa2e96490e9bfc78ae7e9798004e8252c06287"
	expectedSig := "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee509809307e5e678cf6e55836a8705d16871a040ea369a21a427d2100a7d75deba"

	// prepare pkh signature
	normalized, err := CfdGoNormalizeSignature(signature)
	assert.NoError(t, err)
	assert.Equal(t, expectedSig, normalized)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestMnemonic(t *testing.T) {
	mnemonicList, err := CfdGoGetMnemonicWordList("en")
	assert.NoError(t, err)
	assert.Equal(t, 2048, len(mnemonicList))
	assert.Equal(t, "ability", mnemonicList[1])

	mnemonicJaList, err := CfdGoGetMnemonicWordList("jp")
	assert.NoError(t, err)
	assert.Equal(t, 2048, len(mnemonicJaList))
	if len(mnemonicJaList) > 1 {
		assert.Equal(t, "あいさつ", mnemonicJaList[1])
	}

	mnemonicWords := []string{
		"gauge",
		"believe",
		"rebel",
		"shuffle",
		"gather",
		"cement",
		"boat",
		"priority",
		"broken",
		"infant",
		"vague",
		"poet"}
	seed1, entropy1, err := CfdGoConvertMnemonicWordsToSeed(mnemonicWords, "abcde", "en")
	assert.NoError(t, err)
	assert.Equal(t, "ea0c8a588f31f31131da01565d398f596764b2b6d085eaef061b61fd13ae398b811335330b9ae203503a5ca82dcd5e9da3aaaa6c71fc6b38951ff4ea41531c5b", seed1)
	assert.Equal(t, "608296cce3b6064a4635571c8e6bc2d3", entropy1)

	mnemonic := "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave"
	seed, entropy, err := CfdGoConvertMnemonicToSeed(mnemonic, "TREZOR", "en")
	assert.NoError(t, err)
	assert.Equal(t, "fd579828af3da1d32544ce4db5c73d53fc8acc4ddb1e3b251a31179cdb71e853c56d2fcb11aed39898ce6c34b10b5382772db8796e52837b54468aeb312cfc3d", seed)
	assert.Equal(t, "6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3", entropy)

	tempMnemonic, err := CfdGoConvertEntropyToMnemonic(entropy, "en")
	assert.NoError(t, err)
	assert.Equal(t, mnemonic, tempMnemonic)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestCreateRawTransactionBitcoin(t *testing.T) {
	handle, err := CfdGoInitializeTransaction(uint32(2), uint32(0))
	assert.NoError(t, err)
	defer CfdGoFreeTransactionHandle(handle)

	sequence := uint32(0xffffffff)
	if err == nil {
		err = CfdGoAddTxInput(
			handle,
			"7461b02405414d79e79a5050684a333c922c1136f4bdff5fb94b551394edebbd", 0,
			sequence)
		assert.NoError(t, err)
	}

	if err == nil {
		err = CfdGoAddTxInput(
			handle,
			"1497e1f146bc5fe00b6268ea16a7069ecb90a2a41a183446d5df8965d2356dc1", 1,
			sequence)
		assert.NoError(t, err)
	}

	if err == nil {
		err = CfdGoAddTxOutput(
			handle,
			int64(100000000),
			"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
		assert.NoError(t, err)
	}

	if err == nil {
		txHex, err := CfdGoFinalizeTransaction(handle)
		assert.NoError(t, err)
		assert.Equal(t, "0200000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff0100e1f50500000000160014751e76e8199196d454941c45d1b3a323f1433bd600000000", txHex)
	}

	if err == nil {
		handle2, err := CfdGoInitializeTransactionByHex("0200000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff0100e1f50500000000160014751e76e8199196d454941c45d1b3a323f1433bd600000000")
		assert.NoError(t, err)
		defer CfdGoFreeTransactionHandle(handle2)

		if err == nil {
			// 03d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b
			err = CfdGoAddTxOutputByScript(
				handle2,
				int64(1900500000),
				"00144dc2412fe3dc759e3830b6fb360264c8ce0abe38")
			assert.NoError(t, err)
		}

		if err == nil {
			txHex, err := CfdGoFinalizeTransaction(handle2)
			assert.NoError(t, err)
			assert.Equal(t, "0200000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff0200e1f50500000000160014751e76e8199196d454941c45d1b3a323f1433bd620544771000000001600144dc2412fe3dc759e3830b6fb360264c8ce0abe3800000000", txHex)
		}
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestSignTransactionBitcoin(t *testing.T) {
	tx := "0200000002bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff0200e1f50500000000160014751e76e8199196d454941c45d1b3a323f1433bd620544771000000001600144dc2412fe3dc759e3830b6fb360264c8ce0abe3800000000"

	// pubkey: '03d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b',
	// privkey: 'cUCCL2wBhCHVwiRpfUVd1rjWUSB4QCnGBczhCW5neLFTQkxZimeG'
	pubkey := "03d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b"
	privkey := "cUCCL2wBhCHVwiRpfUVd1rjWUSB4QCnGBczhCW5neLFTQkxZimeG"
	nettype := int(KCfdNetworkTestnet)
	script := "512103d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b51ae"
	sighash, err := CfdGoCreateSighash(nettype, tx, "1497e1f146bc5fe00b6268ea16a7069ecb90a2a41a183446d5df8965d2356dc1", uint32(1), int(KCfdP2wsh), "", script, int64(10000000), int(KCfdSigHashAll), false)
	assert.NoError(t, err)
	assert.Equal(t, "565a63b7a106969255da55c47b39bd47e7e19b366a00f5270bcc13283c472e08", sighash)

	sig, err := CfdGoCalculateEcSignature(sighash, "", privkey, nettype, true)
	assert.NoError(t, err)
	assert.Equal(t, "7a6eca34eefe7efff7069a01af778d29b9c0311e90878a7245699af394f2b26216f9d4a9a884ab1686140ab10e37b1a8a579fbacd50392dd90a72da22a339867", sig)

	signDataList := []CfdMultisigSignData{
		{
			Signature:           sig,
			IsDerEncode:         true,
			SighashType:         int(KCfdSigHashAll),
			SighashAnyoneCanPay: false,
			RelatedPubkey:       pubkey,
		},
	}
	txHex, err := CfdGoAddTxMultisigSign(nettype, tx, "1497e1f146bc5fe00b6268ea16a7069ecb90a2a41a183446d5df8965d2356dc1", uint32(1), int(KCfdP2wsh), signDataList, script)
	assert.NoError(t, err)
	assert.Equal(t, "02000000000102bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff0200e1f50500000000160014751e76e8199196d454941c45d1b3a323f1433bd620544771000000001600144dc2412fe3dc759e3830b6fb360264c8ce0abe3800030047304402207a6eca34eefe7efff7069a01af778d29b9c0311e90878a7245699af394f2b262022016f9d4a9a884ab1686140ab10e37b1a8a579fbacd50392dd90a72da22a3398670125512103d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b51ae00000000", txHex)

	txHex, err = CfdGoAddTxSignWithPrivkey(nettype, txHex, "7461b02405414d79e79a5050684a333c922c1136f4bdff5fb94b551394edebbd", uint32(0), int(KCfdP2wpkh), pubkey, privkey, int64(10000000), int(KCfdSigHashAll), false, true)
	assert.NoError(t, err)
	assert.Equal(t, "02000000000102bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff0200e1f50500000000160014751e76e8199196d454941c45d1b3a323f1433bd620544771000000001600144dc2412fe3dc759e3830b6fb360264c8ce0abe3802473044022047df4e3d86faa587bdeecb15e9d140956dd6e5c58917cd158d08cf62c1b495ad022010b828d155010188ecaaa8110a48c2dd13d69d7ae620d3926632a004a82483d6012103d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b030047304402207a6eca34eefe7efff7069a01af778d29b9c0311e90878a7245699af394f2b262022016f9d4a9a884ab1686140ab10e37b1a8a579fbacd50392dd90a72da22a3398670125512103d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b51ae00000000", txHex)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestGetTransactionBitcoin(t *testing.T) {
	tx := "02000000000102bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff0200e1f50500000000160014751e76e8199196d454941c45d1b3a323f1433bd620544771000000001600144dc2412fe3dc759e3830b6fb360264c8ce0abe3802473044022047df4e3d86faa587bdeecb15e9d140956dd6e5c58917cd158d08cf62c1b495ad022010b828d155010188ecaaa8110a48c2dd13d69d7ae620d3926632a004a82483d6012103d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b0000000000"
	network := int(KCfdNetworkMainnet)
	data, err := CfdGoGetTxInfo(network, tx)
	assert.NoError(t, err)
	assert.Equal(t, "e05d74e44d51171f71d3babe67c630a8d9c865d602c91998ec8f27ab21c75150", data.Txid)
	assert.Equal(t, "ef936bd43061ab4468ba15618d48c01bd1e4457914c261e90c0dd8f5a6f38741", data.Wtxid)
	assert.Equal(t, uint32(264), data.Size)
	assert.Equal(t, uint32(182), data.Vsize)
	assert.Equal(t, uint32(726), data.Weight)
	assert.Equal(t, uint32(2), data.Version)
	assert.Equal(t, uint32(0), data.LockTime)

	txid, vout, sequence, scriptSig, err := CfdGoGetTxIn(network, tx, uint32(0))
	assert.NoError(t, err)
	assert.Equal(t, "7461b02405414d79e79a5050684a333c922c1136f4bdff5fb94b551394edebbd", txid)
	assert.Equal(t, uint32(0), vout)
	assert.Equal(t, uint32(4294967295), sequence)
	assert.Equal(t, "", scriptSig)

	stackData, err := CfdGoGetTxInWitness(network, tx, uint32(0), uint32(1))
	assert.NoError(t, err)
	assert.Equal(t, "03d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b", stackData)

	satoshiAmount, lockingScript, err := CfdGoGetTxOut(network, tx, uint32(1))
	assert.NoError(t, err)
	assert.Equal(t, int64(1900500000), satoshiAmount)
	assert.Equal(t, "00144dc2412fe3dc759e3830b6fb360264c8ce0abe38", lockingScript)

	inCount, err := CfdGoGetTxInCount(network, tx)
	assert.NoError(t, err)
	assert.Equal(t, uint32(2), inCount)

	witnessCount, err := CfdGoGetTxInWitnessCount(network, tx, uint32(0))
	assert.NoError(t, err)
	assert.Equal(t, uint32(2), witnessCount)

	outCount, err := CfdGoGetTxOutCount(network, tx)
	assert.NoError(t, err)
	assert.Equal(t, uint32(2), outCount)

	txinIndex, err := CfdGoGetTxInIndex(network, tx, "1497e1f146bc5fe00b6268ea16a7069ecb90a2a41a183446d5df8965d2356dc1", uint32(1))
	assert.NoError(t, err)
	assert.Equal(t, uint32(1), txinIndex)

	txoutIndex1, err := CfdGoGetTxOutIndex(network, tx, "bc1qfhpyztlrm36euwpskmanvqnyer8q403cnzfn9t", "")
	assert.NoError(t, err)
	assert.Equal(t, uint32(1), txoutIndex1)

	txoutIndex2, err := CfdGoGetTxOutIndex(network, tx, "", "0014751e76e8199196d454941c45d1b3a323f1433bd6")
	assert.NoError(t, err)
	assert.Equal(t, uint32(0), txoutIndex2)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestGetTransactionBitcoinByHandle(t *testing.T) {
	tx := "02000000000102bdebed9413554bb95fffbdf436112c923c334a6850509ae7794d410524b061740000000000ffffffffc16d35d26589dfd54634181aa4a290cb9e06a716ea68620be05fbc46f1e197140100000000ffffffff0200e1f50500000000160014751e76e8199196d454941c45d1b3a323f1433bd620544771000000001600144dc2412fe3dc759e3830b6fb360264c8ce0abe3802473044022047df4e3d86faa587bdeecb15e9d140956dd6e5c58917cd158d08cf62c1b495ad022010b828d155010188ecaaa8110a48c2dd13d69d7ae620d3926632a004a82483d6012103d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b0000000000"
	network := int(KCfdNetworkMainnet)

	data, txinList, txoutList, err := GetBitcoinTransactionData(tx, true)
	assert.NoError(t, err)

	if err == nil {
		// data, err := CfdGoGetTxInfo(network, tx)
		assert.Equal(t, "e05d74e44d51171f71d3babe67c630a8d9c865d602c91998ec8f27ab21c75150", data.Txid)
		assert.Equal(t, "ef936bd43061ab4468ba15618d48c01bd1e4457914c261e90c0dd8f5a6f38741", data.Wtxid)
		assert.Equal(t, uint32(264), data.Size)
		assert.Equal(t, uint32(182), data.Vsize)
		assert.Equal(t, uint32(726), data.Weight)
		assert.Equal(t, uint32(2), data.Version)
		assert.Equal(t, uint32(0), data.LockTime)

		// txid, vout, sequence, scriptSig, err := CfdGoGetTxIn(network, tx, uint32(0))
		assert.Equal(t, "7461b02405414d79e79a5050684a333c922c1136f4bdff5fb94b551394edebbd", txinList[0].OutPoint.Txid)
		assert.Equal(t, uint32(0), txinList[0].OutPoint.Vout)
		assert.Equal(t, uint32(4294967295), txinList[0].Sequence)
		assert.Equal(t, "", txinList[0].ScriptSig)

		// stackData, err := CfdGoGetTxInWitness(network, tx, uint32(0), uint32(1))
		assert.Equal(t, "03d34d21d3017acdfb033e010574fb73dc83639f97145d83965fe1b19a4c8e2b6b", txinList[0].WitnessStack.Stack[1])

		// satoshiAmount, lockingScript, err := CfdGoGetTxOut(network, tx, uint32(1))
		assert.Equal(t, int64(1900500000), txoutList[1].Amount)
		assert.Equal(t, "00144dc2412fe3dc759e3830b6fb360264c8ce0abe38", txoutList[1].LockingScript)

		// inCount, err := CfdGoGetTxInCount(network, tx)
		assert.Equal(t, 2, len(txinList))

		// witnessCount, err := CfdGoGetTxInWitnessCount(network, tx, uint32(0))
		assert.Equal(t, 2, len(txinList[0].WitnessStack.Stack))

		// outCount, err := CfdGoGetTxOutCount(network, tx)
		assert.Equal(t, 2, len(txoutList))
	}

	txHandle, err := CfdGoInitializeTxDataHandle(network, tx)
	assert.NoError(t, err)
	if err == nil {
		txinIndex, err := CfdGoGetTxInIndexByHandle(txHandle, "1497e1f146bc5fe00b6268ea16a7069ecb90a2a41a183446d5df8965d2356dc1", uint32(1))
		assert.NoError(t, err)
		assert.Equal(t, uint32(1), txinIndex)

		txoutIndex1, err := CfdGoGetTxOutIndexByHandle(txHandle, "bc1qfhpyztlrm36euwpskmanvqnyer8q403cnzfn9t", "")
		assert.NoError(t, err)
		assert.Equal(t, uint32(1), txoutIndex1)

		txoutIndex2, err := CfdGoGetTxOutIndexByHandle(txHandle, "", "0014751e76e8199196d454941c45d1b3a323f1433bd6")
		assert.NoError(t, err)
		assert.Equal(t, uint32(0), txoutIndex2)

		freeErr := CfdGoFreeTxDataHandle(txHandle)
		assert.NoError(t, freeErr)
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestKeyChangeApi(t *testing.T) {
	pubkey := "03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9"
	privkey := "036b13c5a0dd9935fe175b2b9ff86585c231e734b2148149d788a941f1f4f566"
	tweak := "98430d10471cf697e2661e31ceb8720750b59a85374290e175799ba5dd06508e"

	uncompressPubkey, err := CfdGoUncompressPubkey(pubkey)
	assert.NoError(t, err)
	assert.Equal(t, "04662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9eeccf9a82564aef031b5369e86ab05c8f3214a83c81eb643c38fea774b759431",
		uncompressPubkey)

	compressPubkey, err := CfdGoCompressPubkey(uncompressPubkey)
	assert.NoError(t, err)
	assert.Equal(t, pubkey, compressPubkey)

	tweakAddPubkey, err := CfdGoPubkeyTweakAdd(pubkey, tweak)
	assert.NoError(t, err)
	assert.Equal(t, "02b05cf99a2f556177a38f5108445472316e87eb4f5b243d79d7e5829d3d53babc", tweakAddPubkey)

	tweakMulPubkey, err := CfdGoPubkeyTweakMul(pubkey, tweak)
	assert.NoError(t, err)
	assert.Equal(t, "0305d10e760a529d0523e98892d2deff59b91593a0d670bd82271cfa627c9e7e18", tweakMulPubkey)

	negatePubkey, err := CfdGoNegatePubkey(pubkey)
	assert.NoError(t, err)
	assert.Equal(t, "02662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9", negatePubkey)

	tweakAddPrivkey, err := CfdGoPrivkeyTweakAdd(privkey, tweak)
	assert.NoError(t, err)
	assert.Equal(t, "9bae20d5e7fa8fcde07d795d6eb0d78d12e781b9e957122b4d0244e7cefb45f4", tweakAddPrivkey)

	tweakMulPrivkey, err := CfdGoPrivkeyTweakMul(privkey, tweak)
	assert.NoError(t, err)
	assert.Equal(t, "aa71b12accba23b49761a7521e661f07a7e5742ac48cf708b8f9497b3a72a957", tweakMulPrivkey)

	negatePrivkey, err := CfdGoNegatePrivkey(privkey)
	assert.NoError(t, err)
	assert.Equal(t, "fc94ec3a5f2266ca01e8a4d460079a78f87cf5b1fd341ef1e849b54ade414bdb", negatePrivkey)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestSerializeByteData(t *testing.T) {
	serialized, err := CfdGoSerializeByteData("0123456789ab")
	assert.NoError(t, err)
	assert.Equal(t, "060123456789ab", serialized)

	// serialized, err = CfdGoSerializeByteData("")
	// assert.NoError(t, err)
	// assert.Equal(t, "00", serialized)

	serialized, err = CfdGoSerializeByteData("111111111111111111112222222222222222222233333333333333333333444444444444444444445555555555555555555566666666666666666666777777777777777777778888888888888888888899999999999999999999aaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbccccccccccccccccccccdddddddddddddddddddd111111111111111111112222222222222222222233333333333333333333444444444444444444445555555555555555555566666666666666666666777777777777777777778888888888888888888899999999999999999999aaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbccccccccccccccccccccdddddddddddddddddddd")
	assert.NoError(t, err)
	assert.Equal(t, "fd0401111111111111111111112222222222222222222233333333333333333333444444444444444444445555555555555555555566666666666666666666777777777777777777778888888888888888888899999999999999999999aaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbccccccccccccccccccccdddddddddddddddddddd111111111111111111112222222222222222222233333333333333333333444444444444444444445555555555555555555566666666666666666666777777777777777777778888888888888888888899999999999999999999aaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbccccccccccccccccccccdddddddddddddddddddd", serialized)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestFundRawTransactionBtc(t *testing.T) {
	_, utxos := GetCoinSelectionTestData()
	netType := int(KCfdNetworkMainnet)
	option := NewCfdFundRawTxOption(netType)
	option.EffectiveFeeRate = float64(5.0)

	txinList := []CfdUtxo{
		{
			Txid:            "8b84fd7266e1ec09cb5a27cd032729be0102178e250645ee429518e7e83f99f1",
			Vout:            uint32(0),
			Amount:          int64(5000000000),
			Asset:           "",
			Descriptor:      "sh(wpkh(02f466d403c0c4057257e7bcbed1d172880fe75f337c77df5490ad9bc8cc2d6a16))",
			IsIssuance:      false,
			IsBlindIssuance: false,
			IsPegin:         false,
			PeginBtcTxSize:  uint32(0),
		},
	}
	txHex := "02000000000101f1993fe8e7189542ee4506258e170201be292703cd275acb09ece16672fd848b0000000017160014703e50206e4d27ad1340a7b6a0d94563a3fb768afeffffff02080410240100000017a9141e60c63c6d099ee2b48eded11acfdf3a79a891f48700e1f5050000000017a9142699570770f32e0cf3e1d12d81064fbc45899e8a870247304402202b12edc9a75edd70a0e4261c5816efa2c5256e3f8bcffdd49182bd9f791c74e902201e3ae5c1062a83d787098322b3071fe68c4b181e0088b0e0087020495adaf6e3012102f466d403c0c4057257e7bcbed1d172880fe75f337c77df5490ad9bc8cc2d6a1600000000"

	outputTx, fee, usedAddressList, err := CfdGoFundRawTransactionBtc(txHex, txinList, utxos, int64(0), "bc1qfhpyztlrm36euwpskmanvqnyer8q403cnzfn9t", &option)
	assert.NoError(t, err)
	assert.Equal(t, "02000000000102f1993fe8e7189542ee4506258e170201be292703cd275acb09ece16672fd848b0000000017160014703e50206e4d27ad1340a7b6a0d94563a3fb768afeffffff040b0000000000000000000000000000000000000000000000000000000000000000000000ffffffff03080410240100000017a9141e60c63c6d099ee2b48eded11acfdf3a79a891f48700e1f5050000000017a9142699570770f32e0cf3e1d12d81064fbc45899e8a878cf41901000000001600144dc2412fe3dc759e3830b6fb360264c8ce0abe380247304402202b12edc9a75edd70a0e4261c5816efa2c5256e3f8bcffdd49182bd9f791c74e902201e3ae5c1062a83d787098322b3071fe68c4b181e0088b0e0087020495adaf6e3012102f466d403c0c4057257e7bcbed1d172880fe75f337c77df5490ad9bc8cc2d6a160000000000", outputTx)
	assert.Equal(t, int64(1450), fee)
	assert.Equal(t, 1, len(usedAddressList))
	if len(usedAddressList) == 1 {
		assert.Equal(t, "bc1qfhpyztlrm36euwpskmanvqnyer8q403cnzfn9t", usedAddressList[0])
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestUpdateTxOutAmount(t *testing.T) {
	baseTx := "0100000000010136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000023220020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac080047304402206ac44d672dac41f9b00e28f4df20c52eeb087207e8d758d76d92c6fab3b73e2b0220367750dbbe19290069cba53d096f44530e4f98acaa594810388cf7409a1870ce01473044022068c7946a43232757cbdf9176f009a928e1cd9a1a8c212f15c1e11ac9f2925d9002205b75f937ff2f9f3c1246e547e54f62e027f64eefa2695578cc6432cdabce271502473044022059ebf56d98010a932cf8ecfec54c48e6139ed6adb0728c09cbe1e4fa0915302e022007cd986c8fa870ff5d2b3a89139c9fe7e499259875357e20fcbb15571c76795403483045022100fbefd94bd0a488d50b79102b5dad4ab6ced30c4069f1eaa69a4b5a763414067e02203156c6a5c9cf88f91265f5a942e96213afae16d83321c8b31bb342142a14d16381483045022100a5263ea0553ba89221984bd7f0b13613db16e7a70c549a86de0cc0444141a407022005c360ef0ae5a5d4f9f2f87a56c1546cc8268cab08c73501d6b3be2e1e1a8a08824730440220525406a1482936d5a21888260dc165497a90a15669636d8edca6b9fe490d309c022032af0c646a34a44d1f4576bf6a4a74b67940f8faa84c7df9abe12a01a11e2b4783cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae00000000"

	txHex, err := CfdGoUpdateTxOutAmount(int(KCfdNetworkMainnet), baseTx, uint32(1), int64(76543210))
	assert.NoError(t, err)
	assert.Equal(t, "0100000000010136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000023220020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688aceaf48f04000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac080047304402206ac44d672dac41f9b00e28f4df20c52eeb087207e8d758d76d92c6fab3b73e2b0220367750dbbe19290069cba53d096f44530e4f98acaa594810388cf7409a1870ce01473044022068c7946a43232757cbdf9176f009a928e1cd9a1a8c212f15c1e11ac9f2925d9002205b75f937ff2f9f3c1246e547e54f62e027f64eefa2695578cc6432cdabce271502473044022059ebf56d98010a932cf8ecfec54c48e6139ed6adb0728c09cbe1e4fa0915302e022007cd986c8fa870ff5d2b3a89139c9fe7e499259875357e20fcbb15571c76795403483045022100fbefd94bd0a488d50b79102b5dad4ab6ced30c4069f1eaa69a4b5a763414067e02203156c6a5c9cf88f91265f5a942e96213afae16d83321c8b31bb342142a14d16381483045022100a5263ea0553ba89221984bd7f0b13613db16e7a70c549a86de0cc0444141a407022005c360ef0ae5a5d4f9f2f87a56c1546cc8268cab08c73501d6b3be2e1e1a8a08824730440220525406a1482936d5a21888260dc165497a90a15669636d8edca6b9fe490d309c022032af0c646a34a44d1f4576bf6a4a74b67940f8faa84c7df9abe12a01a11e2b4783cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae00000000",
		txHex)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestByteData(t *testing.T) {
	bytedata := []byte{1, 2, 3}
	data1 := NewByteData(bytedata)
	assert.Equal(t, "010203", data1.ToHex())
	assert.Equal(t, bytedata, data1.ToSlice())

	data2, err := NewByteDataFromHex("010203")
	assert.NoError(t, err)
	if err == nil {
		assert.Equal(t, "010203", data2.ToHex())
		assert.Equal(t, bytedata, data2.ToSlice())
	}

	var nullPtr *ByteData
	data3p := NewByteDataFromHexIgnoreError("010203")
	assert.NotEqual(t, nullPtr, data3p)
	if data3p != nil {
		assert.Equal(t, "010203", data3p.ToHex())
		assert.Equal(t, bytedata, data3p.ToSlice())
	}

	_, err = NewByteDataFromHex("01023")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Illegal argument passed.")

	data3p = NewByteDataFromHexIgnoreError("01023")
	assert.Equal(t, nullPtr, data3p)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestEcdsaAdaptorApi(t *testing.T) {
	msg, err := NewByteDataFromHex("024bdd11f2144e825db05759bdd9041367a420fad14b665fd08af5b42056e5e2")
	assert.NoError(t, err)
	adaptor, err := NewByteDataFromHex("038d48057fc4ce150482114d43201b333bf3706f3cd527e8767ceb4b443ab5d349")
	assert.NoError(t, err)
	sk, err := NewByteDataFromHex("90ac0d5dc0a1a9ab352afb02005a5cc6c4df0da61d8149d729ff50db9b5a5215")
	assert.NoError(t, err)
	pubkey, err := NewByteDataFromHex("03490cec9a53cd8f2f664aea61922f26ee920c42d2489778bb7c9d9ece44d149a7")
	assert.NoError(t, err)
	adaptorSig2, err := NewByteDataFromHex("01099c91aa1fe7f25c41085c1d3c9e73fe04a9d24dac3f9c2172d6198628e57f47bb90e2ad6630900b69f55674c8ad74a419e6ce113c10a21a79345a6e47bc74c1")
	assert.NoError(t, err)
	secret, err := NewByteDataFromHex("475697a71a74ff3f2a8f150534e9b67d4b0b6561fab86fcaa51f8c9d6c9db8c6")
	assert.NoError(t, err)
	derSignature := "30440220099c91aa1fe7f25c41085c1d3c9e73fe04a9d24dac3f9c2172d6198628e57f4702204d13456e98d8989043fd4674302ce90c432e2f8bb0269f02c72aafec60b72de101"

	obj := NewEcdsaAdaptorUtil()
	adaptorSignature, proof, err := obj.Sign(msg, sk, adaptor)
	assert.NoError(t, err)
	assert.Equal(t, "00cbe0859638c3600ea1872ed7a55b8182a251969f59d7d2da6bd4afedf25f5021a49956234cbbbbede8ca72e0113319c84921bf1224897a6abd89dc96b9c5b208", adaptorSignature.ToHex())
	assert.Equal(t, "00b02472be1ba09f5675488e841a10878b38c798ca63eff3650c8e311e3e2ebe2e3b6fee5654580a91cc5149a71bf25bcbeae63dea3ac5ad157a0ab7373c3011d0fc2592a07f719c5fc1323f935569ecd010db62f045e965cc1d564eb42cce8d6d", proof.ToHex())

	isVerify, err := obj.Verify(adaptorSignature, proof, adaptor, msg, pubkey)
	assert.NoError(t, err)
	assert.True(t, isVerify)

	ecSig, _, _, err := CfdGoDecodeSignatureFromDer(derSignature)
	assert.NoError(t, err)
	signature, err := obj.Adapt(adaptorSig2, secret)
	assert.NoError(t, err)
	assert.Equal(t, ecSig, signature.ToHex())

	adaptorSecret, err := obj.ExtractSecret(adaptorSig2, signature, adaptor)
	assert.NoError(t, err)
	assert.Equal(t, secret.ToHex(), adaptorSecret.ToHex())

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestSchnorrApi(t *testing.T) {
	msg, err := NewByteDataFromHex("e48441762fb75010b2aa31a512b62b4148aa3fb08eb0765d76b252559064a614")
	assert.NoError(t, err)
	sk, err := NewByteDataFromHex("688c77bc2d5aaff5491cf309d4753b732135470d05b7b2cd21add0744fe97bef")
	assert.NoError(t, err)
	pk, err := NewByteDataFromHex("03b33cc9edc096d0a83416964bd3c6247b8fecd256e4efa7870d2c854bdeb33390")
	assert.NoError(t, err)
	pubkey, err := NewByteDataFromHex("b33cc9edc096d0a83416964bd3c6247b8fecd256e4efa7870d2c854bdeb33390")
	assert.NoError(t, err)
	auxRand, err := NewByteDataFromHex("02cce08e913f22a36c5648d6405a2c7c50106e7aa2f1649e381c7f09d16b80ab")
	assert.NoError(t, err)
	nonce, err := NewByteDataFromHex("8c8ca771d3c25eb38de7401818eeda281ac5446f5c1396148f8d9d67592440fe")
	assert.NoError(t, err)
	schnorrNonce, err := NewByteDataFromHex("f14d7e54ff58c5d019ce9986be4a0e8b7d643bd08ef2cdf1099e1a457865b547")
	assert.NoError(t, err)

	tweak, err := NewByteDataFromHex("e48441762fb75010b2aa31a512b62b4148aa3fb08eb0765d76b252559064a614")
	assert.NoError(t, err)
	expTweakedPk, err := NewByteDataFromHex("1fc8e882e34cc7942a15f39ffaebcbdf58a19239bcb17b7f5aa88e0eb808f906")
	assert.NoError(t, err)
	expTweakedSk, err := NewByteDataFromHex("7bf7c9ba025ca01b698d3e9b3e40efce2774f8a388f8c390550481e1407b2a25")
	assert.NoError(t, err)

	obj := NewSchnorrUtil()

	schnorrPubkey, err := obj.GetPubkeyFromPrivkey(sk)
	assert.NoError(t, err)
	assert.Equal(t, pubkey.ToHex(), schnorrPubkey.ToHex())

	schnorrPubkey, parity, err := obj.GetSchnorrPubkeyFromPrivkey(sk)
	assert.NoError(t, err)
	assert.Equal(t, pubkey.ToHex(), schnorrPubkey.ToHex())
	assert.True(t, parity)

	schnorrPubkey, parity, err = obj.GetSchnorrPubkeyFromPubkey(pk)
	assert.NoError(t, err)
	assert.Equal(t, pubkey.ToHex(), schnorrPubkey.ToHex())
	assert.True(t, parity)

	tweakedPubkey, parity, err := obj.TweakAddPubkey(pubkey, tweak)
	assert.NoError(t, err)
	assert.Equal(t, expTweakedPk.ToHex(), tweakedPubkey.ToHex())
	assert.True(t, parity)

	isTweaked, err := obj.IsTweakedPubkey(tweakedPubkey, true, pubkey, tweak)
	assert.NoError(t, err)
	assert.True(t, isTweaked)

	isTweaked, err = obj.IsTweakedPubkey(tweakedPubkey, false, pubkey, tweak)
	assert.NoError(t, err)
	assert.False(t, isTweaked)

	tweakedPubkey, parity, tweakedPrivkey, err := obj.TweakAddKeyPair(sk, tweak)
	assert.NoError(t, err)
	assert.Equal(t, expTweakedPk.ToHex(), tweakedPubkey.ToHex())
	assert.True(t, parity)
	assert.Equal(t, expTweakedSk.ToHex(), tweakedPrivkey.ToHex())

	signature, err := obj.Sign(msg, sk, auxRand)
	assert.NoError(t, err)
	assert.Equal(t, "6470fd1303dda4fda717b9837153c24a6eab377183fc438f939e0ed2b620e9ee5077c4a8b8dca28963d772a94f5f0ddf598e1c47c137f91933274c7c3edadce8", signature.ToHex())

	signatureWithNonce, err := obj.SignWithNonce(msg, sk, nonce)
	assert.NoError(t, err)
	assert.Equal(t, "5da618c1936ec728e5ccff29207f1680dcf4146370bdcfab0039951b91e3637a958e91d68537d1f6f19687cec1fd5db1d83da56ef3ade1f3c611babd7d08af42", signatureWithNonce.ToHex())

	point, err := obj.ComputeSigPoint(msg, schnorrNonce, pubkey)
	assert.NoError(t, err)
	assert.Equal(t, "03735acf82eef9da1540efb07a68251d5476dabb11ac77054924eccbb4121885e8", point.ToHex())

	sigsNonce, sigsKey, err := obj.SplitSignature(signature)
	assert.NoError(t, err)
	assert.Equal(t, "6470fd1303dda4fda717b9837153c24a6eab377183fc438f939e0ed2b620e9ee", sigsNonce.ToHex())
	assert.Equal(t, "5077c4a8b8dca28963d772a94f5f0ddf598e1c47c137f91933274c7c3edadce8", sigsKey.ToHex())

	isVerify, err := obj.Verify(signature, msg, pubkey)
	assert.NoError(t, err)
	assert.True(t, isVerify)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestDescriptorStruct(t *testing.T) {
	// PKH
	networkType := (int)(KCfdNetworkLiquidv1)
	desc := NewDescriptorFromString(
		"pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)",
		networkType)
	rootData, descriptorDataList, multisigList, err := desc.Parse()
	assert.NoError(t, err)
	assert.Equal(t, uint32(0), rootData.Depth)
	assert.Equal(t, (int)(KCfdDescriptorScriptPkh), rootData.ScriptType)
	assert.Equal(t, "76a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac", rootData.LockingScript)
	assert.Equal(t, "PwsjpD1YkjcfZ95WGVZuvGfypkKmpogoA3", rootData.Address)
	assert.Equal(t, (int)(KCfdP2pkh), rootData.HashType)
	assert.Equal(t, "", rootData.RedeemScript)
	assert.Equal(t, (int)(KCfdDescriptorKeyPublic), rootData.KeyType)
	assert.Equal(t, "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5", rootData.Pubkey)
	assert.Equal(t, "", rootData.ExtPubkey)
	assert.Equal(t, "", rootData.ExtPrivkey)
	assert.Equal(t, "", rootData.SchnorrPubkey)
	assert.Equal(t, "", rootData.TreeString)
	assert.Equal(t, false, rootData.IsMultisig)
	assert.Equal(t, uint32(0), rootData.ReqSigNum)
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
		fmt.Print("[error message] " + err.Error() + "\n")
	}
	desc2 := NewDescriptorFromPubkey(int(KCfdP2pkh), "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5", networkType)
	assert.Equal(t, desc.OutputDescriptor, desc2.OutputDescriptor)

	// p2sh-p2wsh(pkh)
	networkType = (int)(KCfdNetworkLiquidv1)
	desc = NewDescriptorFromString(
		"sh(wsh(pkh(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13)))",
		networkType)
	rootData, descriptorDataList, multisigList, err = desc.Parse()
	assert.NoError(t, err)
	assert.Equal(t, uint32(0), rootData.Depth)
	assert.Equal(t, (int)(KCfdDescriptorScriptSh), rootData.ScriptType)
	assert.Equal(t, "a91455e8d5e8ee4f3604aba23c71c2684fa0a56a3a1287", rootData.LockingScript)
	assert.Equal(t, "Gq1mmExLuSEwfzzk6YtUxJ769grv6T5Tak", rootData.Address)
	assert.Equal(t, (int)(KCfdP2shP2wsh), rootData.HashType)
	assert.Equal(t, "76a914c42e7ef92fdb603af844d064faad95db9bcdfd3d88ac", rootData.RedeemScript)
	assert.Equal(t, (int)(KCfdDescriptorKeyPublic), rootData.KeyType)
	assert.Equal(t, "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13", rootData.Pubkey)
	assert.Equal(t, "", rootData.ExtPubkey)
	assert.Equal(t, "", rootData.ExtPrivkey)
	assert.Equal(t, "", rootData.SchnorrPubkey)
	assert.Equal(t, "", rootData.TreeString)
	assert.Equal(t, false, rootData.IsMultisig)
	assert.Equal(t, uint32(0), rootData.ReqSigNum)
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
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	// multisig (bitcoin)
	networkType = (int)(KCfdNetworkMainnet)
	desc = NewDescriptorFromString(
		"wsh(multi(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))",
		networkType)
	rootData, descriptorDataList, multisigList, err = desc.ParseWithDerivationPath("0")
	assert.NoError(t, err)
	assert.Equal(t, uint32(0), rootData.Depth)
	assert.Equal(t, (int)(KCfdDescriptorScriptWsh), rootData.ScriptType)
	assert.Equal(t, "002064969d8cdca2aa0bb72cfe88427612878db98a5f07f9a7ec6ec87b85e9f9208b", rootData.LockingScript)
	assert.Equal(t, "bc1qvjtfmrxu524qhdevl6yyyasjs7xmnzjlqlu60mrwepact60eyz9s9xjw0c", rootData.Address)
	assert.Equal(t, (int)(KCfdP2wsh), rootData.HashType)
	assert.Equal(t, "51210205f8f73d8a553ad3287a506dbd53ed176cadeb200c8e4f7d68a001b1aed871062102c04c4e03921809fcbef9a26da2d62b19b2b4eb383b3e6cfaaef6370e7514477452ae", rootData.RedeemScript)
	assert.Equal(t, (int)(KCfdDescriptorKeyNull), rootData.KeyType)
	assert.Equal(t, "", rootData.Pubkey)
	assert.Equal(t, "", rootData.ExtPubkey)
	assert.Equal(t, "", rootData.ExtPrivkey)
	assert.Equal(t, "", rootData.SchnorrPubkey)
	assert.Equal(t, "", rootData.TreeString)
	assert.Equal(t, true, rootData.IsMultisig)
	assert.Equal(t, uint32(1), rootData.ReqSigNum)
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
		fmt.Print("[error message] " + err.Error() + "\n")
	}
	desc2 = NewDescriptorFromMultisig(int(KCfdP2wsh), []string{
		"xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*",
		"xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*",
	}, 1, networkType)
	assert.Equal(t, desc.OutputDescriptor, desc2.OutputDescriptor)

	// miniscript wsh
	networkType = (int)(KCfdNetworkMainnet)
	desc = NewDescriptorFromString(
		"wsh(thresh(2,multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00),a:multi(1,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00),ac:pk_k(022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01)))",
		networkType)
	rootData, descriptorDataList, multisigList, err = desc.ParseWithDerivationPath("0")
	assert.NoError(t, err)
	assert.Equal(t, uint32(0), rootData.Depth)
	assert.Equal(t, (int)(KCfdDescriptorScriptWsh), rootData.ScriptType)
	assert.Equal(t, "00206a6c42f62db9fab091ffaf930e0a847646898d225e1ad94ff43226e20180b9d1", rootData.LockingScript)
	assert.Equal(t, "bc1qdfky9a3dh8atpy0l47fsuz5ywergnrfztcddjnl5xgnwyqvqh8gschn2ch", rootData.Address)
	assert.Equal(t, (int)(KCfdP2wsh), rootData.HashType)
	assert.Equal(t, "522103a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c721036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a0052ae6b5121036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a0051ae6c936b21022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01ac6c935287", rootData.RedeemScript)
	assert.Equal(t, (int)(KCfdDescriptorKeyNull), rootData.KeyType)
	assert.Equal(t, "", rootData.Pubkey)
	assert.Equal(t, "", rootData.ExtPubkey)
	assert.Equal(t, "", rootData.ExtPrivkey)
	assert.Equal(t, "", rootData.SchnorrPubkey)
	assert.Equal(t, "", rootData.TreeString)
	assert.Equal(t, false, rootData.IsMultisig)
	assert.Equal(t, uint32(0), rootData.ReqSigNum)
	assert.Equal(t, 1, len(descriptorDataList))
	assert.Equal(t, 0, len(multisigList))
	if len(descriptorDataList) == 1 {
		assert.Equal(t, uint32(0), descriptorDataList[0].Depth)
		assert.Equal(t, (int)(KCfdDescriptorScriptWsh), descriptorDataList[0].ScriptType)
		assert.Equal(t, "00206a6c42f62db9fab091ffaf930e0a847646898d225e1ad94ff43226e20180b9d1", descriptorDataList[0].LockingScript)
		assert.Equal(t, "bc1qdfky9a3dh8atpy0l47fsuz5ywergnrfztcddjnl5xgnwyqvqh8gschn2ch", descriptorDataList[0].Address)
		assert.Equal(t, (int)(KCfdP2wsh), descriptorDataList[0].HashType)
		assert.Equal(t, "522103a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c721036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a0052ae6b5121036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a0051ae6c936b21022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01ac6c935287", descriptorDataList[0].RedeemScript)
		assert.Equal(t, (int)(KCfdDescriptorKeyNull), descriptorDataList[0].KeyType)
		assert.Equal(t, "", descriptorDataList[0].Pubkey)
		assert.Equal(t, "", descriptorDataList[0].ExtPubkey)
		assert.Equal(t, "", descriptorDataList[0].ExtPrivkey)
		assert.Equal(t, false, descriptorDataList[0].IsMultisig)
		assert.Equal(t, uint32(0), descriptorDataList[0].ReqSigNum)
	}
	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	// miniscript wsh derive
	networkType = (int)(KCfdNetworkMainnet)
	desc = NewDescriptorFromString(
		"sh(wsh(c:or_i(andor(c:pk_h(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*),pk_h(xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*),pk_h(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)),pk_k(02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e))))",
		networkType)
	rootData, descriptorDataList, multisigList, err = desc.ParseWithDerivationPath("44")
	assert.NoError(t, err)
	assert.Equal(t, uint32(0), rootData.Depth)
	assert.Equal(t, (int)(KCfdDescriptorScriptSh), rootData.ScriptType)
	assert.Equal(t, "a914a7a9f411001e3e3db96d7f02fc9ab1d0dc6aa69187", rootData.LockingScript)
	assert.Equal(t, "3GyYN9WnJBoMn8M5tuqVcFJq1BvbAcdPAt", rootData.Address)
	assert.Equal(t, (int)(KCfdP2shP2wsh), rootData.HashType)
	assert.Equal(t, "6376a914520e6e72bcd5b616bc744092139bd759c31d6bbe88ac6476a91406afd46bcdfd22ef94ac122aa11f241244a37ecc886776a9145ab62f0be26fe9d6205a155403f33e2ad2d31efe8868672102d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e68ac", rootData.RedeemScript)
	assert.Equal(t, (int)(KCfdDescriptorKeyNull), rootData.KeyType)
	assert.Equal(t, "", rootData.Pubkey)
	assert.Equal(t, "", rootData.ExtPubkey)
	assert.Equal(t, "", rootData.ExtPrivkey)
	assert.Equal(t, "", rootData.SchnorrPubkey)
	assert.Equal(t, "", rootData.TreeString)
	assert.Equal(t, false, rootData.IsMultisig)
	assert.Equal(t, uint32(0), rootData.ReqSigNum)
	assert.Equal(t, 2, len(descriptorDataList))
	assert.Equal(t, 0, len(multisigList))
	if len(descriptorDataList) == 2 {
		assert.Equal(t, uint32(0), descriptorDataList[0].Depth)
		assert.Equal(t, (int)(KCfdDescriptorScriptSh), descriptorDataList[0].ScriptType)
		assert.Equal(t, "a914a7a9f411001e3e3db96d7f02fc9ab1d0dc6aa69187", descriptorDataList[0].LockingScript)
		assert.Equal(t, "3GyYN9WnJBoMn8M5tuqVcFJq1BvbAcdPAt", descriptorDataList[0].Address)
		assert.Equal(t, (int)(KCfdP2shP2wsh), descriptorDataList[0].HashType)
		assert.Equal(t, "0020e29b7f3e543d581c99c92b59d45218b008b82c2d406bba3c7384d52e568124aa", descriptorDataList[0].RedeemScript)

		assert.Equal(t, uint32(1), descriptorDataList[1].Depth)
		assert.Equal(t, (int)(KCfdDescriptorScriptWsh), descriptorDataList[1].ScriptType)
		assert.Equal(t, "0020e29b7f3e543d581c99c92b59d45218b008b82c2d406bba3c7384d52e568124aa", descriptorDataList[1].LockingScript)
		assert.Equal(t, "bc1qu2dh70j584vpexwf9dvag5sckqytstpdgp4m50rnsn2ju45pyj4qudazmh", descriptorDataList[1].Address)
		assert.Equal(t, (int)(KCfdP2wsh), descriptorDataList[1].HashType)
		assert.Equal(t, "6376a914520e6e72bcd5b616bc744092139bd759c31d6bbe88ac6476a91406afd46bcdfd22ef94ac122aa11f241244a37ecc886776a9145ab62f0be26fe9d6205a155403f33e2ad2d31efe8868672102d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e68ac", descriptorDataList[1].RedeemScript)
		assert.Equal(t, (int)(KCfdDescriptorKeyNull), descriptorDataList[1].KeyType)
		assert.Equal(t, "", descriptorDataList[1].Pubkey)
		assert.Equal(t, "", descriptorDataList[1].ExtPubkey)
		assert.Equal(t, "", descriptorDataList[1].ExtPrivkey)
		assert.Equal(t, false, descriptorDataList[1].IsMultisig)
		assert.Equal(t, uint32(0), descriptorDataList[1].ReqSigNum)
	}
	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestTaprootDescriptorStruct(t *testing.T) {
	// taproot schnorr
	networkType := (int)(KCfdNetworkRegtest)
	desc := NewDescriptorFromString(
		"tr(ef514f1aeb14baa6cc57ab3268fb329ca540c48454f7f46771ed731e34ba521a)",
		networkType)
	rootData, descriptorDataList, multisigList, err := desc.Parse()
	assert.NoError(t, err)
	assert.Equal(t, uint32(0), rootData.Depth)
	assert.Equal(t, (int)(KCfdDescriptorScriptTaproot), rootData.ScriptType)
	assert.Equal(t, "5120630f2d9ea4cbcc3f04b73fd56a1c7b51fd3192de8e26e7cd893124900033d3d1", rootData.LockingScript)
	assert.Equal(t, "bcrt1pvv8jm84ye0xr7p9h8l2k58rm287nryk73cnw0nvfxyjfqqpn60gssz7u5f", rootData.Address)
	assert.Equal(t, (int)(KCfdTaproot), rootData.HashType)
	assert.Equal(t, "", rootData.RedeemScript)
	assert.Equal(t, (int)(KCfdDescriptorKeySchnorr), rootData.KeyType)
	assert.Equal(t, "", rootData.Pubkey)
	assert.Equal(t, "", rootData.ExtPubkey)
	assert.Equal(t, "", rootData.ExtPrivkey)
	assert.Equal(t, "ef514f1aeb14baa6cc57ab3268fb329ca540c48454f7f46771ed731e34ba521a", rootData.SchnorrPubkey)
	assert.Equal(t, "", rootData.TreeString)
	assert.Equal(t, false, rootData.IsMultisig)
	assert.Equal(t, uint32(0), rootData.ReqSigNum)
	assert.Equal(t, 1, len(descriptorDataList))
	assert.Equal(t, 0, len(multisigList))
	if len(descriptorDataList) == 1 {
		assert.Equal(t, uint32(0), descriptorDataList[0].Depth)
		assert.Equal(t, (int)(KCfdDescriptorScriptTaproot), descriptorDataList[0].ScriptType)
		assert.Equal(t, "5120630f2d9ea4cbcc3f04b73fd56a1c7b51fd3192de8e26e7cd893124900033d3d1", descriptorDataList[0].LockingScript)
		assert.Equal(t, "bcrt1pvv8jm84ye0xr7p9h8l2k58rm287nryk73cnw0nvfxyjfqqpn60gssz7u5f", descriptorDataList[0].Address)
		assert.Equal(t, (int)(KCfdTaproot), descriptorDataList[0].HashType)
		assert.Equal(t, "", descriptorDataList[0].RedeemScript)
		assert.Equal(t, (int)(KCfdDescriptorKeySchnorr), descriptorDataList[0].KeyType)
		assert.Equal(t, "", descriptorDataList[0].Pubkey)
		assert.Equal(t, "", descriptorDataList[0].ExtPubkey)
		assert.Equal(t, "", descriptorDataList[0].ExtPrivkey)
		assert.Equal(t, "ef514f1aeb14baa6cc57ab3268fb329ca540c48454f7f46771ed731e34ba521a", descriptorDataList[0].SchnorrPubkey)
		assert.Equal(t, "", descriptorDataList[0].TreeString)
		assert.Equal(t, false, descriptorDataList[0].IsMultisig)
		assert.Equal(t, uint32(0), descriptorDataList[0].ReqSigNum)
	}
	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	// taproot extpubkey
	networkType = (int)(KCfdNetworkMainnet)
	desc = NewDescriptorFromString(
		"tr([bd16bee5/0]xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*)",
		networkType)
	rootData, descriptorDataList, multisigList, err = desc.ParseWithDerivationPath("1")
	assert.NoError(t, err)
	assert.Equal(t, uint32(0), rootData.Depth)
	assert.Equal(t, (int)(KCfdDescriptorScriptTaproot), rootData.ScriptType)
	assert.Equal(t, "5120acb99cf4bb397c8aef2fca4f9201053526f5484174fef211ac6ac7fad0a38a48", rootData.LockingScript)
	assert.Equal(t, "bc1p4jueea9m897g4me0ef8eyqg9x5n02jzpwnl0yydvdtrl459r3fyqg8wvnj", rootData.Address)
	assert.Equal(t, (int)(KCfdTaproot), rootData.HashType)
	assert.Equal(t, "", rootData.RedeemScript)
	assert.Equal(t, (int)(KCfdDescriptorKeyBip32), rootData.KeyType)
	assert.Equal(t, "038c6f5956c3cc7251d483fc683fa06b22d4e2ddc7496a2590acee36c4a313f816", rootData.Pubkey)
	assert.Equal(t, "xpub6EKMC2gSMfKgSwn7V9VZn7x1MvoeeVzSmmtSJ4z2L2d6R4WxvdQMouokypZHVp4fgKycrrQnGr6WJ5ED5jG9Q9FiA1q5gKYUc8u6JHJhdo8", rootData.ExtPubkey)
	assert.Equal(t, "", rootData.ExtPrivkey)
	assert.Equal(t, "8c6f5956c3cc7251d483fc683fa06b22d4e2ddc7496a2590acee36c4a313f816", rootData.SchnorrPubkey)
	assert.Equal(t, "", rootData.TreeString)
	assert.Equal(t, false, rootData.IsMultisig)
	assert.Equal(t, uint32(0), rootData.ReqSigNum)
	assert.Equal(t, 1, len(descriptorDataList))
	assert.Equal(t, 0, len(multisigList))
	if len(descriptorDataList) == 1 {
		assert.Equal(t, uint32(0), descriptorDataList[0].Depth)
		assert.Equal(t, (int)(KCfdDescriptorScriptTaproot), descriptorDataList[0].ScriptType)
		assert.Equal(t, "5120acb99cf4bb397c8aef2fca4f9201053526f5484174fef211ac6ac7fad0a38a48", descriptorDataList[0].LockingScript)
		assert.Equal(t, "bc1p4jueea9m897g4me0ef8eyqg9x5n02jzpwnl0yydvdtrl459r3fyqg8wvnj", descriptorDataList[0].Address)
		assert.Equal(t, (int)(KCfdTaproot), descriptorDataList[0].HashType)
		assert.Equal(t, "", descriptorDataList[0].RedeemScript)
		assert.Equal(t, (int)(KCfdDescriptorKeyBip32), descriptorDataList[0].KeyType)
		assert.Equal(t, "038c6f5956c3cc7251d483fc683fa06b22d4e2ddc7496a2590acee36c4a313f816", descriptorDataList[0].Pubkey)
		assert.Equal(t, "xpub6EKMC2gSMfKgSwn7V9VZn7x1MvoeeVzSmmtSJ4z2L2d6R4WxvdQMouokypZHVp4fgKycrrQnGr6WJ5ED5jG9Q9FiA1q5gKYUc8u6JHJhdo8", descriptorDataList[0].ExtPubkey)
		assert.Equal(t, "", descriptorDataList[0].ExtPrivkey)
		assert.Equal(t, "", descriptorDataList[0].SchnorrPubkey)
		assert.Equal(t, "", descriptorDataList[0].TreeString)
		assert.Equal(t, false, descriptorDataList[0].IsMultisig)
		assert.Equal(t, uint32(0), descriptorDataList[0].ReqSigNum)
	}
	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	// taproot  tapscript single
	networkType = (int)(KCfdNetworkRegtest)
	desc = NewDescriptorFromString(
		"tr(ef514f1aeb14baa6cc57ab3268fb329ca540c48454f7f46771ed731e34ba521a,c:pk_k(8c6f5956c3cc7251d483fc683fa06b22d4e2ddc7496a2590acee36c4a313f816))",
		networkType)
	rootData, descriptorDataList, multisigList, err = desc.Parse()
	assert.NoError(t, err)
	assert.Equal(t, uint32(0), rootData.Depth)
	assert.Equal(t, (int)(KCfdDescriptorScriptTaproot), rootData.ScriptType)
	assert.Equal(t, "51205347c06cc9ed4b2286efcf4ed292a810ee451bdc50a4f0ab4a534a3f594763d5", rootData.LockingScript)
	assert.Equal(t, "bcrt1p2druqmxfa49j9ph0ea8d9y4gzrhy2x7u2zj0p2622d9r7k28v02s6x9jx3", rootData.Address)
	assert.Equal(t, (int)(KCfdTaproot), rootData.HashType)
	assert.Equal(t, "", rootData.RedeemScript)
	assert.Equal(t, (int)(KCfdDescriptorKeySchnorr), rootData.KeyType)
	assert.Equal(t, "", rootData.Pubkey)
	assert.Equal(t, "", rootData.ExtPubkey)
	assert.Equal(t, "", rootData.ExtPrivkey)
	assert.Equal(t, "ef514f1aeb14baa6cc57ab3268fb329ca540c48454f7f46771ed731e34ba521a", rootData.SchnorrPubkey)
	assert.Equal(t, "tl(208c6f5956c3cc7251d483fc683fa06b22d4e2ddc7496a2590acee36c4a313f816ac)", rootData.TreeString)
	assert.Equal(t, false, rootData.IsMultisig)
	assert.Equal(t, uint32(0), rootData.ReqSigNum)
	assert.Equal(t, 1, len(descriptorDataList))
	assert.Equal(t, 0, len(multisigList))
	if len(descriptorDataList) == 1 {
		assert.Equal(t, uint32(0), descriptorDataList[0].Depth)
		assert.Equal(t, (int)(KCfdDescriptorScriptTaproot), descriptorDataList[0].ScriptType)
		assert.Equal(t, "51205347c06cc9ed4b2286efcf4ed292a810ee451bdc50a4f0ab4a534a3f594763d5", descriptorDataList[0].LockingScript)
		assert.Equal(t, "bcrt1p2druqmxfa49j9ph0ea8d9y4gzrhy2x7u2zj0p2622d9r7k28v02s6x9jx3", descriptorDataList[0].Address)
		assert.Equal(t, (int)(KCfdTaproot), descriptorDataList[0].HashType)
		assert.Equal(t, "", descriptorDataList[0].RedeemScript)
		assert.Equal(t, (int)(KCfdDescriptorKeySchnorr), descriptorDataList[0].KeyType)
		assert.Equal(t, "", descriptorDataList[0].Pubkey)
		assert.Equal(t, "", descriptorDataList[0].ExtPubkey)
		assert.Equal(t, "", descriptorDataList[0].ExtPrivkey)
		assert.Equal(t, "ef514f1aeb14baa6cc57ab3268fb329ca540c48454f7f46771ed731e34ba521a", descriptorDataList[0].SchnorrPubkey)
		assert.Equal(t, "", descriptorDataList[0].TreeString)
		assert.Equal(t, false, descriptorDataList[0].IsMultisig)
		assert.Equal(t, uint32(0), descriptorDataList[0].ReqSigNum)
	}
	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	// taproot tapscript tapbranch
	networkType = (int)(KCfdNetworkRegtest)
	desc = NewDescriptorFromString(
		"tr(ef514f1aeb14baa6cc57ab3268fb329ca540c48454f7f46771ed731e34ba521a,{c:pk_k(8c6f5956c3cc7251d483fc683fa06b22d4e2ddc7496a2590acee36c4a313f816),{c:pk_k([bd16bee5/0]xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*),thresh(2,c:pk_k(5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc),s:sha256(e38990d0c7fc009880a9c07c23842e886c6bbdc964ce6bdd5817ad357335ee6f),a:hash160(dd69735817e0e3f6f826a9238dc2e291184f0131))}})",
		networkType)
	rootData, descriptorDataList, multisigList, err = desc.ParseWithDerivationPath("1")
	assert.NoError(t, err)
	assert.Equal(t, uint32(0), rootData.Depth)
	assert.Equal(t, (int)(KCfdDescriptorScriptTaproot), rootData.ScriptType)
	assert.Equal(t, "51204f009acbd8c905be4470df1b92c70be16a71d354ba55cc0e6517853f77d79651", rootData.LockingScript)
	assert.Equal(t, "bcrt1pfuqf4j7ceyzmu3rsmude93ctu948r565hf2ucrn9z7zn7a7hjegskj3rsv", rootData.Address)
	assert.Equal(t, (int)(KCfdTaproot), rootData.HashType)
	assert.Equal(t, "", rootData.RedeemScript)
	assert.Equal(t, (int)(KCfdDescriptorKeySchnorr), rootData.KeyType)
	assert.Equal(t, "", rootData.Pubkey)
	assert.Equal(t, "", rootData.ExtPubkey)
	assert.Equal(t, "", rootData.ExtPrivkey)
	assert.Equal(t, "ef514f1aeb14baa6cc57ab3268fb329ca540c48454f7f46771ed731e34ba521a", rootData.SchnorrPubkey)
	assert.Equal(t, "{tl(208c6f5956c3cc7251d483fc683fa06b22d4e2ddc7496a2590acee36c4a313f816ac),{tl(208c6f5956c3cc7251d483fc683fa06b22d4e2ddc7496a2590acee36c4a313f816ac),tl(205cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bcac7c82012088a820e38990d0c7fc009880a9c07c23842e886c6bbdc964ce6bdd5817ad357335ee6f87936b82012088a914dd69735817e0e3f6f826a9238dc2e291184f0131876c935287)}}", rootData.TreeString)
	assert.Equal(t, false, rootData.IsMultisig)
	assert.Equal(t, uint32(0), rootData.ReqSigNum)
	assert.Equal(t, 1, len(descriptorDataList))
	assert.Equal(t, 0, len(multisigList))
	if len(descriptorDataList) == 1 {
		assert.Equal(t, uint32(0), descriptorDataList[0].Depth)
		assert.Equal(t, (int)(KCfdDescriptorScriptTaproot), descriptorDataList[0].ScriptType)
		assert.Equal(t, "51204f009acbd8c905be4470df1b92c70be16a71d354ba55cc0e6517853f77d79651", descriptorDataList[0].LockingScript)
		assert.Equal(t, "bcrt1pfuqf4j7ceyzmu3rsmude93ctu948r565hf2ucrn9z7zn7a7hjegskj3rsv", descriptorDataList[0].Address)
		assert.Equal(t, (int)(KCfdTaproot), descriptorDataList[0].HashType)
		assert.Equal(t, "", descriptorDataList[0].RedeemScript)
		assert.Equal(t, (int)(KCfdDescriptorKeySchnorr), descriptorDataList[0].KeyType)
		assert.Equal(t, "", descriptorDataList[0].Pubkey)
		assert.Equal(t, "", descriptorDataList[0].ExtPubkey)
		assert.Equal(t, "", descriptorDataList[0].ExtPrivkey)
		assert.Equal(t, "ef514f1aeb14baa6cc57ab3268fb329ca540c48454f7f46771ed731e34ba521a", descriptorDataList[0].SchnorrPubkey)
		assert.Equal(t, "", descriptorDataList[0].TreeString)
		assert.Equal(t, false, descriptorDataList[0].IsMultisig)
		assert.Equal(t, uint32(0), descriptorDataList[0].ReqSigNum)
	}
	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	// taproot tapscript tapbranch2
	networkType = (int)(KCfdNetworkRegtest)
	desc = NewDescriptorFromString(
		"tr(ef514f1aeb14baa6cc57ab3268fb329ca540c48454f7f46771ed731e34ba521a,{1717a480c2e3a474eed8dba83f684731243cff8ef384521936cf3a730dd0a286,{1717a480c2e3a474eed8dba83f684731243cff8ef384521936cf3a730dd0a286,80039cda864c4f2f1c87f161b0038e57fb7a4a59ff37517048696b85cdaaf911}})",
		networkType)
	rootData, descriptorDataList, multisigList, err = desc.ParseWithDerivationPath("1")
	assert.NoError(t, err)
	assert.Equal(t, uint32(0), rootData.Depth)
	assert.Equal(t, (int)(KCfdDescriptorScriptTaproot), rootData.ScriptType)
	assert.Equal(t, "51204f009acbd8c905be4470df1b92c70be16a71d354ba55cc0e6517853f77d79651", rootData.LockingScript)
	assert.Equal(t, "bcrt1pfuqf4j7ceyzmu3rsmude93ctu948r565hf2ucrn9z7zn7a7hjegskj3rsv", rootData.Address)
	assert.Equal(t, (int)(KCfdTaproot), rootData.HashType)
	assert.Equal(t, "", rootData.RedeemScript)
	assert.Equal(t, (int)(KCfdDescriptorKeySchnorr), rootData.KeyType)
	assert.Equal(t, "", rootData.Pubkey)
	assert.Equal(t, "", rootData.ExtPubkey)
	assert.Equal(t, "", rootData.ExtPrivkey)
	assert.Equal(t, "ef514f1aeb14baa6cc57ab3268fb329ca540c48454f7f46771ed731e34ba521a", rootData.SchnorrPubkey)
	assert.Equal(t, "{1717a480c2e3a474eed8dba83f684731243cff8ef384521936cf3a730dd0a286,{1717a480c2e3a474eed8dba83f684731243cff8ef384521936cf3a730dd0a286,80039cda864c4f2f1c87f161b0038e57fb7a4a59ff37517048696b85cdaaf911}}", rootData.TreeString)
	assert.Equal(t, false, rootData.IsMultisig)
	assert.Equal(t, uint32(0), rootData.ReqSigNum)
	assert.Equal(t, 1, len(descriptorDataList))
	assert.Equal(t, 0, len(multisigList))
	if len(descriptorDataList) == 1 {
		assert.Equal(t, uint32(0), descriptorDataList[0].Depth)
		assert.Equal(t, (int)(KCfdDescriptorScriptTaproot), descriptorDataList[0].ScriptType)
		assert.Equal(t, "51204f009acbd8c905be4470df1b92c70be16a71d354ba55cc0e6517853f77d79651", descriptorDataList[0].LockingScript)
		assert.Equal(t, "bcrt1pfuqf4j7ceyzmu3rsmude93ctu948r565hf2ucrn9z7zn7a7hjegskj3rsv", descriptorDataList[0].Address)
		assert.Equal(t, (int)(KCfdTaproot), descriptorDataList[0].HashType)
		assert.Equal(t, "", descriptorDataList[0].RedeemScript)
		assert.Equal(t, (int)(KCfdDescriptorKeySchnorr), descriptorDataList[0].KeyType)
		assert.Equal(t, "", descriptorDataList[0].Pubkey)
		assert.Equal(t, "", descriptorDataList[0].ExtPubkey)
		assert.Equal(t, "", descriptorDataList[0].ExtPrivkey)
		assert.Equal(t, "ef514f1aeb14baa6cc57ab3268fb329ca540c48454f7f46771ed731e34ba521a", descriptorDataList[0].SchnorrPubkey)
		assert.Equal(t, "", descriptorDataList[0].TreeString)
		assert.Equal(t, false, descriptorDataList[0].IsMultisig)
		assert.Equal(t, uint32(0), descriptorDataList[0].ReqSigNum)
	}
	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestTaprootSchnorr1(t *testing.T) {
	util := NewSchnorrUtil()
	sk, err := NewByteDataFromHex("305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27")
	assert.NoError(t, err)
	spk, _, err := util.GetSchnorrPubkeyFromPrivkey(sk)
	assert.NoError(t, err)
	assert.Equal(t, "1777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb", spk.hex)

	addr, _, _, err := CfdGoCreateAddress(int(KCfdTaproot), spk.ToHex(), "", int(KCfdNetworkTestnet))
	assert.NoError(t, err)
	assert.Equal(t, "tb1pzamhq9jglfxaj0r5ahvatr8uc77u973s5tm04yytdltsey5r8naskf8ee6", addr)

	txHex := "020000000116d975e4c2cea30f72f4f5fe528f5a0727d9ea149892a50c030d44423088ea2f0000000000ffffffff0130f1029500000000160014164e985d0fc92c927a66c0cbaf78e6ea389629d500000000"
	networkType := (int)(KCfdNetworkMainnet)
	utxos := []CfdUtxo{
		{
			Txid:       "2fea883042440d030ca5929814ead927075a8f52fef5f4720fa3cec2e475d916",
			Vout:       uint32(0),
			Amount:     int64(2499999000),
			Descriptor: "raw(51201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb)",
		},
	}
	txid := utxos[0].Txid
	vout := utxos[0].Vout

	option := CfdFeeEstimateOption{
		EffectiveFeeRate: 2.0,
	}
	fee, _, _, err := CfdGoEstimateFeeUsingUtxo(txHex, utxos, option)
	assert.NoError(t, err)
	assert.Equal(t, int64(202), fee)

	sighashType := NewSigHashType(int(KCfdSigHashAll))
	sighash, err := CfdGoGetSighashByKey(networkType, txHex, utxos, txid, vout, sighashType, &spk, nil)
	assert.NoError(t, err)
	assert.Equal(t, "e5b11ddceab1e4fc49a8132ae589a39b07acf49cabb2b0fbf6104bc31da12c02", sighash)

	sighashBytes, err := NewByteDataFromHex(sighash)
	assert.NoError(t, err)
	emptyBytes := ByteData{}
	signature, err := util.Sign(sighashBytes, sk, emptyBytes)
	assert.NoError(t, err)
	sig, err := util.AddSighashTypeInSignature(&signature, sighashType)
	assert.NoError(t, err)
	assert.Equal(t, "61f75636003a870b7a1685abae84eedf8c9527227ac70183c376f7b3a35b07ebcbea14749e58ce1a87565b035b2f3963baa5ae3ede95e89fd607ab7849f2087201", sig.ToHex())

	txHex, err = CfdGoAddTaprootSchnorrSign(networkType, txHex, txid, vout, sig, nil)
	assert.NoError(t, err)
	assert.Equal(t, "0200000000010116d975e4c2cea30f72f4f5fe528f5a0727d9ea149892a50c030d44423088ea2f0000000000ffffffff0130f1029500000000160014164e985d0fc92c927a66c0cbaf78e6ea389629d5014161f75636003a870b7a1685abae84eedf8c9527227ac70183c376f7b3a35b07ebcbea14749e58ce1a87565b035b2f3963baa5ae3ede95e89fd607ab7849f208720100000000", txHex)

	isVerify, reason, err := CfdGoVerifySign(networkType, txHex, utxos, txid, vout)
	assert.NoError(t, err)
	assert.True(t, isVerify)
	assert.Equal(t, "", reason)

	// verify signature
	isVerify, err = util.Verify(signature, sighashBytes, spk)
	assert.NoError(t, err)
	assert.True(t, isVerify)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestTaprootSchnorr2(t *testing.T) {
	util := NewSchnorrUtil()
	sk, err := NewByteDataFromHex("305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27")
	assert.NoError(t, err)
	spk, _, err := util.GetSchnorrPubkeyFromPrivkey(sk)
	assert.NoError(t, err)
	assert.Equal(t, "1777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb", spk.hex)

	txHex := "020000000116d975e4c2cea30f72f4f5fe528f5a0727d9ea149892a50c030d44423088ea2f0000000000ffffffff0130f1029500000000160014164e985d0fc92c927a66c0cbaf78e6ea389629d500000000"
	networkType := (int)(KCfdNetworkMainnet)
	utxos := []CfdUtxo{
		{
			Txid:       "2fea883042440d030ca5929814ead927075a8f52fef5f4720fa3cec2e475d916",
			Vout:       uint32(0),
			Amount:     int64(2499999000),
			Descriptor: "raw(51201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb)",
		},
	}
	txid := utxos[0].Txid
	vout := utxos[0].Vout
	sighashType := NewSigHashType(int(KCfdSigHashAll))
	txHex, err = CfdGoAddTxSignWithPrivkeyByUtxoList(networkType, txHex, utxos, txid, vout, sk.ToHex(), sighashType, true, nil, nil)
	assert.NoError(t, err)
	assert.Equal(t, "0200000000010116d975e4c2cea30f72f4f5fe528f5a0727d9ea149892a50c030d44423088ea2f0000000000ffffffff0130f1029500000000160014164e985d0fc92c927a66c0cbaf78e6ea389629d5014161f75636003a870b7a1685abae84eedf8c9527227ac70183c376f7b3a35b07ebcbea14749e58ce1a87565b035b2f3963baa5ae3ede95e89fd607ab7849f208720100000000", txHex)

	isVerify, reason, err := CfdGoVerifySign(networkType, txHex, utxos, txid, vout)
	assert.NoError(t, err)
	assert.True(t, isVerify)
	assert.Equal(t, "", reason)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestTapScript(t *testing.T) {
	util := NewSchnorrUtil()
	sk, err := NewByteDataFromHex("305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27")
	assert.NoError(t, err)
	spk, _, err := util.GetSchnorrPubkeyFromPrivkey(sk)
	assert.NoError(t, err)
	assert.Equal(t, "1777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb", spk.hex)

	scriptCheckSig, err := NewScriptFromAsmList([]string{spk.ToHex(), "OP_CHECKSIG"})
	assert.NoError(t, err)

	tree, err := NewTapBranchFromTapScript(&scriptCheckSig)
	assert.NoError(t, err)
	tree.AddBranchByHash(NewByteDataFromHexIgnoreError("4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6d"))
	assert.NoError(t, err)
	tree.AddBranchByHash(NewByteDataFromHexIgnoreError("dc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d54"))
	assert.NoError(t, err)
	tweakedPubkey, tapLeafHash, controlBlock, err := tree.GetTweakedPubkey(&spk)
	assert.NoError(t, err)
	assert.Equal(t, "3dee5a5387a2b57902f3a6e9da077726d19c6cc8c8c7b04bcf5a197b2a9b01d2", tweakedPubkey.hex)
	assert.Equal(t, "dfc43ba9fc5f8a9e1b6d6a50600c704bb9e41b741d9ed6de6559a53d2f38e513", tapLeafHash.hex)
	assert.Equal(t, "c01777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6ddc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d54", controlBlock.hex)

	tweakedPrivkey, err := tree.GetTweakedPrivkey(&sk)
	assert.NoError(t, err)
	assert.Equal(t, "a7d17bee0b6313cf864a1ac6f203aafd74a40703ffc050f66517e4f83ff41a03", tweakedPrivkey.hex)

	networkType := (int)(KCfdNetworkMainnet)
	addr, _, _, err := CfdGoCreateAddress(int(KCfdTaproot), tweakedPubkey.ToHex(), "", networkType)
	assert.NoError(t, err)
	assert.Equal(t, "bc1p8hh955u8526hjqhn5m5a5pmhymgecmxgerrmqj70tgvhk25mq8fqw77n40", addr)

	txHex := "02000000015b80a1af0e00c700bee9c8e4442bec933fcdc0c686dac2dc336caaaf186c5d190000000000ffffffff0130f1029500000000160014164e985d0fc92c927a66c0cbaf78e6ea389629d500000000"
	utxos := []CfdUtxo{
		{
			Txid:       "195d6c18afaa6c33dcc2da86c6c0cd3f93ec2b44e4c8e9be00c7000eafa1805b",
			Vout:       uint32(0),
			Amount:     int64(2499999000),
			Descriptor: "raw(51203dee5a5387a2b57902f3a6e9da077726d19c6cc8c8c7b04bcf5a197b2a9b01d2)",
		},
	}
	txid := utxos[0].Txid
	vout := utxos[0].Vout
	sighashType := NewSigHashType(int(KCfdSigHashAll))
	sighash, err := CfdGoGetSighashByTapScript(networkType, txHex, utxos, txid, vout, sighashType, nil, tapLeafHash, nil, nil)
	assert.NoError(t, err)
	assert.Equal(t, "80e53eaee13048aee9c6c13fa5a8529aad7fe2c362bfc16f1e2affc71f591d36", sighash)

	sighashBytes, err := NewByteDataFromHex(sighash)
	assert.NoError(t, err)
	emptyBytes := ByteData{}
	signature, err := util.Sign(sighashBytes, sk, emptyBytes)
	assert.NoError(t, err)
	sig, err := util.AddSighashTypeInSignature(&signature, sighashType)
	assert.NoError(t, err)
	assert.Equal(t, "f5aa6b260f9df687786cd3813ba83b476e195041bccea800f2571212f4aae9848a538b6175a4f8ea291d38e351ea7f612a3d700dca63cd3aff05d315c5698ee901", sig.ToHex())

	signDataList := []ByteData{*sig}
	txHex, err = CfdGoAddTapScriptSign(networkType, txHex, txid, vout, signDataList, &scriptCheckSig, controlBlock, nil)
	assert.NoError(t, err)
	assert.Equal(t, "020000000001015b80a1af0e00c700bee9c8e4442bec933fcdc0c686dac2dc336caaaf186c5d190000000000ffffffff0130f1029500000000160014164e985d0fc92c927a66c0cbaf78e6ea389629d50341f5aa6b260f9df687786cd3813ba83b476e195041bccea800f2571212f4aae9848a538b6175a4f8ea291d38e351ea7f612a3d700dca63cd3aff05d315c5698ee90122201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfbac61c01777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6ddc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d5400000000", txHex)

	isVerify, reason, err := CfdGoVerifySign(networkType, txHex, utxos, txid, vout)
	assert.Error(t, err)
	assert.False(t, isVerify)
	assert.Equal(t, "The script analysis of tapscript is not supported.", reason)

	// verify signature
	isVerify, err = util.Verify(signature, sighashBytes, spk)
	assert.NoError(t, err)
	assert.True(t, isVerify)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestTapScriptTree(t *testing.T) {
	util := NewSchnorrUtil()
	sk, err := NewByteDataFromHex("305e293b010d29bf3c888b617763a438fee9054c8cab66eb12ad078f819d9f27")
	assert.NoError(t, err)
	spk, _, err := util.GetSchnorrPubkeyFromPrivkey(sk)
	assert.NoError(t, err)
	assert.Equal(t, "1777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb", spk.hex)

	scriptCheckSig, err := NewScriptFromAsmList([]string{spk.ToHex(), "OP_CHECKSIG"})
	assert.NoError(t, err)
	scriptOpTrue, err := NewScriptFromAsm("OP_TRUE")
	assert.NoError(t, err)
	scriptCheckSig2, err := NewScriptFromAsmList([]string{
		"ac52f50b28cdd4d3bcb7f0d5cb533f232e4c4ef12fbf3e718420b84d4e3c3440",
		"OP_CHECKSIG",
	})
	assert.NoError(t, err)

	tree, err := NewTapBranchFromTapScript(&scriptCheckSig)
	assert.NoError(t, err)
	err = tree.AddBranchByTapScript(&scriptOpTrue)
	assert.NoError(t, err)
	err = tree.AddBranchByTapScript(&scriptCheckSig2)
	assert.NoError(t, err)
	assert.Equal(t, "{tl(20ac52f50b28cdd4d3bcb7f0d5cb533f232e4c4ef12fbf3e718420b84d4e3c3440ac),{tl(51),tl(201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfbac)}}", tree.GetTreeString())
	count, err := tree.GetMaxBranchCount()
	assert.NoError(t, err)
	assert.Equal(t, uint32(2), count)

	// deserialize
	treeStr := "{{{tl(51),{tl(204a7af8660f2b0bdb92d2ce8b88ab30feb916343228d2e7bd15da02e1f6a31d47ac),tl(2000d134c42fd51c90fa82c6cfdaabd895474d979118525362c0cd236c857e29d9ac)}},{{tl(20ac52f50b28cdd4d3bcb7f0d5cb533f232e4c4ef12fbf3e718420b84d4e3c3440ac),{tl(2057bf643684f6c5c75e1cdf45990036502a0d897394013210858cdabcbb95a05aac),tl(51)}},tl(2057bf643684f6c5c75e1cdf45990036502a0d897394013210858cdabcbb95a05aad205bec1a08fa3443176edd0a08e2a64642f45e57543b62bffe43ec350edc33dc22ac)}},tl(2008f8280d68e02e807ccffee141c4a6b7ac31d3c283ae0921892d95f691742c44ad20b0f8ce3e1df406514a773414b5d9e5779d8e68ce816e9db39b8e53255ac3b406ac)}"
	controlNodes := []string{
		"06b46c960d6824f0da5af71d9ecc55714de5b2d2da51be60bd12c77df20a20df",
		"4691fbb1196f4675241c8958a7ab6378a63aa0cc008ed03d216fd038357f52fd",
		"e47f58011f27e9046b8195d0ab6a2acbc68ce281437a8d5132dadf389b2a5ebb",
		"32a0a039ec1412be2803fd7b5f5444c03d498e5e8e107ee431a9597c7b5b3a7c",
		"d7b0b8d070638ff4f0b7e7d2aa930c58ec2d39853fd04c29c4c6688fdcb2ae75",
	}
	tree2, err := NewTapBranchFromStringByNodes(
		treeStr,
		&scriptOpTrue,
		controlNodes,
	)
	assert.NoError(t, err)
	count, err = tree2.GetMaxBranchCount()
	assert.NoError(t, err)
	assert.Equal(t, uint32(5), count)
	assert.Equal(t, treeStr, tree2.GetTreeString())
	nodeList, err := tree2.GetControlNodeList()
	assert.NoError(t, err)
	assert.Equal(t, 5, len(nodeList))
	if len(nodeList) == 5 {
		for index := 0; index < len(nodeList); index++ {
			assert.Equal(t, controlNodes[index], nodeList[index])
		}
	}
	branch, err := tree2.GetBranch(3)
	assert.NoError(t, err)
	assert.Equal(t, "{tl(51),{tl(204a7af8660f2b0bdb92d2ce8b88ab30feb916343228d2e7bd15da02e1f6a31d47ac),tl(2000d134c42fd51c90fa82c6cfdaabd895474d979118525362c0cd236c857e29d9ac)}}", branch.GetTreeString())

	tree3, err := NewTapBranchFromString(
		"{{tl(20ac52f50b28cdd4d3bcb7f0d5cb533f232e4c4ef12fbf3e718420b84d4e3c3440ac),{tl(2057bf643684f6c5c75e1cdf45990036502a0d897394013210858cdabcbb95a05aac),tl(51)}},tl(2057bf643684f6c5c75e1cdf45990036502a0d897394013210858cdabcbb95a05aad205bec1a08fa3443176edd0a08e2a64642f45e57543b62bffe43ec350edc33dc22ac)}",
		&scriptOpTrue,
	)
	assert.NoError(t, err)
	err = tree3.AddBranchByBranch(branch)
	assert.NoError(t, err)
	err = tree3.AddBranchByString("tl(2008f8280d68e02e807ccffee141c4a6b7ac31d3c283ae0921892d95f691742c44ad20b0f8ce3e1df406514a773414b5d9e5779d8e68ce816e9db39b8e53255ac3b406ac)")
	assert.NoError(t, err)
	assert.Equal(t, tree2.GetTreeString(), tree3.GetTreeString())

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestSplitTxOut(t *testing.T) {
	txHex, err := CfdGoSplitTxOut(
		"0200000001ffa8db90b81db256874ff7a98fb7202cdc0b91b5b02d7c3427c4190adc66981f0000000000ffffffff0118f50295000000002251201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb00000000",
		0,
		[]CfdTxOut{
			{
				Amount:  499999000,
				Address: "bc1qz33wef9ehrvd7c64p27jf5xtvn50946xfzpxx4",
			},
		},
	)
	assert.NoError(t, err)
	assert.Equal(t, "0200000001ffa8db90b81db256874ff7a98fb7202cdc0b91b5b02d7c3427c4190adc66981f0000000000ffffffff0200943577000000002251201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb1861cd1d000000001600141462eca4b9b8d8df63550abd24d0cb64e8f2d74600000000", txHex)

	txHex, err = CfdGoSplitTxOut(
		"0200000001ffa8db90b81db256874ff7a98fb7202cdc0b91b5b02d7c3427c4190adc66981f0000000000ffffffff0118f50295000000002251201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb00000000",
		0,
		[]CfdTxOut{
			{
				Amount:        400000000,
				LockingScript: "00141462eca4b9b8d8df63550abd24d0cb64e8f2d746",
			},
			{
				Amount:        99999000,
				LockingScript: "0014164e985d0fc92c927a66c0cbaf78e6ea389629d5",
			},
		},
	)
	assert.NoError(t, err)
	assert.Equal(t, "0200000001ffa8db90b81db256874ff7a98fb7202cdc0b91b5b02d7c3427c4190adc66981f0000000000ffffffff0300943577000000002251201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb0084d717000000001600141462eca4b9b8d8df63550abd24d0cb64e8f2d74618ddf50500000000160014164e985d0fc92c927a66c0cbaf78e6ea389629d500000000", txHex)

	indexes, err := CfdGoGetTxOutIndexes(
		int(KCfdNetworkMainnet),
		"02000000034cdeada737db97af334f0fa4e87432d6068759eea65a3067d1f14a979e5a9dea0000000000ffffffff81ddd34c6c0c32544e3b89f5e24c6cd7afca62f2b5069281ac9fced6251191d20000000000ffffffff81ddd34c6c0c32544e3b89f5e24c6cd7afca62f2b5069281ac9fced6251191d20100000000ffffffff040200000000000000220020c5ae4ff17cec055e964b573601328f3f879fa441e53ef88acdfd4d8e8df429ef406f400100000000220020ea5a7208cddfbc20dd93e12bf29deb00b68c056382a502446c9c5b55490954d215cd5b0700000000220020f39f6272ba6b57918eb047c5dc44fb475356b0f24c12fca39b19284e80008a42406f400100000000220020ea5a7208cddfbc20dd93e12bf29deb00b68c056382a502446c9c5b55490954d200000000",
		"bc1qafd8yzxdm77zphvnuy4l980tqzmgcptrs2jsy3rvn3d42jgf2nfqc4zt4j",
		"")
	assert.NoError(t, err)
	assert.Equal(t, 2, len(indexes))
	if len(indexes) == 2 {
		assert.Equal(t, uint32(1), indexes[0])
		assert.Equal(t, uint32(3), indexes[1])
	}

	txHex, err = CfdGoUpdateWitnessStack(
		int(KCfdNetworkMainnet),
		"020000000001014cdeada737db97af334f0fa4e87432d6068759eea65a3067d1f14a979e5a9dea0000000000ffffffff010cdff5050000000017a91426b9ba9cf5d822b70cf490ad0394566f9db20c63870247304402200b3ca71e82551a333fe5c8ce9a8f8454eb8f08aa194180e5a87c79ccf2e46212022065c1f2a363ebcb155a80e234258394140d08f6ab807581953bb21a58f2d229a6012102fd54c734e48c544c3c3ad1aab0607f896eb95e23e7058b174a580826a7940ad800000000",
		"ea9d5a9e974af1d167305aa6ee598706d63274e8a40f4f33af97db37a7adde4c",
		0,
		1,
		"03aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf79")
	assert.NoError(t, err)
	assert.Equal(t, "020000000001014cdeada737db97af334f0fa4e87432d6068759eea65a3067d1f14a979e5a9dea0000000000ffffffff010cdff5050000000017a91426b9ba9cf5d822b70cf490ad0394566f9db20c63870247304402200b3ca71e82551a333fe5c8ce9a8f8454eb8f08aa194180e5a87c79ccf2e46212022065c1f2a363ebcb155a80e234258394140d08f6ab807581953bb21a58f2d229a6012103aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf7900000000", txHex)

	txHex, err = CfdGoUpdateTxInSequence(
		int(KCfdNetworkMainnet),
		txHex,
		"ea9d5a9e974af1d167305aa6ee598706d63274e8a40f4f33af97db37a7adde4c",
		0,
		4294967294)
	assert.NoError(t, err)
	assert.Equal(t, "020000000001014cdeada737db97af334f0fa4e87432d6068759eea65a3067d1f14a979e5a9dea0000000000feffffff010cdff5050000000017a91426b9ba9cf5d822b70cf490ad0394566f9db20c63870247304402200b3ca71e82551a333fe5c8ce9a8f8454eb8f08aa194180e5a87c79ccf2e46212022065c1f2a363ebcb155a80e234258394140d08f6ab807581953bb21a58f2d229a6012103aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf7900000000", txHex)

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestBlockApi1(t *testing.T) {
	blockHex := "00000030957958949bad814d1666ed0d4a005c8aed6b7fd56df5d12c81d584c71e5fae2dfe391f9150dcfb06d54d4eb6621672590bf46bed6893da825c076b841794cec5414e2660ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0502d5000101ffffffff0200f9029500000000160014164e985d0fc92c927a66c0cbaf78e6ea389629d50000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000"

	network := int(KCfdNetworkMainnet)
	hash, header, err := CfdGoGetBlockHeaderData(network, blockHex)
	assert.NoError(t, err)
	assert.Equal(t, "53fd7b794cf751a148b2be637df6c7daf663f1be509cb35294bd69400fdc694e", hash)
	assert.NotNil(t, header)
	if header != nil {
		assert.Equal(t, uint32(805306368), header.Version)
		assert.Equal(t, "2dae5f1ec784d5812cd1f56dd57f6bed8a5c004a0ded66164d81ad9b94587995", header.PrevBlockHash)
		assert.Equal(t, "c5ce9417846b075c82da9368ed6bf40b59721662b64e4dd506fbdc50911f39fe", header.MerkleRoot)
		assert.Equal(t, uint32(1613123137), header.Time)
		assert.Equal(t, uint32(0x207fffff), header.Bits)
		assert.Equal(t, uint32(0), header.Nonce)
	}

	count, err := CfdGoGetTxCountInBlock(network, blockHex)
	assert.NoError(t, err)
	assert.Equal(t, uint32(1), count)

	txid := "c5ce9417846b075c82da9368ed6bf40b59721662b64e4dd506fbdc50911f39fe"
	txidList, err := CfdGoGetTxidListFromBlock(network, blockHex)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(txidList))
	if len(txidList) == 1 {
		assert.Equal(t, txid, txidList[0])
	}

	txHex, proof, err := CfdGoGetTransactionDataFromBlock(network, blockHex, txid)
	assert.NoError(t, err)
	assert.Equal(t, "020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0502d5000101ffffffff0200f9029500000000160014164e985d0fc92c927a66c0cbaf78e6ea389629d50000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000", txHex)
	assert.Equal(t, "00000030957958949bad814d1666ed0d4a005c8aed6b7fd56df5d12c81d584c71e5fae2dfe391f9150dcfb06d54d4eb6621672590bf46bed6893da825c076b841794cec5414e2660ffff7f20000000000100000001fe391f9150dcfb06d54d4eb6621672590bf46bed6893da825c076b841794cec50101", proof)

	exist, err := CfdGoExistTxidInBlock(network, blockHex, txid)
	assert.NoError(t, err)
	assert.True(t, exist)

	exist, err = CfdGoExistTxidInBlock(network, blockHex, "f5ce9417846b075c82da9368ed6bf40b59721662b64e4dd506fbdc50911f39fe")
	assert.NoError(t, err)
	assert.False(t, exist)
}

func TestBlockApi2(t *testing.T) {
	blockHex := "00000020d987e1f7cc030f4272beda5a081f8f8969f044ef72a3b2c2e544afc8230b9642d8b5de43b746fa65aaab7cfa0b521b41e4eb0d7c0e2fb834380259df581daf03157eb360ffff7f200100000015020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff050277020101ffffffff02246aa01200000000160014aef2e2877c45ada6b9eaef2bdb9131630ae12dca0000000000000000266a24aa21a9ed2af9d1c54b61988d37ce9bcde367fba7f3c5910cecaf8be1b6b443e937e39cec0120000000000000000000000000000000000000000000000000000000000000000000000000020000000001013d067178968e8e7469a61a82c365508ee3615bed93ed421ddefe19da412171080000000000feffffff02a0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee13373f2500000000160014a9b62806472c7b70c9f753bf41573e1506534dc40247304402205de2d7b0acf8e6027fcb1e197745ca8d23c1a4a7f4dc449762265e2aab2022f202204d35e5866f31595616b44f77e218fbddbfed702b830eb4c2aac087c5c1ad0648012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d476020000020000000001019421ca1de8781f070262511333197ab44f1629dbb704bd923f48bae4fa67a9f90000000000feffffff0213373f250000000016001455d6fbae5d95d2b03e5210abbe5a15ddbdb62c47a0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee0247304402206f590ce48f6f7a93821c116c3a4a9659d9739d8a9bc62fcae12e34cf0e4b26500220361867ad6dcd30af0bec09a9571a8888452d2812275201f4878de296a78e8627012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d476020000020000000001018e4212da7a883762b80efdf512263fd8d412771515b8b81cf992c01314fc93210000000000feffffff0213373f2500000000160014563423d5881cddbb72a1d6fea1af5c56bbea6a3fa0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee024730440220185d48c45b2e83f56249bfda4e2f0e1a211165c3c1175bd358cc7e4024e4764202201835811415ee2e5efbf42445b0113f54ae87b99e77e59252a69960759fdd8cf7012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d46302000002000000000101f0d8cef892eb52f81ac0e86bce4df8eeb9d0c1336cb62a069626c173e65321f80000000000feffffff02a0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee13373f2500000000160014e53cad733f173a80f1402d16123321535454048e0247304402207bbea0204f17fb98370ada2158666b4554d1354409efbd326835413041cd24410220323a16ee7b50f298446db61cd197cc44dd27fd90d45adb1a4fd780574300be7b012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d47602000002000000000101106a9ee2f6bbc4e58cbff2b1c99a53cdddec1a153f8a699350c00969500097210000000000feffffff02a0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee13373f2500000000160014f0321c988998afdb2b8788ce862402110792be8c0247304402207f6e3931036bb80b127b3d25ecf92bf5507cf057ec5af7c3a70b37e0c74575eb02205da9e647d92c86b2e17533050edd95e7eb887981e6145ade05728e0447a357bf012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d47602000002000000000101ea826992d745371bd6d762692369b94b2ac047df92d8b83cf9f46f6c9dbb13450000000000feffffff02a0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee13373f2500000000160014008e9141e1a0fd29384d41585598d2d1dc90ad380247304402202aeae79aa171eb28d21ee22fff4b58794d77e1ceda4c0bdd02fe87b4b6260c17022067184229e67f0ac2729e30206700fb50f0691e248690b6b103788552ebfb8b37012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d476020000020000000001011723ce44d3f606a6fbd3de7e5204ad22f6b48154e19e0e37fdb547c84e57bdfe0000000000feffffff0213373f2500000000160014b30e6003f0a61a3c594678af24bfe170894c15cca0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee0247304402202876093a9dec94f9ce1fb3b7c487a8cf38b09a9f3e438c2a1e56d2ff8e2287df02204bba8b7936cccad0302d4f0e39da4b27779a2e8a5ba5a506fe00907544224633012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d476020000020000000001016de1c5853fd550cb2fdd67f25b32496bb182404e2f127b5e82e48c587622eabc0000000000feffffff0213373f250000000016001496864cef7241cc0c24e8914f4ec75e34da0a70a6a0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee0247304402207dde78431c3e5ede2a90af0b3e3d32fadb5712e5ec04e3fac2dc6137d747187902202fc5603f63ce4498ad9062ed35b37ca5fc9a19fc90a9ef40ddec55b30820862c012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d476020000020000000001013e22c22ad4afedfac4642f54ebc1fb93f94f3af1c7cedd78fb17242975e00e650000000000feffffff02a0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee13373f250000000016001485fe6084fcec5323e4647ccb6781f2975ce78a690247304402202d4676c01c0f5f39d98f3e0435101c283baff3f2168bb20fccc99ef514abc77c02205703439a4ca4c289f9ab36e31ba88b81d5503ad705a30b036b628e505ef2b07f012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d476020000020000000001018e637219b2c53a395f6b61b85ff720e7380161b31473556d470878ccc9077fe80000000000feffffff02a0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee13373f2500000000160014d9a72d531686342f1f81a447f9643d22ec7bd0ab02473044022010df9caa2ae04bf2b04cce039d859e8fe9f04add799ce02ce4f5848a48eebb9802204e11ae33d32a7c99af8dcc85797b5dc0b7a864c5f9848be41604740fac2bdb89012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d4760200000200000000010124c74f712076cb581a3ee4ae502e094487139ca3da724edb9c0acfd905bd8d340000000000feffffff0213373f250000000016001465eab055d88f1ac853fe1f790740ce24c8623e4ea0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee02473044022053373da5b4b0583d7ef8e743b0fad5688d5a81c82dd33fb6a614a0cf7234431a0220192e5802c1bf8d2e05bca416e3e42b1fb7947169333c40a33bfda2bf1170237d012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d4760200000200000000010145df9bc5da442ff71110c0872dc58939138aba50f2e12bdf13ef7e75ab2f893c0000000000feffffff0213373f250000000016001427880ac035c111a8e8f71e4ae6a5bb4df79518c4a0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee0247304402200a13fd5ae3a2dd9bb210316fea853cc8ad9ada202a58c91f53c61a0741b63833022012a15e4bb30938b31da9606d03e2692e12ce87afe816df19ca20934dfadb7641012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d4760200000200000000010140b280318583b4e346fab2a2a126201799ddaffa169d3ac375b9434b3937a0750000000000feffffff0213373f2500000000160014e11569e65a6a7bbe75ca0322070eb0745201b99ca0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee024730440220655e813dcd37ee11f44d82eddc1540225866e3cc730b768c6c5f9b80cd1c447502200e538e03ed2a3c4f5da9396e884890556e42bf5d25ae49eb1b6c8a0101096fb0012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d476020000020000000001012fb0c024a0ae79e6217dc8889c6af40853b2b230a0e9f79d765c8b5525e0e2320000000000feffffff0213373f25000000001600147f44238db9775e0e738fb949724a7ffb66f4ac47a0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee02473044022032778f2c844abedb675ef947bdc7a11271800b5a11c98be5c0c9fdc6b2037f7302206acf28de27d327dc5a9d93998edad27f7509aa8479a1a2be1cb28f0eee28bf6a012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d47602000002000000000101892c26005096da187a5de107320c08a02e458be0184af915edbacaf5ad898c160000000000feffffff02a0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee13373f250000000016001460524bb60b4dc68abe9ba195376d572dd6cc20fa0247304402206b43d3fcceff2ee92380f6e112b99907b94df56c9ed2ab7df4fa750fd5010ed70220526807188cb56ff1944e19db3910b06d944c8772a76fd91b83cca791c740da14012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d4760200000200000000010128877cbe42170fca382e506d745a333a1e1eed9ed5c3597cf904cd441f7fef050000000000feffffff02a0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee13373f250000000016001462bf5d506758c4075c1484ed199c12b1d070dcc9024730440220514defa364f4cf78355fb64a79f0be487a0515f2c383cca2c7572b862f389b8b022040fb39e0cef457968c22c7a778b3225bf6d95e661c6bfaeea40dc6c9ae7fd9d5012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d476020000020000000001019b34c725b2b7de36389cec07b79109d482dab48e1641c2ba143fe1e0ab80f86d0000000000feffffff02a0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee13373f250000000016001437586a889710f537d70d511e41f45ade16ae96b80247304402205e1560130977bf5584e1938c34daa77e3dd0393eff6cfb18fa3d485a622a9f1d02200d55678c7c274442b0aa99d0a047094051b125ff74e8582be20d52dbb1825889012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d476020000020000000001017883189114213697b8adc8069c8bafc80d9972c9fc1949a478c57bde58daacbb0000000000feffffff02a0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee13373f25000000001600144b69012485912f125d6121323d1b2c55e24b3a8f0247304402203bf784686661951078c64dce1410677127d92015d018a1233a9be6351f26ad2302203b6287e552aed0abcf8740cc464d5843dbd3712e58b33dfa2be6947ba88e7b8f012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d4760200000200000000010180143a2ecddd4d3b32eb7c1e6378a054a2a02b278811a5ffbddf4db4e17f0ad70000000000feffffff0213373f2500000000160014fe956a004e01b6cbe82bf6a351f9370a60917abba0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee024730440220769b4f0bc75725b686fcc131af5b31722eeb0e7835bdeb812e16982183045d66022070a2f04e7619e75a9abd62170a1dbffceb11e398119c559bdb66cf49d91d7b43012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d47602000002000000000101f33b3ce193ef8a4450c6b4db2184538c0e5c5c5406e549478d8afe10b3d7e1760000000000feffffff02a0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee13373f25000000001600147235fdc337715c994998751dbfb0f3a38e87594e02473044022071323b810bed75c508337a442268503d70ac598f8db2fd0af57fb7ff6b913450022075157811bc930b2a7e2dc2cf5d6b075ca99e3e81bef2992111e43b8aebe9a0ac012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d434020000"

	network := int(KCfdNetworkMainnet)
	hash, header, err := CfdGoGetBlockHeaderData(network, blockHex)
	assert.NoError(t, err)
	assert.Equal(t, "0ae1754425645e84cf354366150db602bd1ca38a5b64b6d7949ffc7f5480ab41", hash)
	assert.NotNil(t, header)
	if header != nil {
		assert.Equal(t, uint32(536870912), header.Version)
		assert.Equal(t, "42960b23c8af44e5c2b2a372ef44f069898f1f085adabe72420f03ccf7e187d9", header.PrevBlockHash)
		assert.Equal(t, "03af1d58df59023834b82f0e7c0debe4411b520bfa7cabaa65fa46b743deb5d8", header.MerkleRoot)
		assert.Equal(t, uint32(1622375957), header.Time)
		assert.Equal(t, uint32(0x207fffff), header.Bits)
		assert.Equal(t, uint32(1), header.Nonce)
	}

	count, err := CfdGoGetTxCountInBlock(network, blockHex)
	assert.NoError(t, err)
	assert.Equal(t, uint32(21), count)

	txid := "cb3f209415bd73c709740fa0742ba960679cf22e86f691d11eb08e4a85cef95f"
	txidList, err := CfdGoGetTxidListFromBlock(network, blockHex)
	assert.NoError(t, err)
	assert.Equal(t, 21, len(txidList))
	if len(txidList) == 21 {
		expTxidList := []string{
			"7f5fb624f5cdce391362aa6befea307c4e778e008e799b40ca7119046f26ab31",
			"b4bcb584d0ee9c1e687c69ad0497b2686f7d47529affc0f1df8210b2a074c40c",
			"7af0cb6d0a0ded748790daa5e20b079e30cc82d90a267cad982328ed11409c17",
			"8d0b1863957eaa5b9c82a07c4e8b78801e496a8af4ed11450186fb1e7bdbfa29",
			"b42e9550b5129b34152950843ca09b0674a51ef4d273688366b216db7da16442",
			"d4ebf5a67e891b059c6aa67dd06c0ac3e129bf959919e2077c6519d6d460b347",
			"5edd72b9fef5225167c11862063c8cd955e648e01470b9784693d3868eaadf49",
			"d6f11f1fa8efb17911c1918ec1f2964d20b6bd5ddcefc60acc751094344f2b5e",
			"cb3f209415bd73c709740fa0742ba960679cf22e86f691d11eb08e4a85cef95f",
			"f4be3e47478145959d2d0978bf1900db2521be4d4f2964b277c35b754133bc7d",
			"9c9a3d9783dd9ac6c14c0ee487fa94f2e53053a7c96d10c37f0289edcdeb2b7e",
			"a5ab7f31660deb709d4ab2a70f4ce16a7cb02a16b03e843a39aba43115d3217f",
			"dc11069c2643ff09717a290e7dc0e38863316ec68b24fbb7d47d4e670f74777f",
			"4b244572aaec7a7b92431f7371b42547aca705b7ede430081be6374e8a672282",
			"4ae603bfb1689c29b1e5feb2cbd2f1ebb950df3ed4b25b6ad98f2f56da8cac93",
			"18b54774739e59b7bb0ec6a7196000c0f8fe42b441502636bdb5adde40f9e8a8",
			"587b9d5224a54fb3427cd99dc276b8acab4d4322c1b5681408d74a2927cd62ac",
			"98bdb3d84051b02a8bb147bb34d2e34c5b32339aebcccff696429c04538a45df",
			"695eddd38e01b5f67f93d3dcbdca033e1d8fd3feaefbdbcc2a2bd1326a6b7be4",
			"2bc841beb4de23e39e9674f96afc7a8b3c6db60c6d3c645c06a747eeb5135ae8",
			"be37763a766b5aa48d31a44a2c34ff1355e55e7f0efae58de9594d4eae3ca8ed",
		}
		for index := 0; index < len(txidList); index++ {
			assert.Equal(t, expTxidList[index], txidList[index])
		}
	}

	txHex, proof, err := CfdGoGetTransactionDataFromBlock(network, blockHex, txid)
	assert.NoError(t, err)
	assert.Equal(t, "020000000001016de1c5853fd550cb2fdd67f25b32496bb182404e2f127b5e82e48c587622eabc0000000000feffffff0213373f250000000016001496864cef7241cc0c24e8914f4ec75e34da0a70a6a0860100000000001600143df45aa3e4c76b1f2f4693675770ba4e3db2acee0247304402207dde78431c3e5ede2a90af0b3e3d32fadb5712e5ec04e3fac2dc6137d747187902202fc5603f63ce4498ad9062ed35b37ca5fc9a19fc90a9ef40ddec55b30820862c012102b30fc0ddd4de67700667921a0c73f9e773d473c4827abe8c63b5060725b745d476020000", txHex)
	assert.Equal(t, "00000020d987e1f7cc030f4272beda5a081f8f8969f044ef72a3b2c2e544afc8230b9642d8b5de43b746fa65aaab7cfa0b521b41e4eb0d7c0e2fb834380259df581daf03157eb360ffff7f20010000001500000006774b1a7f9e060f94a1c7bd9d8109e233014e4e74a09a5b85a42add1837c18de15ff9ce854a8eb01ed191f6862ef29c6760a92b74a00f7409c773bd1594203fcb7dbc3341755bc377b264294f4dbe2125db0019bf78092d9d95458147473ebef40b484381159b8168441d718d2855f98b076d7f319e08fc129fc6684a10364d6cab62141fa7cf9455e1db2b83d9746dcb4151f71cbde29b8074d9c280cf2329858c705d27704a43f47e3a3066b9253a3d7380cb20874e67178450d2ab376f06ee027b00", proof)

	exist, err := CfdGoExistTxidInBlock(network, blockHex, txid)
	assert.NoError(t, err)
	assert.True(t, exist)

	exist, err = CfdGoExistTxidInBlock(network, blockHex, "f5ce9417846b075c82da9368ed6bf40b59721662b64e4dd506fbdc50911f39fe")
	assert.NoError(t, err)
	assert.False(t, exist)
}
