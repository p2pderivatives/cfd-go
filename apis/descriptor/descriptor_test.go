package descriptor

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/cryptogarageinc/cfd-go/config"
	"github.com/cryptogarageinc/cfd-go/errors"
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

func TestCfdGoParseDescriptorData(t *testing.T) {
	// PKH
	descApi := NewDescriptorApi(config.NetworkOption(types.LiquidV1))
	assert.NoError(t, descApi.GetError())
	rootData, _, err := descApi.ParseByString(
		"pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)")
	assert.NoError(t, err)
	assert.Equal(t, uint32(0), rootData.Depth)
	assert.Equal(t, types.DescriptorTypePkh, rootData.Type)
	assert.Equal(t, "76a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac", rootData.Address.LockingScript.ToHex())
	assert.Equal(t, "PwsjpD1YkjcfZ95WGVZuvGfypkKmpogoA3", rootData.Address.Address)
	assert.Equal(t, types.P2pkh, rootData.HashType)
	assert.Nil(t, rootData.RedeemScript)
	assert.Equal(t, types.DescriptorKeyPublic, rootData.Key.KeyType)
	assert.Equal(t, "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5", rootData.Key.Pubkey.Hex)
	assert.Nil(t, rootData.Key.ExtPubkey)
	assert.Nil(t, rootData.Key.ExtPrivkey)
	assert.Nil(t, rootData.Multisig)
	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	// p2sh-p2wsh(pkh)
	rootData, details, err := descApi.ParseByString(
		"sh(wsh(pkh(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13)))")
	assert.NoError(t, err)
	assert.Equal(t, uint32(0), rootData.Depth)
	assert.Equal(t, types.DescriptorTypeSh, rootData.Type)
	assert.Equal(t, "a91455e8d5e8ee4f3604aba23c71c2684fa0a56a3a1287", rootData.Address.LockingScript.ToHex())
	assert.Equal(t, "Gq1mmExLuSEwfzzk6YtUxJ769grv6T5Tak", rootData.Address.Address)
	assert.Equal(t, types.P2shP2wsh, rootData.HashType)
	assert.Equal(t, "76a914c42e7ef92fdb603af844d064faad95db9bcdfd3d88ac", rootData.RedeemScript.ToHex())
	assert.Equal(t, types.DescriptorKeyPublic, rootData.Key.KeyType)
	assert.Equal(t, "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13", rootData.Key.Pubkey.Hex)
	assert.Nil(t, rootData.Key.ExtPubkey)
	assert.Nil(t, rootData.Key.ExtPrivkey)
	assert.Nil(t, rootData.Multisig)
	assert.Equal(t, "0020fc5acc302aab97f821f9a61e1cc572e7968a603551e95d4ba12b51df6581482f", details[0].RedeemScript)
	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	// multisig (bitcoin)
	descApi = NewDescriptorApi(config.NetworkOption(types.Mainnet))
	assert.NoError(t, descApi.GetError())
	rootData, _, err = descApi.ParseWithDerivationPath(
		&types.Descriptor{OutputDescriptor: "wsh(multi(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))"},
		"0")
	assert.NoError(t, err)
	assert.Equal(t, uint32(0), rootData.Depth)
	assert.Equal(t, types.DescriptorTypeWsh, rootData.Type)
	assert.Equal(t, "002064969d8cdca2aa0bb72cfe88427612878db98a5f07f9a7ec6ec87b85e9f9208b", rootData.Address.LockingScript.ToHex())
	assert.Equal(t, "bc1qvjtfmrxu524qhdevl6yyyasjs7xmnzjlqlu60mrwepact60eyz9s9xjw0c", rootData.Address.Address)
	assert.Equal(t, types.P2wsh, rootData.HashType)
	assert.Equal(t, "51210205f8f73d8a553ad3287a506dbd53ed176cadeb200c8e4f7d68a001b1aed871062102c04c4e03921809fcbef9a26da2d62b19b2b4eb383b3e6cfaaef6370e7514477452ae", rootData.RedeemScript.ToHex())
	assert.Equal(t, false, rootData.Key.KeyType.Valid())
	assert.Nil(t, rootData.Key.Pubkey)
	assert.Nil(t, rootData.Key.ExtPubkey)
	assert.Nil(t, rootData.Key.ExtPrivkey)
	assert.NotNil(t, rootData.Multisig)
	assert.Equal(t, uint32(1), rootData.Multisig.ReqSigNum)
	assert.Equal(t, 2, len(rootData.Multisig.Keys))
	assert.Equal(t, "0205f8f73d8a553ad3287a506dbd53ed176cadeb200c8e4f7d68a001b1aed87106", rootData.Multisig.Keys[0].Pubkey.Hex)
	assert.Equal(t, "02c04c4e03921809fcbef9a26da2d62b19b2b4eb383b3e6cfaaef6370e75144774", rootData.Multisig.Keys[1].Pubkey.Hex)
	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	// miniscript wsh
	rootData, _, err = descApi.ParseWithDerivationPath(
		&types.Descriptor{OutputDescriptor: "wsh(thresh(2,multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00),a:multi(1,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00),ac:pk_k(022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01)))"},
		"0")
	assert.NoError(t, err)
	assert.Equal(t, uint32(0), rootData.Depth)
	assert.Equal(t, types.DescriptorTypeWsh, rootData.Type)
	assert.Equal(t, "00206a6c42f62db9fab091ffaf930e0a847646898d225e1ad94ff43226e20180b9d1", rootData.Address.LockingScript.ToHex())
	assert.Equal(t, "bc1qdfky9a3dh8atpy0l47fsuz5ywergnrfztcddjnl5xgnwyqvqh8gschn2ch", rootData.Address.Address)
	assert.Equal(t, types.P2wsh, rootData.HashType)
	assert.Equal(t, "522103a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c721036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a0052ae6b5121036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a0051ae6c936b21022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01ac6c935287", rootData.RedeemScript.ToHex())
	assert.Equal(t, false, rootData.Key.KeyType.Valid())
	assert.Nil(t, rootData.Key.Pubkey)
	assert.Nil(t, rootData.Key.ExtPubkey)
	assert.Nil(t, rootData.Key.ExtPrivkey)
	assert.Nil(t, rootData.Multisig)
	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	// miniscript wsh derive
	rootData, _, err = descApi.ParseWithDerivationPath(
		&types.Descriptor{OutputDescriptor: "sh(wsh(c:or_i(andor(c:pk_h(xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*),pk_h(xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*),pk_h(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)),pk_k(02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e))))"},
		"44")
	assert.NoError(t, err)
	assert.Equal(t, uint32(0), rootData.Depth)
	assert.Equal(t, types.DescriptorTypeSh, rootData.Type)
	assert.Equal(t, "a914a7a9f411001e3e3db96d7f02fc9ab1d0dc6aa69187", rootData.Address.LockingScript.ToHex())
	assert.Equal(t, "3GyYN9WnJBoMn8M5tuqVcFJq1BvbAcdPAt", rootData.Address.Address)
	assert.Equal(t, types.P2shP2wsh, rootData.HashType)
	assert.Equal(t, "6376a914520e6e72bcd5b616bc744092139bd759c31d6bbe88ac6476a91406afd46bcdfd22ef94ac122aa11f241244a37ecc886776a9145ab62f0be26fe9d6205a155403f33e2ad2d31efe8868672102d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e68ac", rootData.RedeemScript.ToHex())
	assert.Equal(t, types.DescriptorKeyNull, rootData.Key.KeyType)
	assert.Nil(t, rootData.Key.Pubkey)
	assert.Nil(t, rootData.Key.ExtPubkey)
	assert.Nil(t, rootData.Key.ExtPrivkey)
	assert.Nil(t, rootData.Multisig)
	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}

func TestParseDescriptorByFilter(t *testing.T) {
	// PKH
	descApi := NewDescriptorApi(config.NetworkOption(types.LiquidV1))
	assert.NoError(t, descApi.GetError())
	filter := &types.DescriptorParseFilter{}
	filter.EnableHashTypes = []types.HashType{types.P2pkh}
	rootData, _, err := descApi.ParseByFilter(
		&types.Descriptor{OutputDescriptor: "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)"}, filter)
	assert.NoError(t, err)
	assert.Equal(t, types.P2pkh, rootData.HashType)
	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	filter.EnableHashTypes = []types.HashType{types.P2wpkh}
	rootData, _, err = descApi.ParseByFilter(
		&types.Descriptor{OutputDescriptor: "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)"}, filter)
	assert.Error(t, err)
	assert.Nil(t, rootData)
	assert.Equal(t, errors.ErrDescriptorFilter, err)

	filter.EnableHashTypes = nil
	filter.DisableHashTypes = []types.HashType{types.P2pkh}
	rootData, _, err = descApi.ParseByFilter(
		&types.Descriptor{OutputDescriptor: "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)"}, filter)
	assert.Error(t, err)
	assert.Nil(t, rootData)
	assert.Equal(t, errors.ErrDescriptorFilter, err)

	// p2sh-p2wsh(pkh)
	filter.EnableHashTypes = nil
	filter.DisableHashTypes = nil
	rootData, _, err = descApi.ParseByFilter(
		&types.Descriptor{OutputDescriptor: "sh(wsh(pkh(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13)))"}, filter)
	assert.NoError(t, err)
	assert.Equal(t, types.P2shP2wsh, rootData.HashType)
	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	filter.IsMultisigOnlyOnScriptHash = true
	rootData, _, err = descApi.ParseByFilter(
		&types.Descriptor{OutputDescriptor: "sh(wsh(pkh(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13)))"}, filter)
	assert.Error(t, err)
	assert.Nil(t, rootData)
	assert.Equal(t, errors.ErrDescriptorFilter, err)

	filter.IsMultisigOnlyOnScriptHash = false
	filter.EnableRootDescriptorTypes = []types.DescriptorType{types.DescriptorTypeSh}
	rootData, _, err = descApi.ParseByFilter(
		&types.Descriptor{OutputDescriptor: "sh(wsh(pkh(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13)))"}, filter)
	assert.NoError(t, err)
	assert.Equal(t, types.P2shP2wsh, rootData.HashType)
	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	filter.EnableRootDescriptorTypes = []types.DescriptorType{types.DescriptorTypeWsh}
	rootData, _, err = descApi.ParseByFilter(
		&types.Descriptor{OutputDescriptor: "sh(wsh(pkh(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13)))"}, filter)
	assert.Error(t, err)
	assert.Nil(t, rootData)
	assert.Equal(t, errors.ErrDescriptorFilter, err)

	filter.EnableRootDescriptorTypes = nil
	filter.DisableRootDescriptorTypes = []types.DescriptorType{types.DescriptorTypeSh}
	rootData, _, err = descApi.ParseByFilter(
		&types.Descriptor{OutputDescriptor: "sh(wsh(pkh(02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13)))"}, filter)
	assert.Error(t, err)
	assert.Nil(t, rootData)
	assert.Equal(t, errors.ErrDescriptorFilter, err)

	// multisig (bitcoin)
	descApi = NewDescriptorApi(config.NetworkOption(types.Mainnet))
	assert.NoError(t, descApi.GetError())
	filter.IsMultisigOnlyOnScriptHash = false
	rootData, _, err = descApi.ParseByFilterWithDerivationPath(
		&types.Descriptor{OutputDescriptor: "wsh(multi(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))"},
		"0", filter)
	assert.NoError(t, err)
	assert.Equal(t, types.P2wsh, rootData.HashType)
	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	filter.IsMultisigOnlyOnScriptHash = true
	rootData, _, err = descApi.ParseByFilterWithDerivationPath(
		&types.Descriptor{OutputDescriptor: "wsh(multi(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))"},
		"0", filter)
	assert.NoError(t, err)
	assert.Equal(t, types.P2wsh, rootData.HashType)
	if err != nil {
		fmt.Print("[error message] " + err.Error() + "\n")
	}

	fmt.Printf("%s test done.\n", GetFuncName())
}
