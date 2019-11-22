package cfdgo

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCfdCreateHandle(t *testing.T) {
	ret := CfdCreateHandle(nil)
	assert.Equal(t, 1, ret)

	handle, ret := CfdGoCreateHandle()
	assert.Equal(t, 0, ret)

	ret = CfdFreeHandle(handle)
	assert.Equal(t, 0, ret)
	fmt.Print("TestCfdCreateHandle test done.\n")
}

func TestCfdGetLastError(t *testing.T) {
	handle, ret := CfdGoCreateHandle()
	assert.Equal(t, 0, ret)

	lastErr := CfdGetLastErrorCode(handle)
	assert.Equal(t, 0, lastErr)

	errStr, strret := CfdGoGetLastErrorMessage(handle)
	assert.Equal(t, 0, strret)
	assert.Equal(t, "", errStr)

	_, _, _, strret = CfdGoCreateAddress(handle, 200, "", "", 200)
	lastErr = CfdGetLastErrorCode(handle)
	assert.Equal(t, (int)(KCfdIllegalArgumentError), lastErr)
	assert.Equal(t, strret, lastErr)
	errStr, _ = CfdGoGetLastErrorMessage(handle)
	assert.Equal(t, "Illegal network type.", errStr)

	ret = CfdFreeHandle(handle)
	assert.Equal(t, 0, ret)
	fmt.Print("TestCfdGetLastError test done.\n")
}

func TestCfdGetSupportedFunction(t *testing.T) {
	handle, ret := CfdGoCreateHandle()
	assert.Equal(t, 0, ret)

	flag, ret2 := CfdGoGetSupportedFunction()
	assert.Equal(t, 0, ret2)
	assert.Equal(t, uint64(1), (flag & 0x01))

	ret = CfdFreeHandle(handle)
	assert.Equal(t, 0, ret)
	fmt.Print("TestCfdGetSupportedFunction test done.\n")
}

func TestCfdGoCreateAddress(t *testing.T) {
	handle, ret := CfdGoCreateHandle()
	assert.Equal(t, 0, ret)

	hashType := (int)(KCfdP2pkh)
	networkType := (int)(KCfdNetworkLiquidv1)
	pubkey := "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
	address, lockingScript, segwitLockingScript, addrRet := CfdGoCreateAddress(handle, hashType, pubkey, "", networkType)
	assert.Equal(t, 0, addrRet)
	assert.Equal(t, "Q7wegLt2qMGhm28vch6VTzvpzs8KXvs4X7", address)
	assert.Equal(t, "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac", lockingScript)
	assert.Equal(t, "", segwitLockingScript)

	hashType = (int)(KCfdP2sh)
	redeemScript := "210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac"
	address, lockingScript, segwitLockingScript, addrRet = CfdGoCreateAddress(
		handle, hashType, "", redeemScript, networkType)
	assert.Equal(t, 0, addrRet)
	assert.Equal(t, "GkSEheszYzEBMgX9G9ueaAyLVg8gfZwiDY", address)
	assert.Equal(t, "a91423b0ad3477f2178bc0b3eed26e4e6316f4e83aa187", lockingScript)
	assert.Equal(t, "", segwitLockingScript)

	hashType = (int)(KCfdP2shP2wpkh)
	pubkey = "0205ffcdde75f262d66ada3dd877c7471f8f8ee9ee24d917c3e18d01cee458bafe"
	address, lockingScript, segwitLockingScript, addrRet = CfdGoCreateAddress(
		handle, hashType, pubkey, "", networkType)
	assert.Equal(t, 0, addrRet)
	assert.Equal(t, "GsaK3GXnFAjdfZDBPPo9PD6UNyAJ53nS9Z", address)
	assert.Equal(t, "a9147200818f884ee12b964442b059c11d0712b6abe787", lockingScript)
	assert.Equal(t, "0014ef692e4bf0cd5ed05235a4fc582ec4a4ff9695b4", segwitLockingScript)

	hashType = (int)(KCfdP2wpkh)
	networkType = (int)(KCfdNetworkElementsRegtest)
	pubkey = "02bedf98a38247c1718fdff7e07561b4dc15f10323ebb0accab581778e72c2e995"
	address, lockingScript, segwitLockingScript, addrRet = CfdGoCreateAddress(
		handle, hashType, pubkey, "", networkType)
	assert.Equal(t, 0, addrRet)
	assert.Equal(t, "ert1qs58jzsgjsteydejyhy32p2v2vm8llh9uns6d93", address)
	assert.Equal(t, "0014850f21411282f246e644b922a0a98a66cfffdcbc", lockingScript)
	assert.Equal(t, "", segwitLockingScript)

	ret = CfdFreeHandle(handle)
	assert.Equal(t, 0, ret)
	fmt.Print("TestCfdGoCreateAddress test done.\n")
}
