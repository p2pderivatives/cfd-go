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

	hash_type := 2
	network_type := 10
	pubkey := "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
	redeem_script := ""
	//address, locking_script, _, addr_ret := CfdGoCreateAddress(handle, hash_type, pubkey, redeem_script, network_type)
	var address string
	var locking_script string
	addr_ret := CfdCreateAddress(handle, hash_type, pubkey, redeem_script, network_type, &address, &locking_script, nil)
	assert.Equal(t, 0, addr_ret)
	assert.Equal(t, "Q7wegLt2qMGhm28vch6VTzvpzs8KXvs4X7", address)
	assert.Equal(t, "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac", locking_script)

	hash_type = 1
	pubkey = ""
	redeem_script = "210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac"
	address2, locking_script2, _, addr_ret2 := CfdGoCreateAddress(
		handle, hash_type, pubkey, redeem_script, network_type)
	assert.Equal(t, 0, addr_ret2)
	assert.Equal(t, "GkSEheszYzEBMgX9G9ueaAyLVg8gfZwiDY", address2)
	assert.Equal(t, "a91423b0ad3477f2178bc0b3eed26e4e6316f4e83aa187", locking_script2)

	hash_type = 6
	pubkey = "0205ffcdde75f262d66ada3dd877c7471f8f8ee9ee24d917c3e18d01cee458bafe"
	redeem_script = ""
	address3, locking_script3, redeemScript, addr_ret3 := CfdGoCreateAddress(
		handle, hash_type, pubkey, redeem_script, network_type)
	assert.Equal(t, 0, addr_ret3)
	assert.Equal(t, "GsaK3GXnFAjdfZDBPPo9PD6UNyAJ53nS9Z", address3)
	assert.Equal(t, "a9147200818f884ee12b964442b059c11d0712b6abe787", locking_script3)
	assert.Equal(t, "0014ef692e4bf0cd5ed05235a4fc582ec4a4ff9695b4", redeemScript)

	ret = CfdFreeHandle(handle)
	assert.Equal(t, 0, ret)
	fmt.Print("TestCfdGoCreateAddress test done.\n")
}
