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
