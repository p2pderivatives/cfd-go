package cfdgo

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCfdCreateHandle(t *testing.T) {
	ret := CfdCreateHandle(nil)
	assert.Equal(t, 1, ret)

	var handle uintptr
	ret = CfdCreateHandle(&handle)
	assert.Equal(t, 0, ret)

	ret = CfdFreeHandle(handle)
	assert.Equal(t, 0, ret)
	fmt.Print("TestCfdCreateHandle test done.\n")
}

func TestCfdGetLastError(t *testing.T) {
	var handle uintptr
	ret := CfdCreateHandle(&handle)
	assert.Equal(t, 0, ret)

	lastErr := CfdGetLastErrorCode(handle)
	assert.Equal(t, 0, lastErr)

	errStr := ""
	ret = CfdGetLastErrorMessage(handle, &errStr)
	assert.Equal(t, 0, ret)
	assert.Equal(t, "", errStr)

	ret = CfdFreeHandle(handle)
	assert.Equal(t, 0, ret)
	fmt.Print("TestCfdGetLastError test done.\n")
}
