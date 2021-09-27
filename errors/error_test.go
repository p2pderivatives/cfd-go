package errors

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

type TestHasInitializeErrorObject struct {
	HasInitializeError
}

type TestHasInitializeErrorStub struct {
	*HasInitializeError
}

func TestHasInitializeError(t *testing.T) {
	emptyError := TestHasInitializeErrorObject{}
	assert.NoError(t, emptyError.GetError())
	assert.False(t, emptyError.HasError())

	singleError := TestHasInitializeErrorObject{}
	singleError.SetError(fmt.Errorf("1st error"))
	assert.Error(t, singleError.GetError())
	assert.True(t, singleError.HasError())
	assert.Len(t, GetErrors(singleError.GetError()), 1)
	singleError.SetError(nil)
	assert.Len(t, GetErrors(singleError.GetError()), 1)

	multiError := TestHasInitializeErrorObject{}
	multiError.SetError(fmt.Errorf("1st error"))
	multiError.SetError(fmt.Errorf("2nd error"))
	multiError.SetError(fmt.Errorf("3rd error"))
	assert.Len(t, GetErrors(multiError.GetError()), 3)
	assert.True(t, multiError.HasError())

	// other error
	otherError := TestHasInitializeErrorObject{}
	otherError.HasInitializeError = HasInitializeError{} // empty "error"
	otherError.SetError(fmt.Errorf("other error"))
	// "error" force override
	assert.Contains(t, otherError.GetError().Error(), "CFD Error: initialize error")
	assert.Len(t, GetErrors(otherError.GetError()), 1)
	assert.True(t, otherError.HasError())
	assert.Error(t, otherError.GetError())

	// nil
	errorStub := TestHasInitializeErrorStub{}
	errorStub.SetError(fmt.Errorf("stub error"))
	assert.False(t, errorStub.HasError())
	assert.NoError(t, errorStub.GetError())
}
