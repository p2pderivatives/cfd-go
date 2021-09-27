package errors

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMultiError(t *testing.T) {
	emptyError := NewMultiError(CfdError("empty error"))
	assert.Empty(t, GetErrors(emptyError))
	assert.False(t, emptyError.Exist())

	singleError := NewMultiError(CfdError("single error"),
		fmt.Errorf("1st error"))
	assert.Len(t, GetErrors(singleError), 1)
	assert.True(t, singleError.Exist())
	singleError.Add(nil)
	assert.Len(t, GetErrors(singleError), 1)

	multiError := NewMultiError(CfdError("multi error"),
		fmt.Errorf("1st error"))
	multiError.Add(fmt.Errorf("2nd error"))
	multiError.Add(fmt.Errorf("3rd error"))
	assert.Len(t, multiError.GetErrors(), 3)
	assert.True(t, multiError.Exist())

	copyError := NewMultiError(CfdError("copy error"))
	copyError = Append(copyError, multiError)
	assert.Len(t, copyError.GetErrors(), 3)
	assert.True(t, copyError.Exist())
	copyError = Append(copyError, nil)
	assert.Len(t, copyError.GetErrors(), 3)

	appendError := Append(nil, multiError.GetErrors()...)
	assert.Error(t, appendError)
	assert.Len(t, GetErrors(appendError), 3)
	assert.True(t, appendError.Exist())
	appendError = Append(appendError, multiError)
	assert.Len(t, GetErrors(appendError), 6)
	appendError = Append(appendError, emptyError)
	assert.Len(t, GetErrors(appendError), 6)

	changeMsgError := NewMultiError(CfdError("msg error"))
	changeMsgError.SetError(CfdError("change error"))
	assert.Contains(t, changeMsgError.Error(), "change error")

	// empty check
	assert.Empty(t, GetErrors(nil))
	assert.Empty(t, Append(nil, nil))
	assert.Empty(t, Append(nil))
	// empty check
	assert.Len(t, GetErrors(CfdError("normal error")), 1)

	// nil
	var nilMultiError *MultiError
	assert.Empty(t, GetErrors(nilMultiError))
	assert.False(t, nilMultiError.Exist())
}
