package errors

type CfdError string

const (
	// error
	ErrNetworkConfig    CfdError = "CFD Error: Invalid network configuration"
	ErrElementsNetwork  CfdError = "CFD Error: Network configuration is not elements"
	ErrBitcoinNetwork   CfdError = "CFD Error: Network configuration is not bitcoin"
	ErrUnmatchNetwork   CfdError = "CFD Error: network type is unmatching"
	ErrParameterNil     CfdError = "CFD Error: Parameter is nil"
	ErrDescriptorFilter CfdError = "CFD Error: Descriptor that does not match the condition"
	ErrMultisigScript   CfdError = "CFD Error: Invalid multisig script"

	InternalError CfdError = "CFD Error: Internal error"

	// text
	InvalidConfigErrorMessage string = "Invalid configuration"
)

// Error returns the error string.
func (e CfdError) Error() string {
	return string(e)
}

// HasInitializeError has a InitializeError object.
type HasInitializeError struct {
	InitializeError error
}

// SetError returns HasInitializeError pointer.
func (e *HasInitializeError) SetError(err error) {
	if e == nil || err == nil {
		return
	}
	multiError, ok := e.InitializeError.(*MultiError)
	if !ok {
		multiError = NewMultiError(CfdError("CFD Error: initialize error"))
	}
	multiError.Add(err)
	e.InitializeError = multiError
}

// GetError returns error interface.
func (e *HasInitializeError) GetError() error {
	if e == nil {
		return nil
	}
	return e.InitializeError
}

// HasError returns error exist flag.
func (e *HasInitializeError) HasError() bool {
	if e == nil {
		return false
	}
	return e.InitializeError != nil
}
