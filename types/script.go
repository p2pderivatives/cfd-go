package types

import (
	"encoding/hex"

	cfd "github.com/cryptogarageinc/cfd-go"
	"github.com/pkg/errors"
)

// Script This struct holds a script.
type Script struct {
	hex string
}

// NewScript This function create a script from a byte array.
func NewScript(data []byte) Script {
	var obj Script
	obj.hex = hex.EncodeToString(data)
	return obj
}

// NewScriptFromHex This function create a script from a hex string.
func NewScriptFromHex(hexStr string) (Script, error) {
	var obj Script
	_, osErr := hex.DecodeString(hexStr)
	if osErr != nil {
		return obj, cfd.ConvertCfdErrorCode(int(cfd.KCfdIllegalArgumentError))
	}
	obj.hex = hexStr
	return obj, nil
}

// NewScriptFromHex This function create a script from a hex string. On error, it returns nil.
func NewScriptFromHexIgnoreError(hexStr string) *Script {
	var obj Script
	_, osErr := hex.DecodeString(hexStr)
	if osErr != nil {
		return nil
	}
	obj.hex = hexStr
	return &obj
}

// NewScriptFromAsm This function create a script from an asm string.
func NewScriptFromAsm(scriptAsm string) (Script, error) {
	var obj Script
	hexStr, err := cfd.CfdGoConvertScriptAsmToHex(scriptAsm)
	if err != nil {
		return obj, errors.Wrap(err, "parse script asm error")
	}
	_, osErr := hex.DecodeString(hexStr)
	if osErr != nil {
		return obj, cfd.ConvertCfdErrorCode(int(cfd.KCfdIllegalArgumentError))
	}
	obj.hex = hexStr
	return obj, nil
}

// NewScriptFromAsmList This function create a script from the asm string list.
func NewScriptFromAsmList(scriptAsmList []string) (Script, error) {
	var obj Script
	hexStr, err := cfd.CfdGoCreateScript(scriptAsmList)
	if err != nil {
		return obj, errors.Wrap(err, "create script error")
	}
	_, osErr := hex.DecodeString(hexStr)
	if osErr != nil {
		return obj, cfd.ConvertCfdErrorCode(int(cfd.KCfdIllegalArgumentError))
	}
	obj.hex = hexStr
	return obj, nil
}

// ToHex This function return a hex string.
func (obj *Script) ToHex() string {
	return obj.hex
}

// ToHex This function return a byte array.
func (obj *Script) ToSlice() []byte {
	data, osErr := hex.DecodeString(obj.hex)
	if osErr != nil {
		return []byte{}
	}
	return data
}

// IsEmpty This function return a empty or not.
func (obj *Script) IsEmpty() bool {
	return len(obj.hex) == 0
}

// Parse This function return a parsing script.
func (obj *Script) Parse() (scriptItems []string, err error) {
	return cfd.CfdGoParseScript(obj.hex)
}
