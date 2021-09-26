package types

import (
	"encoding/hex"

	cfd "github.com/cryptogarageinc/cfd-go"
)

// ByteData This struct holds a byte array.
type ByteData struct {
	hex string
}

// NewByteData This function create a bytedata from a byte array.
func NewByteData(data []byte) ByteData {
	var obj ByteData
	obj.hex = hex.EncodeToString(data)
	return obj
}

// NewByteDataFromHex This function create a bytedata from a hex string.
func NewByteDataFromHex(hexStr string) (ByteData, error) {
	var obj ByteData
	_, osErr := hex.DecodeString(hexStr)
	if osErr != nil {
		return obj, cfd.ConvertCfdErrorCode(int(cfd.KCfdIllegalArgumentError))
	}
	obj.hex = hexStr
	return obj, nil
}

// NewByteDataFromHex This function create a bytedata from a hex string. On error, it returns nil.
func NewByteDataFromHexIgnoreError(hexStr string) *ByteData {
	var obj ByteData
	_, osErr := hex.DecodeString(hexStr)
	if osErr != nil {
		return nil
	}
	obj.hex = hexStr
	return &obj
}

// ToHex This function return a hex string.
func (obj *ByteData) ToHex() string {
	return obj.hex
}

// ToHex This function return a byte array.
func (obj *ByteData) ToSlice() []byte {
	data, osErr := hex.DecodeString(obj.hex)
	if osErr != nil {
		return []byte{}
	}
	return data
}
