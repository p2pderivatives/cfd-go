package types

// Address ...
type Address struct {
	Address       string
	Network       NetworkType
	Type          AddressType
	LockingScript Script
}
