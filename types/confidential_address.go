package types

// ConfidentialAddress ...
type ConfidentialAddress struct {
	ConfidentialAddress string
	Address             string
	Network             NetworkType
	Type                AddressType
	ConfidentialKey     *Pubkey
}
