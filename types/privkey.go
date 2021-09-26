package types

// Privkey ...
type Privkey struct {
	Hex                string
	Wif                string
	Network            NetworkType
	IsCompressedPubkey bool
}
