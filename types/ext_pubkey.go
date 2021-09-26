package types

// ExtPubkey xpub
type ExtPubkey struct {
	Key string
}

type ExtkeyData struct {
	// version
	Version string
	// parent fingerprint
	Fingerprint string
	// chain code
	ChainCode string
	// depth
	Depth uint32
	// child number
	ChildNumber uint32
	// key type
	KeyType ExtkeyType
	// network
	Network NetworkType
}
