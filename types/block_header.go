package types

// BlockHeader block header information.
type BlockHeader struct {
	Version       uint32 // Version
	PrevBlockHash string // previous block hash
	MerkleRoot    string // merkleroot
	Time          uint32 // block time
	Bits          uint32 // bit flag
	Nonce         uint32 // nonce
}
