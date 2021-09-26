package types

import (
	"fmt"

	cfd "github.com/cryptogarageinc/cfd-go"
)

const (
	SequenceLockTimeFinal     uint32 = 0xffffffff
	SequenceLockTimeEnableMax uint32 = 0xfffffffe
)

// Transaction ...
type Transaction struct {
	Hex string
}

// OutPoint : utxo outpoint struct.
type OutPoint struct {
	// txid
	Txid string
	// vout
	Vout uint32
}

// ScriptWitness : witness stack.
type ScriptWitness struct {
	// witness stack by hex.
	Stack []string
}

// TxIn : transaction input.
type TxIn struct {
	// utxo outpoint.
	OutPoint OutPoint
	// sequence number.
	Sequence uint32
	// script sig.
	ScriptSig string
	// witness stack.
	WitnessStack ScriptWitness
}

// TxOut : transaction output.
type TxOut struct {
	// satoshi amount.
	Amount int64
	// locking script.
	LockingScript string
	// address (if locking script is usual hashtype.)
	Address string
}

type UtxoData struct {
	OutPoint          OutPoint // OutPoint
	Amount            int64    // satoshi value
	Descriptor        string   // output descriptor
	ScriptSigTemplate string   // scriptsig template hex (require script hash estimate fee)
	Asset             string   // Asset
	AmountCommitment  string   // Amount commitment
}

/**
 * TransactionData data struct.
 */
type TransactionData struct {
	// txid
	Txid string
	// witness txid
	Wtxid string
	// witness hash
	WitHash string
	// size
	Size uint32
	// virtual size
	Vsize uint32
	// weight
	Weight uint32
	// version
	Version uint32
	// locktime
	LockTime uint32
}

type InputTxIn struct {
	OutPoint OutPoint
	Sequence uint32
}

type InputTxOut struct {
	Amount        int64  // satoshi amount (unblind value)
	LockingScript string // locking script
	Address       string // address or confidential address. (if locking script is usual hashtype.)
}

// String This function return outpoint's string.
func (o OutPoint) String() string {
	return fmt.Sprintf("%s,%d", o.Txid, o.Vout)
}

// String This function return outpoint's string.
func (o OutPoint) Equal(target OutPoint) bool {
	if (o.Txid == target.Txid) && (o.Vout == target.Vout) {
		return true
	}
	return false
}

func (u UtxoData) ConvertToCfdUtxo() cfd.CfdUtxo {
	utxo := cfd.CfdUtxo{
		Txid:              u.OutPoint.Txid,
		Vout:              u.OutPoint.Vout,
		Amount:            u.Amount,
		Descriptor:        u.Descriptor,
		ScriptSigTemplate: u.ScriptSigTemplate,
		Asset:             u.Asset,
		AmountCommitment:  u.AmountCommitment,
	}
	return utxo
}
