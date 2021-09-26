package types

type SignParameter struct {
	Data          Script
	IsDerEncode   bool
	SigHashType   SigHashType
	RelatedPubkey *Pubkey
}

func NewSignParameterFromString(derSignature, relatedPubkey string) *SignParameter {
	return &SignParameter{
		Data:          *NewScriptFromHexIgnoreError(derSignature),
		RelatedPubkey: &Pubkey{Hex: relatedPubkey},
	}
}
