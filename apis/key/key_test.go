package key

import (
	"testing"

	cfd "github.com/cryptogarageinc/cfd-go"
	"github.com/cryptogarageinc/cfd-go/config"
	cfdErrors "github.com/cryptogarageinc/cfd-go/errors"
	"github.com/cryptogarageinc/cfd-go/types"
	"github.com/stretchr/testify/assert"
)

func TestCfdPrivkeyAndPubkey(t *testing.T) {
	// pubkeyApi := (PubkeyApi)(NewPubkeyApi())

	network := types.Regtest
	privkeyApiImpl := NewPrivkeyApi(config.NetworkOption(network))
	assert.NoError(t, privkeyApiImpl.GetError())
	for _, errItem := range cfdErrors.GetErrors(privkeyApiImpl.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}
	privkeyApi := (PrivkeyApi)(privkeyApiImpl)

	// compress
	pubkeyHex, privkeyHex, wif, err := cfd.CfdGoCreateKeyPair(true, network.ToCfdValue())
	assert.NoError(t, err)
	assert.Equal(t, 66, len(pubkeyHex))
	assert.Equal(t, 64, len(privkeyHex))
	assert.Equal(t, 52, len(wif))
	pubkey := &types.Pubkey{Hex: pubkeyHex}

	assert.Equal(t, true, privkeyApi.HasWif(wif))
	assert.Equal(t, false, privkeyApi.HasWif(privkeyHex))

	privkey, err := privkeyApi.GetPrivkeyFromWif(wif)
	assert.NoError(t, err)
	assert.Equal(t, privkeyHex, privkey.Hex)
	assert.Equal(t, wif, privkey.Wif)
	assert.Equal(t, types.Testnet, privkey.Network)
	assert.Equal(t, true, privkey.IsCompressedPubkey)

	// wif2, err := CfdGoGetPrivkeyWif(privkey, kNetwork, true)
	// assert.NoError(t, err)
	// assert.Equal(t, wif, wif2)

	pubkey2, err := privkeyApi.GetPubkey(privkey)
	assert.NoError(t, err)
	assert.Equal(t, pubkey.Hex, pubkey2.Hex)
}
