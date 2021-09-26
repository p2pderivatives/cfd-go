package key

import (
	"testing"

	"github.com/cryptogarageinc/cfd-go/config"
	cfdErrors "github.com/cryptogarageinc/cfd-go/errors"
	"github.com/cryptogarageinc/cfd-go/types"
	"github.com/stretchr/testify/assert"
)

func TestCfdExtkey(t *testing.T) {
	seed := types.NewByteDataFromHexIgnoreError(
		"0e09fbdd00e575b654d480ae979f24da45ef4dee645c7dc2e3b30b2e093d38dda0202357754cc856f8920b8e31dd02e9d34f6a2b20dc825c6ba90f90009085e1")
	network := types.Mainnet
	cfdCfg := config.NetworkOption(network)

	hdwalletApiImpl := NewHdWalletApi(cfdCfg)
	assert.NoError(t, hdwalletApiImpl.GetError())
	for _, errItem := range cfdErrors.GetErrors(hdwalletApiImpl.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}
	extPrivkeyApiImpl := NewExtPrivkeyApi(cfdCfg)
	assert.NoError(t, extPrivkeyApiImpl.GetError())
	for _, errItem := range cfdErrors.GetErrors(extPrivkeyApiImpl.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}
	extPubkeyApiImpl := NewExtPubkeyApi(cfdCfg)
	assert.NoError(t, extPubkeyApiImpl.GetError())
	for _, errItem := range cfdErrors.GetErrors(extPubkeyApiImpl.GetError()) {
		if multiError, ok := errItem.(*cfdErrors.MultiError); ok {
			assert.NoError(t, errItem)
			for _, innerError := range cfdErrors.GetErrors(multiError) {
				assert.NoError(t, innerError)
			}
		}
	}
	hdwalletApi := (HdWalletApi)(hdwalletApiImpl)
	extPrivkeyApi := (ExtPrivkeyApi)(extPrivkeyApiImpl)
	extPubkeyApi := (ExtPubkeyApi)(extPubkeyApiImpl)

	extprivkey1, err := hdwalletApi.GetExtPrivkey(seed)
	assert.NoError(t, err)
	assert.Equal(t, "xprv9s21ZrQH143K38XAstQ4D3hCGbgydJgNff6CcwmkrWTBxksb2G4CsqAywJCKbTdywfCpmpJyxqf77iKK1ju1J982iP2PriifaNZLMbyPQCx", extprivkey1.Key)

	extprivkey2, err := hdwalletApi.GetExtPrivkeyByPath(seed, "m/44'")
	assert.NoError(t, err)
	assert.Equal(t, "xprv9tviYANkXM1CY831VtMFKFn6LP6aMHf1kvtCZyTL9YbyMwTR2BSmJaEoqw59BZdQhLSx9ZxyKsRUeCetxA2xZ34eupBqZUsifnWyLJJ16j3", extprivkey2.Key)

	extpubkey1, err := extPrivkeyApi.GetExtPubkey(extprivkey2)
	assert.NoError(t, err)
	assert.Equal(t, "xpub67v4wfueMiZVkc7UbutFgPiptQw4kkNs89ooNMrwht8xEjnZZim1rNZHhEdrLejB99fiBdnWNNAB8hmUK7tCo5Ua6UtHzwVLj2Bzpch7vB2", extpubkey1.Key)

	pubkey0, err := extPubkeyApi.GetPubkey(extpubkey1)
	assert.NoError(t, err)
	assert.Equal(t, "03eded97b860b7cb5cbfda9f195151ed65f19f856edce22a94b2c7a1ad9c30aefe", pubkey0.Hex)

	extprivkey3, err := extPrivkeyApi.GetExtPrivkeyByPath(extprivkey2, "0h/0h/2")
	assert.NoError(t, err)
	assert.Equal(t, "xprvA1YYKkMiZaDHRY4dmXjcP3js7ATJQAwt9gozTvi69etziyBAAENQN4w7sS3uBaF7rgXvP3sUtKFju7p3PosjNkRDuqqSFfxTjjEhgx6ejVZ", extprivkey3.Key)

	privkey, err := extPrivkeyApi.GetPrivkey(extprivkey3)
	assert.NoError(t, err)
	assert.Equal(t, "597da1afc4218445ba9428c1c790a30fd21d5c4a932fa580b99dda7ec0887472", privkey.Hex)
	assert.Equal(t, "KzDfmSzt1XqZh5m4sQPBqhpiTGncQ2xvXuWnKGMqR9gVHGSbVJP2", privkey.Wif)

	pubkey, err := extPrivkeyApi.GetPubkey(extprivkey3)
	assert.NoError(t, err)
	assert.Equal(t, "031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1", pubkey.Hex)

	data, err := extPrivkeyApi.GetData(extprivkey2)
	assert.NoError(t, err)
	if err == nil {
		assert.Equal(t, "0488ade4", data.Version)
		assert.Equal(t, "03af54a0", data.Fingerprint)
		assert.Equal(t, "16ddac07d3c3110f0292136af4bc476323e87b6da49ac0b8eef5bcde17e8a672", data.ChainCode)
		assert.Equal(t, (uint32)(1), data.Depth)
		assert.Equal(t, (uint32)(2147483692), data.ChildNumber)
		assert.Equal(t, types.ExtPrivkeyType, data.KeyType)
		assert.Equal(t, network, data.Network)
	}

	/*
		extkey, err := CfdGoCreateExtkey(int(KCfdNetworkMainnet), int(KCfdExtPrivkey), "03af54a0", "a0467585c122e8c2c59d2a10dbe073533cbe887758b05c23f281c9bf873998f6", "16ddac07d3c3110f0292136af4bc476323e87b6da49ac0b8eef5bcde17e8a672", byte(1), uint32(2147483692))
		assert.NoError(t, err)
		assert.Equal(t, "xprv9tviYANkXM1CY831VtMFKFn6LP6aMHf1kvtCZyTL9YbyMwTR2BSmJaEoqw59BZdQhLSx9ZxyKsRUeCetxA2xZ34eupBqZUsifnWyLJJ16j3", extkey)
	*/

	/*
		// xprv9xhdg2NYoNDWJ2EaCaAafhgm7BenUsEjqM4PrG5wuPvTM7jvo1bL5dXwj8TCwiB1A52bKk5N78xQ3hFVBTYxRxLfEm2po5RyQNaFy2kPXZ4/0h/0h/2
		extkey, err = CfdGoCreateExtkeyFromParent(int(KCfdNetworkMainnet), int(KCfdExtPubkey), "03459e03adb3c86131f9d9d35b299cd2c45638bb77c3fa8d1da16b2b5a16a71067", "031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1", "a3d58c40ac9c588529edb6cf9576241a6c2c919843bd97c3c26b35538d91a292", byte(4), uint32(2))
		assert.NoError(t, err)
		assert.Equal(t, "xpub6EXtjFtcPwmae296sZGckBgbfCHnodfjWujbGK7hhzRybmWJhmgeusFbiiZyG1iSeiBcQ7diPeUC9vtP9wLS44bWpqH4kuQQD5N4gA3LaFE", extkey)
	*/
}
