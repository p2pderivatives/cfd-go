package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncryptDecryptAES(t *testing.T) {
	cryptoApi := NewCryptoApi()

	target_data := "74657374207465737420746573742074657374"
	exp_aes := "752fe203af4a4d427997e5d2c8b246530e0546b66d2982a49e333e77295dccea"
	output, err := cryptoApi.EncryptAES(
		"616975656F616975656F616975656F616975656F616975656F616975656F6169",
		"",
		target_data)
	assert.NoError(t, err)
	assert.Equal(t, exp_aes, output)

	output, err = cryptoApi.DecryptAES(
		"616975656F616975656F616975656F616975656F616975656F616975656F6169",
		"",
		exp_aes)
	assert.NoError(t, err)
	assert.Equal(t, "7465737420746573742074657374207465737400000000000000000000000000", output)
}

func TestEncryptDecryptAESCBC(t *testing.T) {
	cryptoApi := NewCryptoApi()

	target_data := "74657374207465737420746573742074657374"
	exp_aes := "2ef199bb7d160f94fc17fa5f01b220c630d6b19a5973f4b313868c921fc10d22"

	output, err := cryptoApi.EncryptAES(
		"616975656F616975656F616975656F616975656F616975656F616975656F6169",
		"33343536373839303132333435363738",
		target_data)
	assert.NoError(t, err)
	assert.Equal(t, exp_aes, output)

	output, err = cryptoApi.DecryptAES(
		"616975656F616975656F616975656F616975656F616975656F616975656F6169",
		"33343536373839303132333435363738",
		exp_aes)
	assert.NoError(t, err)
	assert.Equal(t, target_data, output)
}

func TestEncodeDecodeBase64(t *testing.T) {
	cryptoApi := NewCryptoApi()

	target_data := "54686520717569636b2062726f776e20666f78206a756d7073206f766572203133206c617a7920646f67732e"
	exp := "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIDEzIGxhenkgZG9ncy4="

	output, err := cryptoApi.EncodeBase64(target_data)
	assert.NoError(t, err)
	assert.Equal(t, exp, output)

	output, err = cryptoApi.DecodeBase64(exp)
	assert.NoError(t, err)
	assert.Equal(t, target_data, output)
}

func TestEncodeDecodeBase58(t *testing.T) {
	cryptoApi := NewCryptoApi()

	target_data := "0488b21e051431616f00000000e6ba4088246b104837c62bd01fd8ba1cf2931ad1a5376c2360a1f112f2cfc63c02acf89ab4e3daa79bceef2ebecee2af92712e6bf5e4b0d10c74bbecc27ac13da8"
	exp := "9XpNiCWvYUYz78YLbbNYoBMUef5GNJooCQ9i2nf9AH95Njpp4AbuEcmL5iVAwxa6LdR6FyRPeGFEmkFDr3KPGww6peFFtqtabW75Ush4TR"

	output, err := cryptoApi.EncodeBase58(target_data, false)
	assert.NoError(t, err)
	assert.Equal(t, exp, output)

	output, err = cryptoApi.DecodeBase58(exp, false)
	assert.NoError(t, err)
	assert.Equal(t, target_data, output)
}

func TestEncodeDecodeBase58Check(t *testing.T) {
	cryptoApi := NewCryptoApi()

	target_data := "0488b21e051431616f00000000e6ba4088246b104837c62bd01fd8ba1cf2931ad1a5376c2360a1f112f2cfc63c02acf89ab4e3daa79bceef2ebecee2af92712e6bf5e4b0d10c74bbecc27ac13da8"
	exp := "xpub6FZeZ5vwcYiT6r7ZYKJhyUqBxMBvzSmb6SpPQCsSenGPrVjKk5SGW4JJpc7cKERN8w9KnJZcMgJA4B2cHnpGq5TahYrDvZSBY2EMLKPRMTT"

	output, err := cryptoApi.EncodeBase58(target_data, true)
	assert.NoError(t, err)
	assert.Equal(t, exp, output)

	output, err = cryptoApi.DecodeBase58(exp, true)
	assert.NoError(t, err)
	assert.Equal(t, target_data, output)
}

func TestHashMessageByHex(t *testing.T) {
	cryptoApi := NewCryptoApi()

	messageHex := "001412012222880A"

	output, err := cryptoApi.Ripemd160(messageHex, false)
	assert.NoError(t, err)
	assert.Equal(t, "5f4e6799b6d87fbf4cee7820b8a168b13225dbc8", output)

	output, err = cryptoApi.Sha256(messageHex, false)
	assert.NoError(t, err)
	assert.Equal(t, "7c90e7f25d3c26b098d43ae18cfc67e2d6c200f8acf8b16737c3ec6143e8ba8b", output)

	output, err = cryptoApi.Hash160(messageHex, false)
	assert.NoError(t, err)
	assert.Equal(t, "1097f123808affe262cc5b7cb6acfa84a7a61bb6", output)

	output, err = cryptoApi.Hash256(messageHex, false)
	assert.NoError(t, err)
	assert.Equal(t, "c6a3953d698f9ed23812c40bcf7aba724d66fbd9f771ffed8f5d6d2b4b267bcf", output)
}

func TestHashMessageByText(t *testing.T) {
	cryptoApi := NewCryptoApi()

	message := "The quick brown fox jumps over the lazy dog"

	output, err := cryptoApi.Ripemd160(message, true)
	assert.NoError(t, err)
	assert.Equal(t, "37f332f68db77bd9d7edd4969571ad671cf9dd3b", output)

	output, err = cryptoApi.Sha256(message, true)
	assert.NoError(t, err)
	assert.Equal(t, "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592", output)

	output, err = cryptoApi.Hash160(message, true)
	assert.NoError(t, err)
	assert.Equal(t, "0e3397b4abc7a382b3ea2365883c3c7ca5f07600", output)

	output, err = cryptoApi.Hash256(message, true)
	assert.NoError(t, err)
	assert.Equal(t, "6d37795021e544d82b41850edf7aabab9a0ebe274e54a519840c4666f35b3937", output)
}
