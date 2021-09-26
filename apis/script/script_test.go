package script

import (
	"testing"

	"github.com/cryptogarageinc/cfd-go/types"
	"github.com/stretchr/testify/assert"
)

func TestCreateFromAsm(t *testing.T) {
	scriptApi := NewScriptApi()
	scriptCheckSig, err := scriptApi.CreateFromAsmStrings([]string{
		"ac52f50b28cdd4d3bcb7f0d5cb533f232e4c4ef12fbf3e718420b84d4e3c3440",
		"OP_CHECKSIG",
	})
	assert.NoError(t, err)
	assert.Equal(t, "20ac52f50b28cdd4d3bcb7f0d5cb533f232e4c4ef12fbf3e718420b84d4e3c3440ac", scriptCheckSig.ToHex())
}

func TestParseScript(t *testing.T) {
	scriptApi := NewScriptApi()

	scriptSig := types.NewScriptFromHexIgnoreError("00473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb0147522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52ae")
	items, err := scriptApi.Parse(scriptSig)
	assert.NoError(t, err)
	assert.Equal(t, int(4), len(items))
	if len(items) == int(4) {
		assert.Equal(t, "OP_0", items[0])
		assert.Equal(t, "3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01", items[1])
		assert.Equal(t, "3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01", items[2])
		assert.Equal(t, "522102bfd7daa5d113fcbd8c2f374ae58cbb89cbed9570e898f1af5ff989457e2d4d712102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad52ae", items[3])
	}
}

func TestParseMultisig(t *testing.T) {
	scriptApi := NewScriptApi()
	script := types.NewScriptFromHexIgnoreError("52210205ffcdde75f262d66ada3dd877c7471f8f8ee9ee24d917c3e18d01cee458bafe2102be61f4350b4ae7544f99649a917f48ba16cf48c983ac1599774958d88ad17ec552ae")

	pubkeys, reqSigNum, err := scriptApi.ParseMultisig(script)
	assert.NoError(t, err)
	assert.Equal(t, uint32(2), reqSigNum)
	assert.Equal(t, 2, len(pubkeys))
	assert.Equal(t, "0205ffcdde75f262d66ada3dd877c7471f8f8ee9ee24d917c3e18d01cee458bafe", pubkeys[0].Hex)
	assert.Equal(t, "02be61f4350b4ae7544f99649a917f48ba16cf48c983ac1599774958d88ad17ec5", pubkeys[1].Hex)
}

func TestCreateMultisig(t *testing.T) {
	scriptApi := NewScriptApi()
	pubkeys := []types.Pubkey{
		{Hex: "0205ffcdde75f262d66ada3dd877c7471f8f8ee9ee24d917c3e18d01cee458bafe"},
		{Hex: "02be61f4350b4ae7544f99649a917f48ba16cf48c983ac1599774958d88ad17ec5"},
	}

	script, err := scriptApi.CreateMultisig(pubkeys, 2)
	assert.NoError(t, err)
	assert.Equal(t, "52210205ffcdde75f262d66ada3dd877c7471f8f8ee9ee24d917c3e18d01cee458bafe2102be61f4350b4ae7544f99649a917f48ba16cf48c983ac1599774958d88ad17ec552ae", script.ToHex())
}
