package script

import (
	"strconv"
	"strings"

	cfdgo "github.com/cryptogarageinc/cfd-go"
	"github.com/cryptogarageinc/cfd-go/apis/key"
	cfdErrors "github.com/cryptogarageinc/cfd-go/errors"
	"github.com/cryptogarageinc/cfd-go/types"

	"github.com/pkg/errors"
)

// go generate comment
//go:generate -command mkdir mock
//go:generate mockgen -source script.go -destination mock/script.go -package mock
//go:generate goimports -w mock/script.go

// -------------------------------------
// API struct
// -------------------------------------

const (
	MaxMultisigPubkeyNum     = 20
	MaxP2shMultisigPubkeyNum = 16
)

type ScriptApi interface {
	CreateFromAsm(asm string) (script *types.Script, err error)
	CreateFromAsmStrings(asmStrings []string) (script *types.Script, err error)
	Parse(script *types.Script) (asmStrings []string, err error)
	ParseMultisig(script *types.Script) (pubkey []types.Pubkey, requireSigNum uint32, err error)
	CreateMultisig(pubkeys []types.Pubkey, requireSigNum uint32) (script *types.Script, err error)
}

// TODO(k-matsuzawa): Implement APIs for the following functions in the future.
// create tapscript
// parse tapscript

// NewScriptApi returns an object that defines the API for Script
func NewScriptApi() *ScriptApiImpl {
	api := ScriptApiImpl{}
	api.pubkeyApi = key.NewPubkeyApi()
	return &api
}

// -------------------------------------
// ScriptApiImpl
// -------------------------------------

type ScriptApiImpl struct {
	cfdErrors.HasInitializeError
	pubkeyApi key.PubkeyApi
}

// WithPubkeyApi This function set a pubkey api.
func (p *ScriptApiImpl) WithPubkeyApi(pubkeyApi key.PubkeyApi) *ScriptApiImpl {
	if pubkeyApi == nil {
		p.SetError(cfdErrors.ErrParameterNil)
	} else {
		p.pubkeyApi = pubkeyApi
	}
	return p
}

func (s *ScriptApiImpl) CreateFromAsm(asm string) (script *types.Script, err error) {
	if s == nil {
		return nil, errors.New(cfdErrors.InternalError.Error())
	}
	hex, err := cfdgo.CfdGoConvertScriptAsmToHex(asm)
	if err != nil {
		return nil, err
	}
	scriptObj, err := types.NewScriptFromHex(hex)
	if err != nil {
		return nil, err
	}
	script = &scriptObj
	return script, nil
}

func (s *ScriptApiImpl) CreateFromAsmStrings(asmStrings []string) (script *types.Script, err error) {
	if len(asmStrings) == 0 {
		return nil, cfdErrors.ErrParameterNil
	}
	asm := strings.Join(asmStrings, " ")
	return s.CreateFromAsm(asm)
}

func (s *ScriptApiImpl) Parse(script *types.Script) (asmStrings []string, err error) {
	if s == nil {
		return nil, errors.New(cfdErrors.InternalError.Error())
	} else if script == nil {
		return nil, cfdErrors.ErrParameterNil
	}
	asmStrings, err = cfdgo.CfdGoParseScript(script.ToHex())
	if err != nil {
		return nil, errors.Wrap(err, "Failed to parse script")
	}
	return asmStrings, nil
}

func (s *ScriptApiImpl) ParseMultisig(script *types.Script) (pubkeys []types.Pubkey, requireSigNum uint32, err error) {
	if s == nil {
		return nil, 0, errors.New(cfdErrors.InternalError.Error())
	} else if script == nil {
		return nil, 0, cfdErrors.ErrParameterNil
	}
	scriptItems, err := cfdgo.CfdGoParseScript(script.ToHex())
	if err != nil {
		return nil, 0, err
	}
	switch {
	case len(scriptItems) < 3:
		return nil, 0, cfdErrors.ErrMultisigScript
	}

	reqSigNum := 0
	totalNum := 0
	pubkeys = make([]types.Pubkey, 0, len(scriptItems)-2)
	for i, item := range scriptItems {
		switch i {
		case 0, len(scriptItems) - 2:
			numStr := ""
			nums := strings.Split(item, "OP_")
			if len(nums) == 2 {
				numStr = nums[1]
			} else {
				numStr = nums[0]
			}
			num, err := strconv.Atoi(numStr)
			if err != nil {
				return nil, 0, errors.Wrap(err, cfdErrors.ErrMultisigScript.Error())
			}
			if i == 0 {
				reqSigNum = num
			} else {
				totalNum = num
			}
		case len(scriptItems) - 1:
			if item != "OP_CHECKMULTISIG" {
				return nil, 0, errors.New(cfdErrors.ErrMultisigScript.Error())
			}
		default:
			pk := types.Pubkey{Hex: item}
			err := s.pubkeyApi.Verify(&pk)
			if err != nil {
				return nil, 0, errors.Wrap(err, cfdErrors.ErrMultisigScript.Error())
			}
			pubkeys = append(pubkeys, pk)
		}
	}

	switch {
	case reqSigNum == 0:
		return nil, 0, errors.New(cfdErrors.ErrMultisigScript.Error())
	case reqSigNum < totalNum:
		return nil, 0, errors.New(cfdErrors.ErrMultisigScript.Error())
	case totalNum != len(pubkeys):
		return nil, 0, errors.New(cfdErrors.ErrMultisigScript.Error())
	case totalNum > MaxMultisigPubkeyNum:
		return nil, 0, errors.New(cfdErrors.ErrMultisigScript.Error())
	}
	if totalNum > MaxP2shMultisigPubkeyNum {
		for _, pubkey := range pubkeys {
			if err := s.pubkeyApi.IsCompressed(&pubkey); err != nil {
				return nil, 0, errors.Wrap(err, cfdErrors.ErrMultisigScript.Error())
			}
		}
	}
	requireSigNum = uint32(reqSigNum)
	return pubkeys, requireSigNum, nil
}

func (s *ScriptApiImpl) CreateMultisig(pubkeys []types.Pubkey, requireSigNum uint32) (script *types.Script, err error) {
	if s == nil {
		return nil, errors.New(cfdErrors.InternalError.Error())
	} else if len(pubkeys) == 0 {
		return nil, cfdErrors.ErrParameterNil
	} else if requireSigNum == 0 {
		return nil, cfdErrors.ErrParameterNil
	}
	pks := make([]string, len(pubkeys))
	for i, pk := range pubkeys {
		pks[i] = pk.Hex
	}
	_, scriptHex, _, err := cfdgo.CfdGoCreateMultisigScript(types.Mainnet.ToCfdValue(), types.P2sh.ToCfdValue(), pks, requireSigNum)
	if err != nil {
		return nil, err
	}
	scriptObj, err := types.NewScriptFromHex(scriptHex)
	if err != nil {
		return nil, err
	}
	script = &scriptObj
	return script, nil
}
