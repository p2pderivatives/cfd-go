// Code generated by MockGen. DO NOT EDIT.
// Source: transaction.go

// Package mock is a generated GoMock package.
package mock

import (
	reflect "reflect"

	types "github.com/p2pderivatives/cfd-go/types"
	gomock "github.com/golang/mock/gomock"
)

// MockTransactionApi is a mock of TransactionApi interface.
type MockTransactionApi struct {
	ctrl     *gomock.Controller
	recorder *MockTransactionApiMockRecorder
}

// MockTransactionApiMockRecorder is the mock recorder for MockTransactionApi.
type MockTransactionApiMockRecorder struct {
	mock *MockTransactionApi
}

// NewMockTransactionApi creates a new mock instance.
func NewMockTransactionApi(ctrl *gomock.Controller) *MockTransactionApi {
	mock := &MockTransactionApi{ctrl: ctrl}
	mock.recorder = &MockTransactionApiMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockTransactionApi) EXPECT() *MockTransactionApiMockRecorder {
	return m.recorder
}

// Add mocks base method.
func (m *MockTransactionApi) Add(tx *types.Transaction, txinList *[]types.InputTxIn, txoutList *[]types.InputTxOut) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Add", tx, txinList, txoutList)
	ret0, _ := ret[0].(error)
	return ret0
}

// Add indicates an expected call of Add.
func (mr *MockTransactionApiMockRecorder) Add(tx, txinList, txoutList interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Add", reflect.TypeOf((*MockTransactionApi)(nil).Add), tx, txinList, txoutList)
}

// AddPubkeySign mocks base method.
func (m *MockTransactionApi) AddPubkeySign(tx *types.Transaction, outpoint *types.OutPoint, hashType types.HashType, pubkey *types.Pubkey, signature string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddPubkeySign", tx, outpoint, hashType, pubkey, signature)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddPubkeySign indicates an expected call of AddPubkeySign.
func (mr *MockTransactionApiMockRecorder) AddPubkeySign(tx, outpoint, hashType, pubkey, signature interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddPubkeySign", reflect.TypeOf((*MockTransactionApi)(nil).AddPubkeySign), tx, outpoint, hashType, pubkey, signature)
}

// AddPubkeySignByDescriptor mocks base method.
func (m *MockTransactionApi) AddPubkeySignByDescriptor(tx *types.Transaction, outpoint *types.OutPoint, outputDescriptor *types.Descriptor, signature string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AddPubkeySignByDescriptor", tx, outpoint, outputDescriptor, signature)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddPubkeySignByDescriptor indicates an expected call of AddPubkeySignByDescriptor.
func (mr *MockTransactionApiMockRecorder) AddPubkeySignByDescriptor(tx, outpoint, outputDescriptor, signature interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddPubkeySignByDescriptor", reflect.TypeOf((*MockTransactionApi)(nil).AddPubkeySignByDescriptor), tx, outpoint, outputDescriptor, signature)
}

// Create mocks base method.
func (m *MockTransactionApi) Create(version, locktime uint32, txinList *[]types.InputTxIn, txoutList *[]types.InputTxOut) (*types.Transaction, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", version, locktime, txinList, txoutList)
	ret0, _ := ret[0].(*types.Transaction)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Create indicates an expected call of Create.
func (mr *MockTransactionApiMockRecorder) Create(version, locktime, txinList, txoutList interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockTransactionApi)(nil).Create), version, locktime, txinList, txoutList)
}

// GetTxOut mocks base method.
func (m *MockTransactionApi) GetTxOut(tx *types.Transaction, vout uint32) (*types.TxOut, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTxOut", tx, vout)
	ret0, _ := ret[0].(*types.TxOut)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetTxOut indicates an expected call of GetTxOut.
func (mr *MockTransactionApiMockRecorder) GetTxOut(tx, vout interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTxOut", reflect.TypeOf((*MockTransactionApi)(nil).GetTxOut), tx, vout)
}

// GetTxid mocks base method.
func (m *MockTransactionApi) GetTxid(tx *types.Transaction) string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTxid", tx)
	ret0, _ := ret[0].(string)
	return ret0
}

// GetTxid indicates an expected call of GetTxid.
func (mr *MockTransactionApiMockRecorder) GetTxid(tx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTxid", reflect.TypeOf((*MockTransactionApi)(nil).GetTxid), tx)
}

// SignWithPrivkey mocks base method.
func (m *MockTransactionApi) SignWithPrivkey(tx *types.Transaction, outpoint *types.OutPoint, privkey *types.Privkey, sighashType types.SigHashType, utxoList *[]types.UtxoData) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SignWithPrivkey", tx, outpoint, privkey, sighashType, utxoList)
	ret0, _ := ret[0].(error)
	return ret0
}

// SignWithPrivkey indicates an expected call of SignWithPrivkey.
func (mr *MockTransactionApiMockRecorder) SignWithPrivkey(tx, outpoint, privkey, sighashType, utxoList interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SignWithPrivkey", reflect.TypeOf((*MockTransactionApi)(nil).SignWithPrivkey), tx, outpoint, privkey, sighashType, utxoList)
}

// VerifySign mocks base method.
func (m *MockTransactionApi) VerifySign(tx *types.Transaction, outpoint *types.OutPoint, amount int64, txinUtxoList *[]types.UtxoData) (bool, string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "VerifySign", tx, outpoint, amount, txinUtxoList)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(string)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// VerifySign indicates an expected call of VerifySign.
func (mr *MockTransactionApiMockRecorder) VerifySign(tx, outpoint, amount, txinUtxoList interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VerifySign", reflect.TypeOf((*MockTransactionApi)(nil).VerifySign), tx, outpoint, amount, txinUtxoList)
}