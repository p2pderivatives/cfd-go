// Code generated by MockGen. DO NOT EDIT.
// Source: block.go

// Package mock is a generated GoMock package.
package mock

import (
	reflect "reflect"

	types "github.com/p2pderivatives/cfd-go/types"
	gomock "github.com/golang/mock/gomock"
)

// MockBlockApi is a mock of BlockApi interface.
type MockBlockApi struct {
	ctrl     *gomock.Controller
	recorder *MockBlockApiMockRecorder
}

// MockBlockApiMockRecorder is the mock recorder for MockBlockApi.
type MockBlockApiMockRecorder struct {
	mock *MockBlockApi
}

// NewMockBlockApi creates a new mock instance.
func NewMockBlockApi(ctrl *gomock.Controller) *MockBlockApi {
	mock := &MockBlockApi{ctrl: ctrl}
	mock.recorder = &MockBlockApiMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockBlockApi) EXPECT() *MockBlockApiMockRecorder {
	return m.recorder
}

// ExistTxid mocks base method.
func (m *MockBlockApi) ExistTxid(block *types.Block, txid string) (bool, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ExistTxid", block, txid)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ExistTxid indicates an expected call of ExistTxid.
func (mr *MockBlockApiMockRecorder) ExistTxid(block, txid interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ExistTxid", reflect.TypeOf((*MockBlockApi)(nil).ExistTxid), block, txid)
}

// GetHeaderData mocks base method.
func (m *MockBlockApi) GetHeaderData(block *types.Block) (string, *types.BlockHeader, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetHeaderData", block)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(*types.BlockHeader)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// GetHeaderData indicates an expected call of GetHeaderData.
func (mr *MockBlockApiMockRecorder) GetHeaderData(block interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetHeaderData", reflect.TypeOf((*MockBlockApi)(nil).GetHeaderData), block)
}

// GetTransactionData mocks base method.
func (m *MockBlockApi) GetTransactionData(block *types.Block, txid string) (*types.Transaction, *types.ByteData, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTransactionData", block, txid)
	ret0, _ := ret[0].(*types.Transaction)
	ret1, _ := ret[1].(*types.ByteData)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// GetTransactionData indicates an expected call of GetTransactionData.
func (mr *MockBlockApiMockRecorder) GetTransactionData(block, txid interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTransactionData", reflect.TypeOf((*MockBlockApi)(nil).GetTransactionData), block, txid)
}

// GetTxCount mocks base method.
func (m *MockBlockApi) GetTxCount(block *types.Block) (uint32, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTxCount", block)
	ret0, _ := ret[0].(uint32)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetTxCount indicates an expected call of GetTxCount.
func (mr *MockBlockApiMockRecorder) GetTxCount(block interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTxCount", reflect.TypeOf((*MockBlockApi)(nil).GetTxCount), block)
}

// GetTxidList mocks base method.
func (m *MockBlockApi) GetTxidList(block *types.Block) ([]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetTxidList", block)
	ret0, _ := ret[0].([]string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetTxidList indicates an expected call of GetTxidList.
func (mr *MockBlockApiMockRecorder) GetTxidList(block interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTxidList", reflect.TypeOf((*MockBlockApi)(nil).GetTxidList), block)
}
