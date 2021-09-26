// Code generated by MockGen. DO NOT EDIT.
// Source: confidential_address.go

// Package mock is a generated GoMock package.
package mock

import (
	reflect "reflect"

	types "github.com/p2pderivatives/cfd-go/types"
	gomock "github.com/golang/mock/gomock"
)

// MockConfidentialAddressApi is a mock of ConfidentialAddressApi interface.
type MockConfidentialAddressApi struct {
	ctrl     *gomock.Controller
	recorder *MockConfidentialAddressApiMockRecorder
}

// MockConfidentialAddressApiMockRecorder is the mock recorder for MockConfidentialAddressApi.
type MockConfidentialAddressApiMockRecorder struct {
	mock *MockConfidentialAddressApi
}

// NewMockConfidentialAddressApi creates a new mock instance.
func NewMockConfidentialAddressApi(ctrl *gomock.Controller) *MockConfidentialAddressApi {
	mock := &MockConfidentialAddressApi{ctrl: ctrl}
	mock.recorder = &MockConfidentialAddressApiMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockConfidentialAddressApi) EXPECT() *MockConfidentialAddressApiMockRecorder {
	return m.recorder
}

// Create mocks base method.
func (m *MockConfidentialAddressApi) Create(addressString string, confidentialKey *types.Pubkey) (*types.ConfidentialAddress, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", addressString, confidentialKey)
	ret0, _ := ret[0].(*types.ConfidentialAddress)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Create indicates an expected call of Create.
func (mr *MockConfidentialAddressApiMockRecorder) Create(addressString, confidentialKey interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockConfidentialAddressApi)(nil).Create), addressString, confidentialKey)
}

// Parse mocks base method.
func (m *MockConfidentialAddressApi) Parse(addressString string) (*types.ConfidentialAddress, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Parse", addressString)
	ret0, _ := ret[0].(*types.ConfidentialAddress)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Parse indicates an expected call of Parse.
func (mr *MockConfidentialAddressApiMockRecorder) Parse(addressString interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Parse", reflect.TypeOf((*MockConfidentialAddressApi)(nil).Parse), addressString)
}
