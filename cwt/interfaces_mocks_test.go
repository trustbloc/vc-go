// Code generated by MockGen. DO NOT EDIT.
// Source: interfaces.go

// Package cwt_test is a generated GoMock package.
package cwt_test

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	checker "github.com/trustbloc/vc-go/proof/checker"
	go_cose "github.com/veraison/go-cose"
)

// MockProofChecker is a mock of ProofChecker interface.
type MockProofChecker struct {
	ctrl     *gomock.Controller
	recorder *MockProofCheckerMockRecorder
}

// MockProofCheckerMockRecorder is the mock recorder for MockProofChecker.
type MockProofCheckerMockRecorder struct {
	mock *MockProofChecker
}

// NewMockProofChecker creates a new mock instance.
func NewMockProofChecker(ctrl *gomock.Controller) *MockProofChecker {
	mock := &MockProofChecker{ctrl: ctrl}
	mock.recorder = &MockProofCheckerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockProofChecker) EXPECT() *MockProofCheckerMockRecorder {
	return m.recorder
}

// CheckCWTProof mocks base method.
func (m *MockProofChecker) CheckCWTProof(checkCWTRequest checker.CheckCWTProofRequest, msg *go_cose.Sign1Message, expectedProofIssuer string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CheckCWTProof", checkCWTRequest, msg, expectedProofIssuer)
	ret0, _ := ret[0].(error)
	return ret0
}

// CheckCWTProof indicates an expected call of CheckCWTProof.
func (mr *MockProofCheckerMockRecorder) CheckCWTProof(checkCWTRequest, msg, expectedProofIssuer interface{}) *ProofCheckerCheckCWTProofCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CheckCWTProof", reflect.TypeOf((*MockProofChecker)(nil).CheckCWTProof), checkCWTRequest, msg, expectedProofIssuer)
	return &ProofCheckerCheckCWTProofCall{Call: call}
}

// ProofCheckerCheckCWTProofCall wrap *gomock.Call
type ProofCheckerCheckCWTProofCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *ProofCheckerCheckCWTProofCall) Return(arg0 error) *ProofCheckerCheckCWTProofCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *ProofCheckerCheckCWTProofCall) Do(f func(checker.CheckCWTProofRequest, *go_cose.Sign1Message, string) error) *ProofCheckerCheckCWTProofCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *ProofCheckerCheckCWTProofCall) DoAndReturn(f func(checker.CheckCWTProofRequest, *go_cose.Sign1Message, string) error) *ProofCheckerCheckCWTProofCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}
