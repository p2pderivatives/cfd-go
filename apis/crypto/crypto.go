package crypto

import (
	cfdgo "github.com/cryptogarageinc/cfd-go"
)

// go generate comment
//go:generate -command mkdir mock
//go:generate mockgen -source crypto.go -destination mock/crypto.go -package mock
//go:generate goimports -w mock/crypto.go

// -------------------------------------
// API struct
// -------------------------------------

const (
	MaxMultisigPubkeyNum     = 20
	MaxP2shMultisigPubkeyNum = 16
)

type CryptoApi interface {
	EncryptAES(key, cbcIv, buffer string) (output string, err error)
	DecryptAES(key, cbcIv, buffer string) (output string, err error)
	EncodeBase64(buffer string) (output string, err error)
	DecodeBase64(base64 string) (output string, err error)
	EncodeBase58(buffer string, useChecksum bool) (output string, err error)
	DecodeBase58(base58 string, useChecksum bool) (output string, err error)
	Ripemd160(message string, hasText bool) (output string, err error)
	Sha256(message string, hasText bool) (output string, err error)
	Hash160(message string, hasText bool) (output string, err error)
	Hash256(message string, hasText bool) (output string, err error)
}

// NewScriptApi returns an object that defines the API for Script
func NewCryptoApi() *CryptoApiImpl {
	api := CryptoApiImpl{}
	return &api
}

// -------------------------------------
// CryptoApiImpl
// -------------------------------------

type CryptoApiImpl struct{}

func (s *CryptoApiImpl) EncryptAES(key, cbcIv, buffer string) (output string, err error) {
	return cfdgo.CfdGoEncryptAES(key, cbcIv, buffer)
}

func (s *CryptoApiImpl) DecryptAES(key, cbcIv, buffer string) (output string, err error) {
	return cfdgo.CfdGoDecryptAES(key, cbcIv, buffer)
}

func (s *CryptoApiImpl) EncodeBase64(buffer string) (output string, err error) {
	return cfdgo.CfdGoEncodeBase64(buffer)
}

func (s *CryptoApiImpl) DecodeBase64(base64 string) (output string, err error) {
	return cfdgo.CfdGoDecodeBase64(base64)
}

func (s *CryptoApiImpl) EncodeBase58(buffer string, useChecksum bool) (output string, err error) {
	return cfdgo.CfdGoEncodeBase58(buffer, useChecksum)
}

func (s *CryptoApiImpl) DecodeBase58(base58 string, useChecksum bool) (output string, err error) {
	return cfdgo.CfdGoDecodeBase58(base58, useChecksum)
}

func (s *CryptoApiImpl) Ripemd160(message string, hasText bool) (output string, err error) {
	return cfdgo.CfdGoRipemd160(message, hasText)
}

func (s *CryptoApiImpl) Sha256(message string, hasText bool) (output string, err error) {
	return cfdgo.CfdGoSha256(message, hasText)
}

func (s *CryptoApiImpl) Hash160(message string, hasText bool) (output string, err error) {
	return cfdgo.CfdGoHash160(message, hasText)
}

func (s *CryptoApiImpl) Hash256(message string, hasText bool) (output string, err error) {
	return cfdgo.CfdGoHash256(message, hasText)
}
