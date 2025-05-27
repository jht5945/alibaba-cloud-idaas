package external

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"github.com/aliyunidaas/alibaba-cloud-idaas/signer"
	"github.com/pkg/errors"
	"io"
	"os"
	"os/exec"
)

type ErrorResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
}

type SignResponse struct {
	Success         bool   `json:"success"`
	SignatureBase64 string `json:"signature_base64"`
}

type PublicKeyResponse struct {
	Success         bool   `json:"success"`
	PublicKeyBase64 string `json:"public_key_base64"`
}

type ExCommandSigner struct {
	command   string
	parameter string
}

func NewExCommandSigner(command string, parameter string) (*ExCommandSigner, error) {
	if command == "" {
		return nil, errors.New("external signer command is empty")
	}
	if parameter == "" {
		return nil, errors.New("external signer parameter is empty")
	}
	return &ExCommandSigner{
		command:   command,
		parameter: parameter,
	}, nil
}

func (ex *ExCommandSigner) Public() (publicKey *crypto.PublicKey, err error) {
	return internalGetPublicKey(ex.command, ex.parameter)
}

func (ex *ExCommandSigner) Sign(rand io.Reader, alg signer.JwtSignAlgorithm, message []byte) (signature []byte, err error) {
	algStr := alg.ToString()
	if algStr == "" {
		return nil, errors.New("invalid algorithm")
	}
	return internalSign(ex.command, ex.parameter, algStr, message)
}

func internalGetPublicKey(command, parameter string) (*crypto.PublicKey, error) {
	cmd := exec.Command(command,
		"external_public_key",
		"--parameter", parameter)
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	err := cmd.Run()
	if err != nil {
		return nil, errors.Wrap(err, "error in external_public_key exec")
	}

	var externalPublicKeyResponse PublicKeyResponse
	err = json.Unmarshal(stdout.Bytes(), &externalPublicKeyResponse)
	if err != nil {
		return nil, errors.Wrapf(err, "error in external_public_key unmarshal: %s", string(stdout.Bytes()))
	}
	if !externalPublicKeyResponse.Success {
		var externalErrorResponse ErrorResponse
		err = json.Unmarshal(stdout.Bytes(), &externalErrorResponse)
		if err != nil {
			return nil, errors.Wrapf(err, "error in external_public_key unmarshal: %s", stdout.Bytes())
		}
		return nil, errors.New(externalErrorResponse.Error)
	}
	publicKeyDer, err := base64.StdEncoding.DecodeString(externalPublicKeyResponse.PublicKeyBase64)
	if err != nil {
		return nil, errors.Wrapf(err, "error in base64 decode: %s", externalPublicKeyResponse.PublicKeyBase64)
	}
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyDer)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse public key")
	}
	return (*crypto.PublicKey)(&publicKey), nil
}

func internalSign(command, parameter, alg string, message []byte) ([]byte, error) {
	cmd := exec.Command(command,
		"external_sign",
		"--alg", alg,
		"--parameter", parameter,
		"--message-base64", base64.StdEncoding.EncodeToString(message))
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	err := cmd.Run()
	if err != nil {
		return nil, errors.Wrap(err, "error in external_sign exec")
	}
	var externalSignResponse SignResponse
	err = json.Unmarshal(stdout.Bytes(), &externalSignResponse)
	if err != nil {
		return nil, errors.Wrapf(err, "error in external_sign unmarshal: %s", string(stdout.Bytes()))
	}
	if !externalSignResponse.Success {
		var externalErrorResponse ErrorResponse
		err = json.Unmarshal(stdout.Bytes(), &externalErrorResponse)
		if err != nil {
			return nil, errors.Wrapf(err, "error in external_sign unmarshal: %s", string(stdout.Bytes()))
		}
		return nil, errors.New(externalErrorResponse.Error)
	}
	signature, err := base64.StdEncoding.DecodeString(externalSignResponse.SignatureBase64)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to decode signature: %s", externalSignResponse.SignatureBase64)
	}
	return signature, nil
}
