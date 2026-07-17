package xssh_test

import (
	_ "embed"
	"errors"
	"testing"
	"time"

	"github.com/fionn/commit-signature-verifier/internal/xssh"
)

//go:embed test_data/message.txt
var message []byte

//go:embed test_data/signature.txt
var signature []byte

func must[T any](x T, err error) T {
	if err != nil {
		panic(err)
	}
	return x
}

// TestSSHSignature is a table-driven test that asserts that commit signature
// verification passes or fails as expected for a variets of commits and
// signatures.
func TestSSHSignature(t *testing.T) {
	timestamp := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	namespace := "git"
	identity := "git@fionn.computer"
	allowedSigner, err := xssh.ParseAllowedSigner(`git@fionn.computer namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILbkp0LwqqV/w6wAGV9bwiR6FpHC/5DtiBAKFLZxvaSp fionn@lotus`)
	allowedSigners := []xssh.AllowedSigner{*allowedSigner}
	if err != nil {
		t.Fatalf("failed to parse test allowed signers: %s", err)
	}

	tests := []struct {
		name           string
		message        []byte
		signature      []byte
		identity       string
		allowedSigners []xssh.AllowedSigner
		namespace      string
		timestamp      time.Time
		err            error
	}{
		{
			name:           "GoodSignature",
			message:        message,
			signature:      signature,
			identity:       identity,
			allowedSigners: allowedSigners,
			namespace:      namespace,
			timestamp:      timestamp,
		},
		{
			name:           "BadSignature",
			message:        message,
			signature:      []byte("yolo"),
			identity:       identity,
			allowedSigners: allowedSigners,
			namespace:      namespace,
			timestamp:      timestamp,
			err:            errors.New("some error"),
		},
		{
			name:           "BadMessage",
			message:        []byte("yolo"),
			signature:      signature,
			identity:       identity,
			allowedSigners: allowedSigners,
			namespace:      namespace,
			timestamp:      timestamp,
			err:            errors.New("some error"),
		},
		{
			name:           "GoodSignatureMismatchedNamespaceExplicit",
			message:        message,
			signature:      signature,
			identity:       identity,
			allowedSigners: allowedSigners,
			namespace:      "file",
			timestamp:      timestamp,
			err:            errors.New("some error"),
		},
		{
			name:           "GoodSignatureMismatchedNamespaceAllowed",
			message:        message,
			signature:      signature,
			identity:       identity,
			allowedSigners: []xssh.AllowedSigner{*must(xssh.ParseAllowedSigner(`git@fionn.computer namespaces="file" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILbkp0LwqqV/w6wAGV9bwiR6FpHC/5DtiBAKFLZxvaSp fionn@lotus`))},
			namespace:      namespace,
			timestamp:      timestamp,
			err:            errors.New("some error"),
		},
		{
			name:           "GoodSignatureMismatchedNamespaceExplicitAndAllowed",
			message:        message,
			signature:      signature,
			identity:       identity,
			allowedSigners: []xssh.AllowedSigner{*must(xssh.ParseAllowedSigner(`git@fionn.computer namespaces="file" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILbkp0LwqqV/w6wAGV9bwiR6FpHC/5DtiBAKFLZxvaSp fionn@lotus`))},
			namespace:      "file",
			timestamp:      timestamp,
			err:            errors.New("some error"),
		},
		{
			name:           "GlobPrincipal",
			message:        message,
			signature:      signature,
			identity:       identity,
			allowedSigners: []xssh.AllowedSigner{*must(xssh.ParseAllowedSigner(`*@fionn.computer namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILbkp0LwqqV/w6wAGV9bwiR6FpHC/5DtiBAKFLZxvaSp fionn@lotus`))},
			namespace:      namespace,
			timestamp:      timestamp,
		},
		{
			name:           "NegatedPrincipal",
			message:        message,
			signature:      signature,
			identity:       identity,
			allowedSigners: []xssh.AllowedSigner{*must(xssh.ParseAllowedSigner(`!git@fionn.computer namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILbkp0LwqqV/w6wAGV9bwiR6FpHC/5DtiBAKFLZxvaSp fionn@lotus`))},
			namespace:      namespace,
			timestamp:      timestamp,
			err:            errors.New("some error"),
		},
		{
			name:           "NegatedGlob",
			message:        message,
			signature:      signature,
			identity:       identity,
			allowedSigners: []xssh.AllowedSigner{*must(xssh.ParseAllowedSigner(`!*@fionn.computer namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILbkp0LwqqV/w6wAGV9bwiR6FpHC/5DtiBAKFLZxvaSp fionn@lotus`))},
			namespace:      namespace,
			timestamp:      timestamp,
			err:            errors.New("some error"),
		},
		{
			name:           "NegatedPrincipals",
			message:        message,
			signature:      signature,
			identity:       identity,
			allowedSigners: []xssh.AllowedSigner{*must(xssh.ParseAllowedSigner(`!hg@fionn.computer,git@fionn.computer namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILbkp0LwqqV/w6wAGV9bwiR6FpHC/5DtiBAKFLZxvaSp fionn@lotus`))},
			namespace:      namespace,
			timestamp:      timestamp,
		},
		{
			name:           "NegatedPrincipalWithWildcardAllow",
			message:        message,
			signature:      signature,
			identity:       identity,
			allowedSigners: []xssh.AllowedSigner{*must(xssh.ParseAllowedSigner(`!git@fionn.computer,* namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILbkp0LwqqV/w6wAGV9bwiR6FpHC/5DtiBAKFLZxvaSp fionn@lotus`))},
			namespace:      namespace,
			timestamp:      timestamp,
			err:            errors.New("some error"),
		},
		{
			name:           "WildcardAllowWithNegatedPrincipal",
			message:        message,
			signature:      signature,
			identity:       identity,
			allowedSigners: []xssh.AllowedSigner{*must(xssh.ParseAllowedSigner(`*,!git@fionn.computer namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILbkp0LwqqV/w6wAGV9bwiR6FpHC/5DtiBAKFLZxvaSp fionn@lotus`))},
			namespace:      namespace,
			timestamp:      timestamp,
			err:            errors.New("some error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := xssh.Verify(tt.message, tt.signature, tt.identity, tt.allowedSigners, tt.namespace, tt.timestamp)
			// For now at least, we don't care what error, only that we get an
			// error if expected or nil if unexpected.
			if (err != nil && tt.err == nil) || (err == nil && tt.err != nil) {
				t.Errorf("Got error %s, expected %s", err, tt.err)
			}
		})
	}
}
