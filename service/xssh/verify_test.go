package xssh_test

import (
	"errors"
	"testing"
	"time"

	"github.com/fionn/commit-signature-verifier/service/xssh"
)

var message = []byte(`tree bfdc48a26bb78e5b4f0798932f4d3460b1f9132e
author Fionn Fitzmaurice <git@fionn.computer> 1757763274 +0800
committer Fionn Fitzmaurice <git@fionn.computer> 1757764182 +0800

initial commit
`)
var signature = []byte(`-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgtuSnQvCqpX/DrAAZX1vCJHoWkc
L/kO2IEAoUtnG9pKkAAAADZ2l0AAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5
AAAAQARrCFIKkhr5LW7pPOhfyLpbQiYWBvo22/B3GB0ZjhPW33Mtv1AWV/ffk70NC9cvN/
lvGzWXH8/iVyL2DKMUDwU=
-----END SSH SIGNATURE-----`)

func must[T any](x T, err error) T {
	if err != nil {
		panic(err)
	}
	return x
}

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
