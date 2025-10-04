package xssh_test

import (
	"errors"
	"slices"
	"testing"
	"time"

	xssh "github.com/fionn/commit-signature-verifier/service/xssh"
)

func TestInput(t *testing.T) {
	tests := []struct {
		name          string
		allowedSigner []byte
		principals    []string
		namespaces    []string
		validBefore   time.Time
		validAfter    time.Time
		comment       string
		err           error
	}{
		{
			name:          "BadAllowedSigner",
			allowedSigner: []byte("yolo"),
			err:           errors.New("some error"),
		},
		{
			name:          "GoodAllowedSigner",
			allowedSigner: []byte(`example@example.com,*@123 namespaces="git,file",valid-before=20470101,valid-after=20010101000000Z ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILbkp0LwqqV/w6wAGV9bwiR6FpHC/5DtiBAKFLZxvaSp some-comment`),
			principals:    []string{"example@example.com", "*@123"},
			namespaces:    []string{"git", "file"},
			validBefore:   time.Date(2047, 1, 1, 0, 0, 0, 0, time.UTC),
			validAfter:    time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC),
			comment:       "some-comment",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowedSigner, err := xssh.ParseAllowedSigner(tt.allowedSigner)
			// For now at least, we don't care what error, only that we get an
			// error if expected or nil if unexpected.
			if (err != nil && tt.err == nil) || (err == nil && tt.err != nil) {
				t.Errorf("Got error %s, expected %s", err, tt.err)
			}
			if err != nil {
				return
			}

			if !slices.Equal(allowedSigner.Principals, tt.principals) {
				t.Errorf("Failed to match expected principals; got %s, expexted %s", allowedSigner.Principals, tt.principals)
			}

			if allowedSigner.Options.CertAuthority {
				t.Errorf("Unexpected certificate in allowed signer")
			}

			if !slices.Equal(allowedSigner.Options.Namespaces, tt.namespaces) {
				t.Errorf("Unexpected namespaces; got %s, wanted %s", allowedSigner.Options.Namespaces, tt.namespaces)
			}

			if !allowedSigner.Options.ValidBefore.Equal(tt.validBefore) {
				t.Errorf("Unexpected valid-before timestamp; got %s, wanted %s", allowedSigner.Options.ValidBefore, tt.validBefore)
			}

			if !allowedSigner.Options.ValidAfter.Equal(tt.validAfter) {
				t.Errorf("Unexpected valid-after timestamp; got %s, wanted %s", allowedSigner.Options.ValidAfter, tt.validAfter)
			}

			if allowedSigner.Comment != tt.comment {
				t.Errorf("Unexpected comment; got %s, wanted %s", allowedSigner.Comment, tt.comment)
			}

			if allowedSigner.Rest != nil {
				t.Errorf("Unexpected additional data %s", allowedSigner.Rest)
			}
		})
	}
}
