package ssh_allowed_signers_test

import (
	"slices"
	"testing"
	"time"

	"github.com/fionn/commit-signature-verifier/service/ssh_allowed_signers"
)

func TestBadInput(t *testing.T) {
	_, _, _, _, _, err := ssh_allowed_signers.ParseAllowedSigner([]byte("yolo"))
	if err == nil {
		t.Fatalf("Expected error on bad input")
	}
}

func TestGoodInput(t *testing.T) {
	allowedSigner := []byte(`fionn@fionn.computer,*@123 namespaces="git,file",valid-before=20470101,valid-after=20010101000000Z ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILbkp0LwqqV/w6wAGV9bwiR6FpHC/5DtiBAKFLZxvaSp fionn@lotus`)

	principals, options, _, comment, rest, err := ssh_allowed_signers.ParseAllowedSigner(allowedSigner)
	if err != nil {
		t.Fatalf("Failed on good input, error: %s", err)
	}

	if !slices.Equal(principals, []string{"fionn@fionn.computer", "*@123"}) {
		t.Errorf("Failed to match expected principals, got %s", principals)
	}

	if options.CertAuthority {
		t.Errorf("Unexpected certificate in allowed signer")
	}

	if !slices.Equal(options.Namespaces, []string{"git", "file"}) {
		t.Errorf("Failed to match expected options, got %s", options.Namespaces)
	}

	if !options.ValidBefore.Equal(time.Date(2047, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("Unexpected valid-before timestamp: %s", options.ValidBefore)
	}

	if !options.ValidAfter.Equal(time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("Unexpected valid-after timestamp: %s", options.ValidBefore)
	}

	if comment != "fionn@lotus" {
		t.Errorf("Unexpected comment %s", comment)
	}

	if rest != nil {
		t.Errorf("Unexpected additional data %s", rest)
	}
}
