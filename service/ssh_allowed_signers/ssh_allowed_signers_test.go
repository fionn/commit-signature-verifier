package ssh_allowed_signers_test

import (
	"slices"
	"testing"
	"time"

	xssh "github.com/fionn/commit-signature-verifier/service/ssh_allowed_signers"
)

func TestBadInput(t *testing.T) {
	_, err := xssh.ParseAllowedSigner([]byte("yolo"))
	if err == nil {
		t.Fatalf("Expected error on bad input")
	}
}

func TestGoodInput(t *testing.T) {
	allowedSignerBytes := []byte(`fionn@fionn.computer,*@123 namespaces="git,file",valid-before=20470101,valid-after=20010101000000Z ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILbkp0LwqqV/w6wAGV9bwiR6FpHC/5DtiBAKFLZxvaSp fionn@lotus`)

	allowedSigner, err := xssh.ParseAllowedSigner(allowedSignerBytes)
	if err != nil {
		t.Fatalf("Failed on good input, error: %s", err)
	}

	if !slices.Equal(allowedSigner.Principals, []string{"fionn@fionn.computer", "*@123"}) {
		t.Errorf("Failed to match expected principals, got %s", allowedSigner.Principals)
	}

	if allowedSigner.Options.CertAuthority {
		t.Errorf("Unexpected certificate in allowed signer")
	}

	if !slices.Equal(allowedSigner.Options.Namespaces, []string{"git", "file"}) {
		t.Errorf("Failed to match expected options, got %s", allowedSigner.Options.Namespaces)
	}

	if !allowedSigner.Options.ValidBefore.Equal(time.Date(2047, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("Unexpected valid-before timestamp: %s", allowedSigner.Options.ValidBefore)
	}

	if !allowedSigner.Options.ValidAfter.Equal(time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("Unexpected valid-after timestamp: %s", allowedSigner.Options.ValidBefore)
	}

	if allowedSigner.Comment != "fionn@lotus" {
		t.Errorf("Unexpected comment %s", allowedSigner.Comment)
	}

	if allowedSigner.Rest != nil {
		t.Errorf("Unexpected additional data %s", allowedSigner.Rest)
	}
}
