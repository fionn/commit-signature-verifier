package service_test

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/google/go-github/v74/github"

	"github.com/fionn/commit-signature-verifier/service"
	"github.com/fionn/commit-signature-verifier/service/xssh"
)

func populateAllowedSigners() ([]xssh.AllowedSigner, error) {
	allowedSignerBytes := []byte(`git@fionn.computer namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILbkp0LwqqV/w6wAGV9bwiR6FpHC/5DtiBAKFLZxvaSp fionn@lotus`)
	allowedSigner, err := xssh.ParseAllowedSigner(allowedSignerBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse allowed signer: %w", err)
	}
	return []xssh.AllowedSigner{*allowedSigner}, nil
}

func exampleCommit() (*github.Commit, error) {
	repositoryCommit := new(github.RepositoryCommit)
	commitJson, err := os.ReadFile("test_data/octocat_commit.json")
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(commitJson, &repositoryCommit)
	commit := repositoryCommit.Commit
	commit.SHA = repositoryCommit.SHA
	return commit, err
}

func TestVerifyExampleUnsignedCommit(t *testing.T) {
	commit, err := exampleCommit()
	if err != nil {
		t.Fatalf("Could not unmarshal example commit")
	}
	allowedSigners, err := populateAllowedSigners()
	if err != nil {
		t.Fatalf("Could not load allowed signers: %s", err)
	}
	status := service.VerifyCommit(commit, allowedSigners)
	if *status.State != "failure" {
		t.Errorf("Expected verification to fail on commit unverified by GitHub")
	}
}
