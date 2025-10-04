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

func loadCommit(path string) (*github.Commit, error) {
	repositoryCommit := new(github.RepositoryCommit)
	commitJson, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(commitJson, &repositoryCommit)
	commit := repositoryCommit.Commit
	commit.SHA = repositoryCommit.SHA
	return commit, err
}

func TestCommit(t *testing.T) {

	tests := []struct {
		name           string
		commitDataFile string
		ok             bool
	}{
		{"BadOctocatCommit", "test_data/octocat_commit.json", false},
		{"GoodCommitSignature", "test_data/signed_commit.json", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			commit, err := loadCommit(tt.commitDataFile)
			if err != nil {
				t.Fatalf("Could not unmarshal example commit")
			}
			allowedSigners, err := populateAllowedSigners()
			if err != nil {
				t.Fatalf("Could not load allowed signers: %s", err)
			}
			ok, _ := service.VerifyCommit(commit, allowedSigners)
			if ok != tt.ok {
				t.Errorf("Expected verification to be %v but got %v instead", tt.ok, ok)
			}
		})
	}
}
