package service_test

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/google/go-github/v75/github"

	"github.com/fionn/commit-signature-verifier/service"
	"github.com/fionn/commit-signature-verifier/service/xssh"
)

func populateAllowedSigners(t *testing.T) ([]xssh.AllowedSigner, error) {
	t.Helper()
	allowedSigner, err := xssh.ParseAllowedSigner(`git@fionn.computer namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILbkp0LwqqV/w6wAGV9bwiR6FpHC/5DtiBAKFLZxvaSp fionn@lotus`)
	if err != nil {
		err = fmt.Errorf("failed to parse allowed signer: %w", err)
		t.Error(err.Error())
		return nil, err
	}
	return []xssh.AllowedSigner{*allowedSigner}, nil
}

func loadCommit(t *testing.T, path string) (*github.Commit, error) {
	t.Helper()
	dataDirectory := "test_data"
	root, err := os.OpenRoot(dataDirectory)
	if err != nil {
		t.Errorf("Failed to open directory: %s", dataDirectory)
		return nil, err
	}
	defer func() {
		if root.Close() != nil {
			t.Errorf("Failed to close directory: %s", dataDirectory)
		}
	}()

	commitJson, err := root.ReadFile(path)
	if err != nil {
		t.Errorf("Failed to load commit from path %s: %v", path, err)
		return nil, err
	}

	repositoryCommit := new(github.RepositoryCommit)
	err = json.Unmarshal(commitJson, &repositoryCommit)
	if err != nil {
		t.Error("Failed to unmarshal test commit payload")
		return nil, err
	}
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
		{"BadOctocatCommit", "octocat_commit.json", false},
		{"GoodCommitSignature", "signed_commit.json", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			commit, err := loadCommit(t, tt.commitDataFile)
			if err != nil {
				t.Fatalf("Could not unmarshal example commit")
			}
			allowedSigners, err := populateAllowedSigners(t)
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
