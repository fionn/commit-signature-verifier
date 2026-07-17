package service_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/google/go-github/v75/github"

	"github.com/fionn/commit-signature-verifier/internal/xssh"
	"github.com/fionn/commit-signature-verifier/service"
)

func populateAllowedSigners(t *testing.T) []xssh.AllowedSigner {
	t.Helper()
	allowedSigner, err := xssh.ParseAllowedSigner(`git@fionn.computer namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILbkp0LwqqV/w6wAGV9bwiR6FpHC/5DtiBAKFLZxvaSp fionn@lotus`)
	if err != nil {
		t.Fatalf("failed to parse allowed signer: %s", err)
	}
	return []xssh.AllowedSigner{*allowedSigner}
}

func loadCommit(t *testing.T, path string) *github.Commit {
	t.Helper()
	dataDirectory := "test_data"
	root, err := os.OpenRoot(dataDirectory)
	if err != nil {
		t.Fatalf("Failed to open directory: %s", dataDirectory)
	}
	defer func() {
		if root.Close() != nil {
			t.Fatalf("Failed to close directory: %s", dataDirectory)
		}
	}()

	commitJson, err := root.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to load commit from path %s: %v", path, err)
	}

	repositoryCommit := new(github.RepositoryCommit)
	err = json.Unmarshal(commitJson, &repositoryCommit)
	if err != nil {
		t.Fatalf("Failed to unmarshal test commit payload: %s", err)
	}
	commit := repositoryCommit.Commit
	commit.SHA = repositoryCommit.SHA
	return commit
}

// /TestCommit tests handling of commit push payloads.
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
			commit := loadCommit(t, tt.commitDataFile)
			allowedSigners := populateAllowedSigners(t)
			s := service.Service{AllowedSigners: allowedSigners}
			ok, _ := s.VerifyCommit(commit)
			if ok != tt.ok {
				t.Errorf("Expected verification to be %v but got %v instead", tt.ok, ok)
			}
		})
	}
}
