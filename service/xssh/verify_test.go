package xssh_test

import (
	"testing"
	"time"

	"github.com/fionn/commit-signature-verifier/service/xssh"
)

var timestamp = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
var allowedSignerBytes = []byte(`git@fionn.computer namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILbkp0LwqqV/w6wAGV9bwiR6FpHC/5DtiBAKFLZxvaSp fionn@lotus`)
var allowedSigner, _ = xssh.ParseAllowedSigner(allowedSignerBytes)
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

func TestGoodSSHSignature(t *testing.T) {
	err := xssh.VerifySignature(message, signature, *allowedSigner, "git", timestamp)
	if err != nil {
		t.Fatalf("failed to verify known good commit SSH signature: %s", err)
	}
}

func TestBadSSHSignature(t *testing.T) {
	signature := []byte("yolo")
	err := xssh.VerifySignature(message, signature, *allowedSigner, "git", timestamp)
	if err == nil {
		t.Fatalf("expected to fail SSH signature check on bad signature, passed instead")
	}
}

func TestBadSSHMessage(t *testing.T) {
	message = []byte("yolo")
	err := xssh.VerifySignature(message, signature, *allowedSigner, "git", timestamp)
	if err == nil {
		t.Fatalf("expected to fail SSH signature check on bad message, passed instead")
	}
}
