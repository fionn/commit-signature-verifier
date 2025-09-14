package verifier_test

import (
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/fionn/commit-verifier/service/verifier"
)

var publicKey, _, _, _, _ = ssh.ParseAuthorizedKey([]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILbkp0LwqqV/w6wAGV9bwiR6FpHC/5DtiBAKFLZxvaSp fionn@lotus"))
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
	err := verifier.VerifySSHSignature(message, signature, publicKey)
	if err != nil {
		t.Fatalf("failed to verify known good commit SSH signature: %s", err)
	}
}

func TestBadSSHSignature(t *testing.T) {
	signature := []byte("yolo")
	err := verifier.VerifySSHSignature(message, signature, publicKey)
	if err == nil {
		t.Fatalf("expected to fail SSH signature check on bad signature, passed instead")
	}
}

func TestBadSSHMessage(t *testing.T) {
	message = []byte("yolo")
	err := verifier.VerifySSHSignature(message, signature, publicKey)
	if err == nil {
		t.Fatalf("expected to fail SSH signature check on bad message, passed instead")
	}
}
