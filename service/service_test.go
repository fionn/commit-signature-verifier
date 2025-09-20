package service_test

import (
	"fmt"
	"testing"

	"github.com/fionn/commit-verifier/service"
)

var principalsData = []byte(`- email_addresses:
    - git@fionn.computer
  public_keys:
    - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILbkp0LwqqV/w6wAGV9bwiR6FpHC/5DtiBAKFLZxvaSp fionn@lotus
`)

func TestYaml(t *testing.T) {
	x, _ := service.PopulateKeyring(principalsData)
	fmt.Println(x)

}
