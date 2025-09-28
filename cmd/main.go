package main

import (
	"github.com/fionn/commit-signature-verifier/service"
)

func main() {
	err := service.Run()
	if err != nil {
		panic(err)
	}
}
