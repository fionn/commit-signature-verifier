SRC := $(shell git ls-files *.go)

export CGO_ENABLED = 0
export SOURCE_DATE_EPOCH ?= $(shell git show -s --format=%at)

.PHONY: build
build: bin/commit-signature-verifier

bin/commit-signature-verifier: $(SRC) go.mod go.sum
	go build -v -trimpath -ldflags="-s -w" -o $@ github.com/fionn/commit-signature-verifier/cmd

.PHONY: test
test:
	@go test -v ./...

coverage.out: $(SRC)
	@go test -covermode=count -coverprofile=$@ ./...

.PHONY: coverage
coverage: coverage.out
	@go tool cover -func=$<

.PHONY: lint
lint:
	@golangci-lint run


.PHONY: clean
clean:
	@rm -r bin coverage.out
