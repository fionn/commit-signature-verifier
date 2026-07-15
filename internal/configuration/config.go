// Package configuration is a helper package to encapsulate the work of getting
// configuration values and bundling them into a form that we can expose to the
// service.
package configuration

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"

	"github.com/fionn/commit-signature-verifier/internal/xssh"
)

// Secret is a secret slice of bytes.
type Secret []byte

// LogValue implements [slog.LogValuer] and redacts the value in structured
// logs.
func (Secret) LogValue() slog.Value {
	return slog.StringValue("[redacted]")
}

// Configuration bundles all the parameters needed to execute the program.
type Configuration struct {
	// InstallationID is the GitHub application installation ID.
	InstallationID int64
	// AppID is the GitHub application ID.
	AppID int64
	// PrivateKey is the GitHub application private key.
	PrivateKey Secret
	// WebhookSecret is the secret used to validate webhook payloads from Github.
	WebhookSecret Secret
	// AllowedSignersPath is the path to the SSH allowed signers file.
	AllowedSigners []xssh.AllowedSigner
}

// FromEnv is a Configuration constructor that pulls configuration values from
// environment variables.
func FromEnv() (*Configuration, error) {
	installationIDStr, ok := os.LookupEnv("INSTALLATION_ID")
	if !ok {
		return nil, errors.New("missing INSTALLATION_ID")
	}

	appIDStr, ok := os.LookupEnv("APP_ID")
	if !ok {
		return nil, errors.New("missing APP_ID")
	}

	privateKey, ok := os.LookupEnv("PRIVATE_KEY")
	if !ok {
		return nil, errors.New("missing PRIVATE_KEY")
	}
	if err := os.Unsetenv("PRIVATE_KEY"); err != nil {
		return nil, fmt.Errorf("failed to unset PRIVATE_KEY: %w", err)
	}

	webhookSecret, ok := os.LookupEnv("WEBHOOK_SECRET")
	if !ok {
		return nil, errors.New("missing WEBHOOK_SECRET")
	}
	if err := os.Unsetenv("WEBHOOK_SECRET"); err != nil {
		return nil, fmt.Errorf("failed to unset WEBHOOK_SECRET: %w", err)
	}

	allowedSigners, err := AllowedSignersFromEnv()
	if err != nil {
		return nil, fmt.Errorf("failed to set allowed signers: %w", err)
	}

	installationID, err := strconv.ParseInt(installationIDStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("bad INSTALLATION_ID %s: %w", installationIDStr, err)
	}

	appID, err := strconv.ParseInt(appIDStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("bad APP ID %s: %w", appIDStr, err)
	}

	return &Configuration{
		InstallationID: installationID,
		AppID:          appID,
		PrivateKey:     Secret([]byte(privateKey)),
		WebhookSecret:  Secret([]byte(webhookSecret)),
		AllowedSigners: allowedSigners,
	}, nil
}

// AllowedSignersFromFile is a helper that takes a file and returns a parsed
// list of xssh.AllowedSigners from it.
func AllowedSignersFromFile(path string) (allowedSigners []xssh.AllowedSigner, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open allowed signers file %s: %w", path, err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			slog.Error("Failed to close allowed signers file",
				slog.String("path", path), slog.String("error", err.Error()))
		}
	}()

	return xssh.ReadAllowedSigners(f)
}

// AllowedSignersFromBase64 is a helper function that takes a base64 blob and
// returnes a parsed list of xssh.AllowedSigners from it.
func AllowedSignersFromBase64(blob string) (allowedSigners []xssh.AllowedSigner, err error) {
	return xssh.ReadAllowedSigners(base64.NewDecoder(base64.StdEncoding, bytes.NewReader([]byte(blob))))
}

// AllowedSignersFromEnv determines from available environment variables what
// allowed signer configuration is available and parses it, returning a list of
// xssh.AllowedSigners from it.
func AllowedSignersFromEnv() (allowedSigners []xssh.AllowedSigner, err error) {
	allowedSignersPath, ok := os.LookupEnv("SSH_ALLOWED_SIGNERS_PATH")
	if ok {
		slog.Info("Loading allowed signers from file", slog.String("path", allowedSignersPath))
		return AllowedSignersFromFile(allowedSignersPath)
	}

	allowedSignersBase64, ok := os.LookupEnv("SSH_ALLOWED_SIGNERS_BASE64")
	if ok {
		slog.Info("Loading allowed signers from base64")
		return AllowedSignersFromBase64(allowedSignersBase64)
	}

	return nil, errors.New("missing one of SSH_ALLOWED_SIGNERS_PATH or SSH_ALLOWED_SIGNERS_BASE64")
}
