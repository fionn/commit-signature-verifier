package configuration

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"

	"github.com/fionn/commit-signature-verifier/service/xssh"
)

type Secret []byte

func (Secret) LogValue() slog.Value {
	return slog.StringValue("[redacted]")
}

type Configuration struct {
	InstallationID     int64
	AppID              int64
	PrivateKey         Secret
	WebhookSecret      Secret
	AllowedSignersPath string
}

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

	webhookSecret, ok := os.LookupEnv("WEBHOOK_SECRET")
	if !ok {
		return nil, errors.New("missing WEBHOOK_SECRET")
	}

	allowedSignersPath, ok := os.LookupEnv("SSH_ALLOWED_SIGNERS")
	if !ok {
		return nil, errors.New("missing SSH_ALLOWED_SIGNERS")
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
		InstallationID:     installationID,
		AppID:              appID,
		PrivateKey:         Secret([]byte(privateKey)),
		WebhookSecret:      Secret([]byte(webhookSecret)),
		AllowedSignersPath: allowedSignersPath,
	}, nil
}

func AllowedSignersFromFile(path string) (allowedSigners []xssh.AllowedSigner, err error) {
	slog.Info("Loading allowed signers from file", slog.String("path", path))
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open allowed signers file %s: %w", path, err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			panic(err)
		}
	}()

	return xssh.ReadAllowedSigners(f)
}
