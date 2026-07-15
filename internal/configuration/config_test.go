package configuration_test

import (
	"os"
	"testing"

	"github.com/fionn/commit-signature-verifier/internal/configuration"
)

// Test redacting secrets in slog output.
func TestSecretRedaction(t *testing.T) {
	secret := configuration.Secret([]byte("yolo"))
	secretRepresentation := secret.LogValue()
	if secretRepresentation.String() != "[redacted]" {
		t.Fatalf("Failed to redact secret")
	}
}

// Test setting configuration from environment.
func TestFromEnv(t *testing.T) {
	baseEnv := map[string]string{
		"INSTALLATION_ID":          "123",
		"APP_ID":                   "456",
		"PRIVATE_KEY":              "private key",
		"WEBHOOK_SECRET":           "webhook secret",
		"SSH_ALLOWED_SIGNERS_PATH": "test_data/test_allowed_signers",
	}

	for key := range baseEnv {
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("Coundn't unset environment variable %s prior to test: %s", key, err)
		}
	}

	t.Run("FullEnv", func(t *testing.T) {
		for key, value := range baseEnv {
			t.Setenv(key, value)
		}

		_, err := configuration.FromEnv()
		if err != nil {
			t.Fatalf("Failed to set configuration from environment: %s", err)
		}
	})

	t.Run("MissingInstallationID", func(t *testing.T) {
		for key, value := range baseEnv {
			if key != "INSTALLATION_ID" {
				t.Setenv(key, value)
			}
		}

		_, err := configuration.FromEnv()
		if err == nil {
			t.Fatalf("Failed to return error when required variable INSTALLATION_ID is missing")
		}
	})
}

// Test parsing allowed signers from a file that doesn't exist.
func TestAllowedSignersFromFileNotExist(t *testing.T) {
	allowedSigners, err := configuration.AllowedSignersFromFile("/does/not/exist")
	if allowedSigners != nil || err == nil {
		t.Fatalf("Failed to return an error when opening an allowed signers file that doesn't exist")
	}
}
