package verifier

import (
	"bytes"
	"log/slog"
	"os"
	"strings"

	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"
)

var logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

func VerifySSHSignature(message []byte, signatureBytes []byte, publicKey ssh.PublicKey) error {
	signature, err := sshsig.Unarmor(signatureBytes)
	if err != nil {
		return err
	}

	logger.Debug(
		"Loaded signature",
		slog.String("signature", string(signatureBytes)),
		slog.String("hashAlgorithm", signature.HashAlgorithm.String()),
		slog.String("namespace", signature.Namespace),
	)
	logger.Debug("Verifying message",
		slog.String("message", string(message)),
		slog.String("public_key", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(publicKey)))))

	return sshsig.Verify(
		bytes.NewReader(message),
		signature,
		publicKey,
		signature.HashAlgorithm,
		"git",
	)
}
