package verifier

import (
	"bytes"
	"log/slog"
	"os"

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
	logger.Debug("Verifying message", slog.String("message", string(message)))

	return sshsig.Verify(
		bytes.NewReader(message),
		signature,
		publicKey,
		signature.HashAlgorithm,
		signature.Namespace,
	)
}
