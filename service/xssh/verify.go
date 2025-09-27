package xssh

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"
)

var logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

func VerifySignature(message []byte, signatureBytes []byte, allowedSigner AllowedSigner, namespace string, timestamp time.Time) error {
	signature, err := sshsig.Unarmor(signatureBytes)
	if err != nil {
		return err
	}

	logger.Debug(
		"Loaded signature",
		slog.String("signature", string(signatureBytes)),
		slog.String("format", signature.Signature.Format),
		slog.String("hashAlgorithm", signature.HashAlgorithm.String()),
		slog.String("namespace", signature.Namespace),
	)
	logger.Debug("Verifying message",
		slog.String("message", string(message)),
		slog.String("public_key", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(allowedSigner.PublicKey)))))

	if len(allowedSigner.Options.Namespaces) > 0 &&
		!slices.Contains(allowedSigner.Options.Namespaces, signature.Namespace) {
		return fmt.Errorf("signature over \"%s\" but only alowed over %s",
			signature.Namespace, allowedSigner.Options.Namespaces)
	}

	if timestamp.Compare(allowedSigner.Options.ValidAfter) == -1 {
		return fmt.Errorf("signature is not yet valid")
	}
	if !allowedSigner.Options.ValidBefore.IsZero() &&
		timestamp.Compare(allowedSigner.Options.ValidBefore) == 1 {
		return fmt.Errorf("signature is no longer valid")
	}

	fmt.Println(slices.Compare(signature.PublicKey.Marshal(), allowedSigner.PublicKey.Marshal()))

	return sshsig.Verify(
		bytes.NewReader(message),
		signature,
		allowedSigner.PublicKey,
		signature.HashAlgorithm,
		namespace,
	)
}
