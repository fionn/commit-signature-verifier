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

// Given a message, a signature over it, a signer identity, an allowed signers
// list, a namespace and a timestamp, find the allowed signers entries that
// correspond to the signing identity and then, for each entry, verify the
// signature until we get a successful verification or run out of entries.
// Verification checks:
//   - that the signature is correct,
//   - that the signature namespace matches both the given namespace and also
//     a namespace permitted by the allowed signers entry, if present,
//   - that the given timestamp is within the validity window, if at least one
//     of verify-before or verify-after are present.
func Verify(message []byte, signature []byte, identity string, allowedSigners []AllowedSigner,
	namespace string, timestamp time.Time) (err error) {
	// Shortcut: we should be checking glob matches but we're assuming the
	// allowed signers have literal principals, not patterns.
	var filteredAllowedSigners []AllowedSigner
	for _, allowedSigner := range allowedSigners {
		if slices.Contains(allowedSigner.Principals, identity) {
			filteredAllowedSigners = append(filteredAllowedSigners, allowedSigner)
		}
	}

	if len(filteredAllowedSigners) == 0 {
		logger.Info("Missing public key", slog.String("identity", identity))
		return fmt.Errorf("missing public key for identity %s", identity)
	}

	for _, allowedSigner := range filteredAllowedSigners {
		err = VerifySignature(message, signature, allowedSigner, namespace, timestamp)
		if err == nil {
			break
		}
	}

	return err
}

func VerifySignature(message []byte, signatureBytes []byte, allowedSigner AllowedSigner,
	namespace string, timestamp time.Time) error {
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

	return sshsig.Verify(
		bytes.NewReader(message),
		signature,
		allowedSigner.PublicKey,
		signature.HashAlgorithm,
		namespace,
	)
}
