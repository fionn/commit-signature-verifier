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
	//
	// We have to check this now, since the underlying verification function
	// doesn't have a concept of principals or an identity, so we are
	// responsible for finding public keys that are appropriate to check
	// against.
	var filteredAllowedSigners []AllowedSigner
	for _, allowedSigner := range allowedSigners {
		if slices.Contains(allowedSigner.Principals, identity) {
			filteredAllowedSigners = append(filteredAllowedSigners, allowedSigner)
		}
	}

	if len(filteredAllowedSigners) == 0 {
		logger.Debug("Missing public key", slog.String("identity", identity))
		return fmt.Errorf("missing public key for identity %s", identity)
	}

	for _, allowedSigner := range filteredAllowedSigners {
		logger.Debug("Checking signature",
			slog.String("identity", identity),
			slog.Any("principals", allowedSigner.Principals))
		err = VerifySignature(message, signature, allowedSigner, namespace, timestamp)
		if err == nil {
			// We got a good signature, no need to check any other allowed
			// signers.
			break
		} else {
			// We got a bad signature, so keep checking in case another allowed
			// signer entry for this identity will match.
			logger.Debug("Got bad signature",
				slog.String("identity", identity),
				slog.Any("principals", allowedSigner.Principals))
		}
	}

	return err
}

func VerifySignature(message []byte, signatureBytes []byte, allowedSigner AllowedSigner,
	namespace string, timestamp time.Time) error {
	signature, err := sshsig.Unarmor(signatureBytes)
	if err != nil {
		return fmt.Errorf("failed to parse SSH signature: %s", err.Error())
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

	// The signature verification below only checks if the signature is over a
	// given namespace, but doesn't know if the allowed signer has excluded this
	// namespace, so we have to check this here. We don't check if the signature
	// namespace matches the given namespace as that check is done for us by the
	// verification.
	if len(allowedSigner.Options.Namespaces) > 0 &&
		!slices.Contains(allowedSigner.Options.Namespaces, signature.Namespace) {
		return fmt.Errorf("signature over %s namespace is not permitted", signature.Namespace)
	}

	if timestamp.Compare(allowedSigner.Options.ValidAfter) == -1 {
		return fmt.Errorf("signature at time %s is not yet valid", timestamp)
	}
	if !allowedSigner.Options.ValidBefore.IsZero() &&
		timestamp.Compare(allowedSigner.Options.ValidBefore) == 1 {
		return fmt.Errorf("signature at time %s is no longer valid", timestamp)
	}

	return sshsig.Verify(
		bytes.NewReader(message),
		signature,
		allowedSigner.PublicKey,
		signature.HashAlgorithm,
		namespace,
	)
}
