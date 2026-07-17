package xssh

import (
	"bytes"
	"fmt"
	"log/slog"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"
)

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
	// First narrow down our allowed signers list to include only those elements
	// that match the given principal. We have to check this now, since the
	// underlying verification function doesn't have a concept of principals or
	// an identity, so we are responsible for finding public keys that are
	// appropriate to check against.
	candidateSigners := slices.DeleteFunc(allowedSigners, func(s AllowedSigner) bool {
		return !patternMatch(s.Principals, identity)
	})

	if len(candidateSigners) == 0 {
		slog.Debug("Missing public key", slog.String("identity", identity))
		return fmt.Errorf("missing public key for identity %s", identity)
	}

	for _, allowedSigner := range candidateSigners {
		slog.Debug("Checking signature",
			slog.String("identity", identity),
			slog.Any("principals", allowedSigner.Principals))
		err = VerifySignature(message, signature, allowedSigner, namespace, timestamp)
		if err == nil {
			// We got a good signature, no need to check any other allowed
			// signers.
			break
		}
		// We got a bad signature, so keep checking in case another allowed
		// signer entry for this identity will match.
		slog.Debug("Got bad signature",
			slog.String("identity", identity),
			slog.Any("principals", allowedSigner.Principals))
	}

	return err
}

// patternMatch takes a list of patterns and a string and does a glob-like
// match for the string against each pattern. From ssh_config(5),
//
// > A pattern-list is a comma-separated list of patterns. Patterns within
// > pattern-lists may be negated by preceding them with an exclamation mark
// > (‘!’).
// >
// > For example, to allow a key to be used from anywhere within an organization
// > except from the "dialup" pool, the following entry (in authorized_keys)
// > could be used: from="!*.dialup.example.com,*.example.com"
//
// and since there is no mention of ordering we infer that negation will take
// precedence, so we must always return a negative match if we have a negation
// of a positive match, even if we also have a positive match elsewhere in the
// list of patterns.
func patternMatch(patterns []string, identity string) (matched bool) {
	// Since we can have negative matches anywhere in the pattern list, we can't
	// return early on match and must check each one. We absorb positive matches
	// in anyMatched, which is returned at the end.
	anyMatched := false

	for _, pattern := range patterns {
		pattern, negate := strings.CutPrefix(pattern, "!")

		matched, err := path.Match(pattern, identity)
		// Bail if we can't understand the pattern or if it contains escape
		// sequences SSH doesn't support.
		if err != nil || strings.ContainsAny(pattern, "[\\") {
			slog.Error("Bad pattern for principal", slog.String("principal", pattern))
			return false
		}

		if negate && matched {
			// We've matched on a negated pattern, so return a negative match
			// early.
			return false
		}

		anyMatched = anyMatched || matched
	}

	return anyMatched
}

// VerifySignature verifies an SSH signature over a namespaced message against
// a given AllowedSigner.
func VerifySignature(message []byte, signatureBytes []byte, allowedSigner AllowedSigner,
	namespace string, timestamp time.Time) error {
	signature, err := sshsig.Unarmor(signatureBytes)
	if err != nil {
		return fmt.Errorf("failed to parse SSH signature: %s", err.Error())
	}

	slog.Debug(
		"Loaded signature",
		slog.String("format", signature.Signature.Format),
		slog.String("hash_algorithm", signature.HashAlgorithm.String()),
		slog.String("namespace", signature.Namespace),
	)
	slog.Debug("Verifying message",
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
