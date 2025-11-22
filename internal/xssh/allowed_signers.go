// Package xssh extends the SSH-related x/crypto functionality with functions to
// parse allowed signers and verify SSH signatures.
package xssh

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Options is the full set of options that can be set for an allowed signer.
type Options struct {
	CertAuthority bool
	Namespaces    []string
	ValidBefore   time.Time
	ValidAfter    time.Time
}

// AllowedSigner is an SSH allowed signer, identifying a principal with an SSH
// public key, constraints on its use and associated metadata.
type AllowedSigner struct {
	Principals []string
	Options    Options
	PublicKey  ssh.PublicKey
	Comment    string
	Rest       []byte
}

func parseTimestamp(timestamp string) (time.Time, error) {
	timestamp, _ = strings.CutSuffix(timestamp, "Z")
	timestampLength := len(timestamp)

	// We only match against YYYYMMDD[Z] or YYYYMMDDHHMM[SS][Z] as per the spec.
	if timestampLength != 8 && timestampLength != 12 && timestampLength != 14 {
		return time.Time{}, fmt.Errorf("timestamp string has unexpected length: %d",
			timestampLength)
	}

	// According to ssh-keygen(1),
	// > Dates and times will be interpreted in the current system time zone
	// > unless suffixed with a Z character, which causes them to be
	// > interpreted in the UTC time zone.
	// but our timezone is arbitrary, so we don't consider this and will take
	// all timestamps to be UTC.
	layout := "20060102150405"[:timestampLength]
	return time.Parse(layout, timestamp)
}

func parseOptions(options []string) (optionsStruct Options, err error) {
	for _, option := range options {
		if option == "cert-authority" {
			optionsStruct.CertAuthority = true
		} else {
			k, v, found := strings.Cut(option, "=")
			if !found {
				return optionsStruct, fmt.Errorf("failed to parse option: %s", k)
			}
			v = strings.Trim(v, "\"")

			switch k {
			case "namespaces":
				optionsStruct.Namespaces = strings.Split(v, ",")
			case "valid-before":
				optionsStruct.ValidBefore, err = parseTimestamp(v)
			case "valid-after":
				optionsStruct.ValidAfter, err = parseTimestamp(v)
			default:
				return optionsStruct, fmt.Errorf("received unknown option: %s", k)
			}
		}
	}
	return optionsStruct, err
}

// ParseAllowedSigner takes an allowed signer line as a string and parses it,
// returning a well-structured *AllowedSigner (or an error).
func ParseAllowedSigner(in string) (allowedSigner *AllowedSigner, err error) {
	principalsBytes, authorizedKeyBytes, found := strings.Cut(in, " ")
	if !found {
		return nil, fmt.Errorf("failed to parse allowed signer %s", in)
	}

	publicKey, comment, optionsStr, rest, err := ssh.ParseAuthorizedKey([]byte(authorizedKeyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to parse key: %w", err)
	}

	var principals []string
	for v := range strings.SplitSeq(principalsBytes, ",") {
		principals = append(principals, string(v))
	}

	options, err := parseOptions(optionsStr)
	return &AllowedSigner{principals, options, publicKey, comment, rest}, err
}

// ReadAllowedSigners takes an io.Reader and returns a list of allowed signers
// from it, as parsed by ParseAllowedSigner.
func ReadAllowedSigners(f io.Reader) (allowedSigners []AllowedSigner, err error) {
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		allowedSigner, err := ParseAllowedSigner(scanner.Text())
		if err != nil {
			return nil, fmt.Errorf("failed to parse allowed signer: %w", err)
		}
		allowedSigners = append(allowedSigners, *allowedSigner)
	}
	return allowedSigners, nil
}
