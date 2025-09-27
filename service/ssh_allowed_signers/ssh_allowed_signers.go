package ssh_allowed_signers

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type Options struct {
	CertAuthority bool
	Namespaces    []string
	ValidBefore   time.Time
	ValidAfter    time.Time
}

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

	if timestampLength < 8 || timestampLength > 14 {
		return time.Time{}, fmt.Errorf("timestamp string has unexpected length")
	}

	// Strictly speaking, we should only match against YYYYMMDD[Z] or
	// YYYYMMDDHHMM[SS][Z], but we allow for intermediate resolution.
	//
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
				return optionsStruct, fmt.Errorf("failed to parse option")
			}
			v = strings.Trim(v, "\"")

			switch k {
			case "namespaces":
				optionsStruct.Namespaces = strings.Split(v, ",")
			case "valid-before":
				optionsStruct.ValidBefore, err = parseTimestamp(v)
				if err != nil {
					return optionsStruct, err
				}
			case "valid-after":
				optionsStruct.ValidAfter, err = parseTimestamp(v)
				if err != nil {
					return optionsStruct, err
				}
			default:
				return optionsStruct, fmt.Errorf("received unknown option")
			}
		}
	}
	return optionsStruct, nil
}

func ParseAllowedSigner(in []byte) (allowedSigner *AllowedSigner, err error) {
	principalsBytes, authorizedKeyBytes, found := bytes.Cut(in, []byte(" "))
	if !found {
		return nil, fmt.Errorf("failed to parse allowed signer %s", in)
	}

	publicKey, comment, optionsStr, rest, err := ssh.ParseAuthorizedKey(authorizedKeyBytes)
	if err != nil {
		return nil, err
	}

	var principals []string
	for v := range bytes.SplitSeq(principalsBytes, []byte(",")) {
		principals = append(principals, string(v))
	}

	options, err := parseOptions(optionsStr)
	return &AllowedSigner{principals, options, publicKey, comment, rest}, err
}
