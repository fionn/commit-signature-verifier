package service

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v74/github"

	"github.com/fionn/commit-signature-verifier/service/xssh"
)

var logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

type Secret struct {
	secret []byte
}

func (secret Secret) String() string {
	return "[redacted]"
}

func (secret Secret) Reveal() []byte {
	return secret.secret
}

type Service struct {
	github         *github.Client
	webhookSecret  Secret
	allowedSigners []xssh.AllowedSigner
}

func (s Service) statusFromEvent(ctx context.Context, event *github.PushEvent) github.RepoStatus {
	var state string
	var description string
	context := "commit-signature"

	repositoryCommit, _, err := s.github.Repositories.GetCommit(
		ctx,
		*event.Repo.Owner.Name,
		*event.Repo.Name,
		*event.After,
		nil,
	)
	if err != nil {
		state = "error"
		description = fmt.Sprintf("Failed to get commit %s.", *event.After)
		logger.Error("Failed to get commit",
			slog.String("commit", *event.After), slog.String("error", err.Error()))
		return github.RepoStatus{State: &state, Description: &description, Context: &context}
	}

	commit := repositoryCommit.Commit
	commit.SHA = repositoryCommit.SHA

	if !*commit.Verification.Verified {
		state = "failure"
		description = fmt.Sprintf("Commit %s is %s.", *commit.SHA, *commit.Verification.Reason)
		logger.Debug("Commit unverified on GitHub",
			slog.String("commit", *commit.SHA), slog.String("reason", description))
		return github.RepoStatus{State: &state, Description: &description, Context: &context}
	}

	signature := []byte(*commit.Verification.Signature)
	message := []byte(*commit.Verification.Payload)
	signerIdentity := *commit.Committer.Email
	// There's an argument that the only timestamp we know is not forged is
	// our own, since if a key has a valid-before option specified we have
	// to assume it's not trustworthy afterwards, at which point an attacker
	// with access to the assumed compromised key could sign a commit with a
	// timestamp prior to valid-before, which would pass validation.
	//
	// We do want to allow pushing old commits, however, so we accept this risk,
	// which is partially mitigated by the above check that GitHub performs,
	// which is done at time of push.
	// https://github.blog/changelog/2024-11-12-persistent-commit-signature-verification-now-in-public-preview/
	timestamp := *commit.Committer.Date.GetTime()

	err = xssh.Verify(message, signature, signerIdentity, s.allowedSigners, "git", timestamp)
	if err != nil {
		state = "failure"
		description = fmt.Sprintf("Commit %s has bad signature: %s.", *commit.SHA, err.Error())
		logger.Info("Commit has bad signature",
			slog.String("commit", *commit.SHA), slog.String("error", err.Error()))
		return github.RepoStatus{State: &state, Description: &description, Context: &context}
	}

	state = "success"
	description = fmt.Sprintf("Commit %s has good signature.", (*commit.SHA)[:7])
	logger.Debug(description, slog.String("commit", *commit.SHA))
	return github.RepoStatus{State: &state, Description: &description, Context: &context}
}

func (s Service) handleWebhook(w http.ResponseWriter, r *http.Request) {
	payload, err := github.ValidatePayload(r, s.webhookSecret.Reveal())
	if err != nil {
		logger.Info("Failed to validate payload", slog.String("error", err.Error()))
		http.Error(w, "Failed to validate payload", http.StatusForbidden)
		return
	}

	event, err := github.ParseWebHook(github.WebHookType(r), payload)
	if err != nil {
		logger.Error("Failed to parse payload", slog.String("error", err.Error()))
		http.Error(w, "Failed to parse payload", http.StatusBadRequest)
		return
	}

	switch event := event.(type) {
	case *github.PushEvent:
		logger.Info("Received push event",
			slog.String("repository", *event.Repo.FullName),
			slog.String("ref", *event.Ref),
			slog.String("commit", *event.After))

		ctx := context.Background()
		status := s.statusFromEvent(ctx, event)
		_, _, err := s.github.Repositories.CreateStatus(
			ctx,
			*event.Repo.Owner.Name,
			*event.Repo.Name,
			*event.After,
			&status,
		)
		if err != nil {
			logger.Error("Failed to post commit status", slog.String("error", err.Error()))
		}
	default:
		logger.Warn("Received webhook for unexpected event", "event", event)
	}
}

func newGitHubClient() (*github.Client, Secret, error) {
	var webhookSecret Secret
	installationIDStr, ok := os.LookupEnv("INSTALLATION_ID")
	if !ok {
		return nil, webhookSecret, fmt.Errorf("missing INSTALLATION_ID")
	}

	installationID, err := strconv.ParseInt(installationIDStr, 10, 64)
	if err != nil {
		return nil, webhookSecret, fmt.Errorf("bad INSTALLATION_ID %s: %w", installationIDStr, err)
	}

	appIDStr, ok := os.LookupEnv("APP_ID")
	if !ok {
		return nil, webhookSecret, fmt.Errorf("missing APP_ID")
	}

	appID, err := strconv.ParseInt(appIDStr, 10, 64)
	if err != nil {
		return nil, webhookSecret, fmt.Errorf("bad APP ID %s: %w", appIDStr, err)
	}

	privateKeyStr, ok := os.LookupEnv("PRIVATE_KEY")
	if !ok {
		return nil, webhookSecret, fmt.Errorf("missing PRIVATE_KEY")
	}

	webhookSecretStr, ok := os.LookupEnv("WEBHOOK_SECRET")
	if !ok {
		return nil, webhookSecret, fmt.Errorf("missing WEBHOOK_SECRET")
	}

	webhookSecret = Secret{[]byte(webhookSecretStr)}
	privateKey := []byte(privateKeyStr)

	tr := http.DefaultTransport
	itr, err := ghinstallation.New(tr, appID, installationID, privateKey)
	if err != nil {
		return nil, webhookSecret, fmt.Errorf("failed to build transport: %w", err)
	}

	return github.NewClient(&http.Client{Transport: itr}), webhookSecret, nil
}

// URGH.
func populateAllowedSigners() ([]xssh.AllowedSigner, error) {
	allowedSignerBytes := []byte(`git@fionn.computer namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILbkp0LwqqV/w6wAGV9bwiR6FpHC/5DtiBAKFLZxvaSp fionn@lotus`)
	allowedSigner, err := xssh.ParseAllowedSigner(allowedSignerBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse allowed signer: %w", err)
	}
	return []xssh.AllowedSigner{*allowedSigner}, nil
}

func Run() error {
	client, webhookSecret, err := newGitHubClient()
	if err != nil {
		logger.Error("failed to create GitHub client",
			slog.String("error", err.Error()))
		return err
	}

	allowedSigners, err := populateAllowedSigners()
	if err != nil {
		logger.Error("failed to populate allowed signers",
			slog.String("error", err.Error()))
		return err
	}

	service := Service{github: client, webhookSecret: webhookSecret, allowedSigners: allowedSigners}

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Post("/api/github/hook", service.handleWebhook)

	address, ok := os.LookupEnv("ADDRESS")
	if !ok {
		address = "localhost:8080"
	}

	logger.Info("Listening", slog.String("address", address))
	if err := http.ListenAndServe(address, r); err != nil && err != http.ErrServerClosed {
		logger.Error("server failed", "address", address, "error", err)
		return err
	}

	return nil
}
