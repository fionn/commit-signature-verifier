// Package service defines all the core logic for interacting with GitHub,
// i.e. listening for commits and responding to them, with a handler that
// verifies the commit signature, passing off cryptography-related functions to
// external packages.
package service

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httplog/v3"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v75/github"

	"github.com/fionn/commit-signature-verifier/internal/configuration"
	"github.com/fionn/commit-signature-verifier/internal/xssh"
)

// GitHub encapsulates GitHub-related functionality.
type GitHub struct {
	*github.Client

	webhookSecret configuration.Secret
}

// Service provides the GitHub client, signature configuration and methods to
// handle commit payloads.
type Service struct {
	github         GitHub
	AllowedSigners []xssh.AllowedSigner
}

// VerifyCommit takes a github.Commit and list of allowed signers and verifies
// the commit signature against that list.
func (s Service) VerifyCommit(commit *github.Commit) (ok bool, description string) {
	if !*commit.Verification.Verified {
		description = fmt.Sprintf("Commit %s is %s.", (*commit.SHA)[:7], *commit.Verification.Reason)
		slog.Info("Commit unverified on GitHub",
			slog.String("commit", *commit.SHA), slog.String("error", description))
		return false, description
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
	timestamp := *commit.Committer.Date.GetTime()

	if err := xssh.Verify(message, signature, signerIdentity, s.AllowedSigners, "git", timestamp); err != nil {
		description = fmt.Sprintf("Commit %s has bad signature: %s.", (*commit.SHA)[:7], err.Error())
		slog.Info("Commit has bad signature",
			slog.String("commit", *commit.SHA),
			slog.String("identity", signerIdentity),
			slog.String("error", err.Error()))
		return false, description
	}

	description = fmt.Sprintf("Commit %s has good signature.", (*commit.SHA)[:7])
	slog.Info("Commit has good signature",
		slog.String("identity", signerIdentity),
		slog.String("commit", *commit.SHA))
	return true, description
}

// statusFromEvent takes a push event, fetches the underlying ref, sends it to
// be verified and then returns a commit status object suitable for posting.
func (s Service) statusFromEvent(ctx context.Context, event *github.PushEvent) (*github.RepoStatus, error) {
	if strings.HasPrefix(*event.Ref, "refs/tags/") {
		slog.DebugContext(ctx, "Received tag so skipping status", slog.String("tag", *event.Ref))
		return nil, nil
	}

	// Push events can include things like branch deletion, which aren't
	// relevant for us.
	if *event.After == strings.Repeat("0", 40) && *event.Deleted {
		slog.DebugContext(ctx, "Received deletion event so skipping status",
			slog.String("ref", *event.Ref))
		return nil, nil
	}

	context := "commit-signature"

	repositoryCommit, _, err := s.github.Repositories.GetCommit(
		ctx,
		*event.Repo.Owner.Name,
		*event.Repo.Name,
		*event.After,
		nil,
	)
	if err != nil {
		state := "error"
		description := fmt.Sprintf("Failed to get commit %s.", *event.After)
		slog.ErrorContext(ctx, "Failed to get commit",
			slog.String("commit", *event.After), slog.String("error", err.Error()))

		return &github.RepoStatus{
			State:       &state,
			Description: &description,
			Context:     &context,
		}, nil
	}

	commit := repositoryCommit.Commit
	commit.SHA = repositoryCommit.SHA

	state := "failure"
	ok, description := s.VerifyCommit(commit)
	if ok {
		state = "success"
	}

	return &github.RepoStatus{
		State:       &state,
		Description: &description,
		Context:     &context,
	}, nil
}

// processPushEvent gets the commit signature state for the event and posts it
// to the commit status, i.e. this is primarily a side-effect function.
func (s Service) processPushEvent(ctx context.Context, event *github.PushEvent) error {
	status, err := s.statusFromEvent(ctx, event)
	if err != nil {
		return fmt.Errorf("failed to create commit status: %w", err)
	}
	if status == nil {
		slog.DebugContext(ctx, "No status created for event")
		return nil
	}
	_, _, err = s.github.Repositories.CreateStatus(
		ctx,
		*event.Repo.Owner.Name,
		*event.Repo.Name,
		*event.After,
		status,
	)
	if err != nil {
		return fmt.Errorf("failed to post commit status: %w", err)
	}
	return nil
}

// handleWebhook receives webhook events posted to us and kicks off the
// processing of these events. Its role is to sanity-check the incoming payloads
// and then, if deemed acceptable, pass the event off to processPushEvent.
func (s Service) handleWebhook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	payload, err := github.ValidatePayload(r, s.github.webhookSecret)
	if err != nil {
		slog.WarnContext(ctx, "Failed to validate payload", slog.String("error", err.Error()))
		http.Error(w, "Failed to validate payload", http.StatusForbidden)
		return
	}

	event, err := github.ParseWebHook(github.WebHookType(r), payload)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to parse payload", slog.String("error", err.Error()))
		http.Error(w, "Failed to parse payload", http.StatusBadRequest)
		return
	}

	switch event := event.(type) {
	case *github.PushEvent:
		slog.InfoContext(ctx, "Received push event",
			slog.String("repository", *event.Repo.FullName),
			slog.String("ref", *event.Ref),
			slog.String("commit", *event.After))

		ctx = context.WithValue(ctx,
			github.SleepUntilPrimaryRateLimitResetWhenRateLimited, true)

		err := s.processPushEvent(ctx, event)
		if err != nil {
			slog.ErrorContext(ctx, "Failed to handle push event",
				slog.String("error", err.Error()))
			http.Error(w, "Failed to handle push event", http.StatusInternalServerError)
		} else {
			if _, err := w.Write([]byte("Event processed successfully.")); err != nil {
				slog.ErrorContext(ctx, "Failed to respond to webhook",
					slog.String("error", err.Error()))
			}
		}
	default:
		slog.WarnContext(ctx, "Received webhook for unexpected event", slog.Any("event", event))
		http.Error(w, "Received webhook for unexpected event", http.StatusBadRequest)
	}
}

func newGitHubClient(appID int64, installationID int64, privateKey []byte) (*github.Client, error) {
	tr, err := ghinstallation.New(http.DefaultTransport, appID, installationID, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to build transport: %w", err)
	}

	return github.NewClient(&http.Client{Transport: tr}), nil
}

// Run initialises the service and executes the main event loop, listening for
// commit payloads.
func Run() error {
	config, err := configuration.FromEnv()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	githubClient, err := newGitHubClient(config.AppID, config.InstallationID, config.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to create GitHub client: %w", err)
	}

	service := Service{
		github:         GitHub{githubClient, config.WebhookSecret},
		AllowedSigners: config.AllowedSigners,
	}

	r := chi.NewRouter()
	r.Use(httplog.RequestLogger(slog.Default(), &httplog.Options{
		Schema:        httplog.SchemaOTEL.Concise(true),
		RecoverPanics: true,
	}))
	r.Use(middleware.AllowContentType("application/json"))
	r.Post("/api/github/hook", service.handleWebhook)
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {})

	address, ok := os.LookupEnv("ADDRESS")
	if !ok {
		address = "localhost:8080"
	}

	server := &http.Server{
		Addr:              address,
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second,
	}

	slog.Info("Listening", slog.String("address", address))
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("Server failed", slog.String("address", address),
			slog.String("error", err.Error()))
		return err
	}

	return nil
}
