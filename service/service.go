package service

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httplog/v3"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v74/github"

	"github.com/fionn/commit-signature-verifier/service/xssh"
)

var logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

type Secret []byte

func (Secret) LogValue() slog.Value {
	return slog.StringValue("[redacted]")
}

type Service struct {
	github         *github.Client
	webhookSecret  Secret
	allowedSigners []xssh.AllowedSigner
}

func VerifyCommit(commit *github.Commit, allowedSigners []xssh.AllowedSigner) (ok bool, description string) {
	if !*commit.Verification.Verified {
		description = fmt.Sprintf("Commit %s is %s.", *commit.SHA, *commit.Verification.Reason)
		logger.Info("Commit unverified on GitHub",
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
	// https://github.blog/changelog/2024-11-12-persistent-commit-signature-verification-now-in-public-preview/
	timestamp := *commit.Committer.Date.GetTime()

	err := xssh.Verify(message, signature, signerIdentity, allowedSigners, "git", timestamp)
	if err != nil {
		description = fmt.Sprintf("Commit %s has bad signature: %s.", *commit.SHA, err.Error())
		logger.Info("Commit has bad signature",
			slog.String("commit", *commit.SHA), slog.String("error", err.Error()))
		return false, description
	}

	description = fmt.Sprintf("Commit %s has good signature.", (*commit.SHA)[:7])
	logger.Info("Commit has good signature", slog.String("commit", *commit.SHA))
	return true, description
}

func (s Service) statusFromEvent(ctx context.Context, event *github.PushEvent) (*github.RepoStatus, error) {
	if strings.HasPrefix(*event.Ref, "refs/tags/") {
		logger.Debug("received tag so skipping status", slog.String("tag", *event.Ref))
		return nil, nil
	}

	// Push events can include things like branch deletion, which aren't
	// relevant for us.
	if *event.After == strings.Repeat("0", 40) && *event.Deleted {
		logger.Debug("received deletion event so skipping status", slog.String("ref", *event.Ref))
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
		logger.Error("Failed to get commit",
			slog.String("commit", *event.After), slog.String("error", err.Error()))
		return &github.RepoStatus{State: &state, Description: &description, Context: &context}, nil
	}

	commit := repositoryCommit.Commit
	commit.SHA = repositoryCommit.SHA

	state := "failure"
	ok, description := VerifyCommit(commit, s.allowedSigners)
	if ok {
		state = "success"
	}
	return &github.RepoStatus{State: &state, Description: &description, Context: &context}, nil
}

func (s Service) handlePushEvent(ctx context.Context, event *github.PushEvent) error {
	status, err := s.statusFromEvent(ctx, event)
	if err != nil {
		return fmt.Errorf("failed to create commit status: %w", err)
	}
	if status == nil {
		logger.Debug("No status created for event")
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

func (s Service) handleWebhook(w http.ResponseWriter, r *http.Request) {
	payload, err := github.ValidatePayload(r, s.webhookSecret)
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
		ctx := r.Context()
		if err := s.handlePushEvent(ctx, event); err != nil {
			logger.Error("Failed to handle push event", slog.String("error", err.Error()))
			http.Error(w, "Failed to handle push event", http.StatusInternalServerError)
		}
	default:
		logger.Warn("Received webhook for unexpected event", "event", event)
		http.Error(w, "Received webhook for unexpected event", http.StatusBadRequest)
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

	webhookSecret = Secret([]byte(webhookSecretStr))
	privateKey := []byte(privateKeyStr)

	tr := http.DefaultTransport
	itr, err := ghinstallation.New(tr, appID, installationID, privateKey)
	if err != nil {
		return nil, webhookSecret, fmt.Errorf("failed to build transport: %w", err)
	}

	return github.NewClient(&http.Client{Transport: itr}), webhookSecret, nil
}

func populateAllowedSigners() (allowedSigners []xssh.AllowedSigner, err error) {
	allowedSignersPath, ok := os.LookupEnv("SSH_ALLOWED_SIGNERS")
	if !ok {
		homedir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("could not construct fallback path: %w", err)
		}
		allowedSignersPath = homedir + "/.ssh/allowed_signers"
	}

	logger.Info("Loading allowed signers from file", slog.String("path", allowedSignersPath))
	f, err := os.Open(allowedSignersPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open allowed signers file %s: %w", allowedSignersPath, err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			panic(err)
		}
	}()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		allowedSigner, err := xssh.ParseAllowedSigner(scanner.Bytes())
		if err != nil {
			return nil, fmt.Errorf("failed to parse allowed signer: %w", err)
		}
		logger.Debug("Loaded allowed signer", slog.Any("principals", allowedSigner.Principals))
		allowedSigners = append(allowedSigners, *allowedSigner)
	}
	return allowedSigners, nil
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
	r.Use(httplog.RequestLogger(logger, &httplog.Options{
		Schema:        httplog.SchemaOTEL.Concise(true),
		RecoverPanics: true,
	}))
	r.Use(middleware.AllowContentType("application/json"))
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
