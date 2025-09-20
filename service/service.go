package service

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"

	"golang.org/x/crypto/ssh"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/goccy/go-yaml"
	"github.com/google/go-github/v74/github"

	"github.com/fionn/commit-verifier/service/verifier"
)

var logger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

type emailAddress string

type keyring map[emailAddress][]ssh.PublicKey

type principal struct {
	EmailAddresses []emailAddress  `yaml:"email_addresses"`
	PublicKeys     []ssh.PublicKey `yaml:"public_keys"`
}

type Service struct {
	github        *github.Client
	webhookSecret []byte // TODO: type.
	keyring       keyring
}

func newKeyring(principals []principal) keyring {
	k := make(keyring)
	for _, p := range principals {
		for _, emailAddress := range p.EmailAddresses {
			k[emailAddress] = p.PublicKeys
		}
	}
	return k
}

func (s Service) pushEventStatus(ctx context.Context, event *github.PushEvent) github.RepoStatus {
	var state string
	var description string
	context := "commit-signature"

	commit, _, err := s.github.Repositories.GetCommit(
		ctx,
		*event.Repo.Owner.Name,
		*event.Repo.Name,
		*event.After,
		nil,
	)
	if err != nil {
		state = "error"
		description = fmt.Sprintf("Failed to get commit %s", *event.After)
		logger.Error("Failed to get commit",
			slog.String("commit", *event.After), slog.String("error", err.Error()))
		return github.RepoStatus{State: &state, Description: &description, Context: &context}
	}

	if !*commit.Commit.Verification.Verified {
		state = "failure"
		description = *commit.Commit.Verification.Reason
		logger.Debug("Commit unverified on GitHub",
			slog.String("commit", *event.After), slog.String("reason", description))
		return github.RepoStatus{State: &state, Description: &description, Context: &context}
	}

	signature := []byte(*commit.Commit.Verification.Signature)
	message := []byte(*commit.Commit.Verification.Payload)
	publicKeys := s.keyring[emailAddress(*commit.Commit.Committer.Email)]

	if len(publicKeys) == 0 {
		state = "error"
		description = fmt.Sprintf("missing public key for email address %s",
			*commit.Commit.Committer.Email)
		logger.Debug("Missing public key", slog.String("commit", *event.After),
			slog.String("committer", *commit.Commit.Committer.Email))
		return github.RepoStatus{State: &state, Description: &description, Context: &context}
	}

	var verifierError error
	for _, publicKey := range publicKeys {
		verifierError = verifier.VerifySSHSignature(message, signature, publicKey)
		if verifierError == nil {
			break
		}
	}
	if verifierError != nil {
		state = "failure"
		description = verifierError.Error()
		logger.Debug("Commit has bad signature",
			slog.String("commit", *event.After), slog.String("error", description))
		return github.RepoStatus{State: &state, Description: &description, Context: &context}
	}

	state = "success"
	description = fmt.Sprintf("Commit %s has good signature", (*event.After)[:7])
	logger.Debug(description, slog.String("commit", *event.After))
	return github.RepoStatus{State: &state, Description: &description, Context: &context}
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
		logger.Info("Failed to parse payload", slog.String("error", err.Error()))
		http.Error(w, "Failed to parse payload", http.StatusBadRequest)
		return
	}

	switch event := event.(type) {
	case *github.PushEvent:
		ctx := context.Background()
		status := s.pushEventStatus(ctx, event)
		_, _, err := s.github.Repositories.CreateStatus(
			ctx,
			*event.Repo.Owner.Name,
			*event.Repo.Name,
			*event.After,
			&status,
		)
		if err != nil {
			panic(err)
		}
	default:
		logger.Warn("Received webhook for unexpected event", "event", event)
	}
}

func newGitHubClient() (*github.Client, []byte, error) {
	installationIDStr, ok := os.LookupEnv("INSTALLATION_ID")
	if !ok {
		return nil, nil, fmt.Errorf("missing INSTALLATION_ID")
	}

	installationID, err := strconv.ParseInt(installationIDStr, 10, 64)
	if err != nil {
		logger.Error("Bad INSTALLATION_ID", slog.String("error", err.Error()))
		return nil, nil, err
	}

	appIDStr, ok := os.LookupEnv("APP_ID")
	if !ok {
		return nil, nil, fmt.Errorf("missing APP_ID")
	}

	appID, err := strconv.ParseInt(appIDStr, 10, 64)
	if err != nil {
		logger.Error("Bad APP_ID", slog.String("error", err.Error()))
		return nil, nil, err
	}

	privateKeyStr, ok := os.LookupEnv("PRIVATE_KEY")
	if !ok {
		return nil, nil, fmt.Errorf("missing PRIVATE_KEY")
	}

	webhookSecretStr, ok := os.LookupEnv("WEBHOOK_SECRET")
	if !ok {
		return nil, nil, fmt.Errorf("missing WEBHOOK_SECRET")
	}

	webhookSecret := []byte(webhookSecretStr)
	privateKey := []byte(privateKeyStr)

	tr := http.DefaultTransport
	itr, err := ghinstallation.New(
		tr, appID, installationID, privateKey)
	if err != nil {
		return nil, webhookSecret, err
	}

	return github.NewClient(&http.Client{Transport: itr}), webhookSecret, nil
}

func PopulateKeyring(data []byte) (keyring, error) {
	var principals []principal
	if err := yaml.Unmarshal(data, &principals); err != nil {
		return nil, err
	}

	fmt.Println(string(data))
	fmt.Printf("%+v\n", principals)

	return newKeyring(principals), nil

	// publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILbkp0LwqqV/w6wAGV9bwiR6FpHC/5DtiBAKFLZxvaSp fionn@lotus"))
	// if err != nil {
	// 	return nil, err
	// }
	// p := principal{emailAddresses: []emailAddress{"git@fionn.computer"}, publicKeys: []ssh.PublicKey{publicKey}}
	// return newKeyring([]principal{p}), nil
}

func Run() {
	client, webhookSecret, err := newGitHubClient()
	if err != nil {
		panic(err)
	}

	principalsPath, ok := os.LookupEnv("PRINCIPALS_PATH")
	if !ok {
		principalsPath = "principals.yaml"
	}

	logger.Debug("Loading principals", slog.String("path", principalsPath))
	data, err := os.ReadFile(principalsPath)
	if err != nil {
		panic(err)
	}

	keyring, err := PopulateKeyring(data)
	if err != nil {
		panic(err)
	}

	service := Service{github: client, webhookSecret: webhookSecret, keyring: keyring}

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
	}
}
