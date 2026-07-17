# Commit Signature Verifier

Verify Git commit signatures on GitHub independently of GitHub's check.

This might be useful if you don't trust the integrity of a user's account or want to enforce signing from a set of known good keys (like those residing on hardware devices).

The application waits to be called by a push event webhook payload. It then fetches the commit corresponding to that payload and verifies its signature, writing the verification result to the commit as a status check.

## Supported Signature Types

* [x] SSH,
* [ ] PGP.

## Permissions

The application requires the following permissions:
* metadata access (mandatory, every application requires this),
* read and write access to commit statuses, in order to write the verification status,
* read-only access to repository contents, in order to subscribe to push events and get commits to verify their signature.

## Usage

### Configuration

We expect the following environment variables to be set:

* for GitHub:
  * `APP_ID`, the GitHub app ID,
  * `INSTALLATION_ID`, the GitHub app installation ID,
  * `PRIVATE_KEY`, the GitHub app private key,
  * `WEBHOOK_SECRET`, the secret used to validate webhook payloads,
* for verifying signatures, one of:
  * `SSH_ALLOWED_SIGNERS_PATH`, the path to the SSH allowed signers file, or
  * `SSH_ALLOWED_SIGNERS_BASE64`, the base64-encoded contents of an allowed signers file
* and for the server:
  * `ADDRESS`, the address to listen on (optional and defaults to `localhost:8080`).

### Compilation

```shell
make build
```

### Running

```shell
go run cmd/main.go
# or, if compiled,
./bin/commit-signature-verifier
```

Or,

```shell
make image
podman run -e=INSTALLATION_ID -e=APP_ID -e=PRIVATE_KEY -e=WEBHOOK_SECRET -e=SSH_ALLOWED_SIGNERS_PATH --mount=type=bind,src=$(pwd)/$SSH_ALLOWED_SIGNERS_PATH,dst=/$SSH_ALLOWED_SIGNERS_PATH,ro=true -it -p 8080:8080 commit-signature-verifier
```
to run in a container.

## Testing

### Unit Tests

```shell
make test
```

### "Integration" Tests

Set up a reverse tunnel to proxy traffic to the local application with
```shell
ssh -R 80:localhost:8080 localhost.run
```
or similar.
Then add the proxy URL as the webhook URL in the application settings.

## Deploying

### Fly

```
fly launch --no-deploy
fly secrets set APP_ID=$APP_ID
fly secrets set INSTALLATION_ID=$INSTALLATION_ID
fly secrets set PRIVATE_KEY=$PRIVATE_KEY
fly secrets set WEBHOOK_SECRET=$WEBHOOK_SECRET
fly secrets set SSH_ALLOWED_SIGNERS_BASE64=$SSH_ALLOWED_SIGNERS_BASE64
fly deploy --build-arg "VERSION=$(git describe --tags --always --dirty)"
```
