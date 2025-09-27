# Commit Signature Verifier

Verify Git commit signatures on GitHub independently of GitHub's check.

This might be useful if you don't trust the integrity of a user's account or want to enforce signing from a set of known good keys (like those residing on hardware devices).

## Hacking

Set up a reverse tunnel to proxy traffic to the local application with
```shell
ssh -R 80:localhost:8080 localhost.run
```
or similar.
Then add the proxy URL as the webhook URL in the application settings.
