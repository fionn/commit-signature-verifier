FROM public.ecr.aws/docker/library/golang:1.26.5-alpine3.24@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN ["go", "mod", "download"]

COPY . .
ARG CGO_ENABLED=0
RUN ["go", "build", "-v", "-trimpath", "-ldflags=-s -w", "-o", \
     "bin/commit-signature-verifier", "github.com/fionn/commit-signature-verifier/cmd"]

FROM scratch
USER 65534:65534

ENV port=8080
ENV ADDRESS=0.0.0.0:$port
EXPOSE $port

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /src/bin/commit-signature-verifier /bin/commit-signature-verifier

ENTRYPOINT ["/bin/commit-signature-verifier"]
