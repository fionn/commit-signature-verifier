FROM public.ecr.aws/docker/library/golang:1.27.3-alpine3.24@sha256:f2c872bcee949b7be9c490efd02b48a8a2fbf947cdf533f1c58525ec9d8170fd AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN ["go", "mod", "download"]

COPY . .
ARG VERSION
RUN go build -v -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
    -o bin/commit-signature-verifier github.com/fionn/commit-signature-verifier/cmd

FROM scratch
USER 65534:65534

ENV port=8080
ENV ADDRESS=0.0.0.0:$port
EXPOSE $port

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /src/bin/commit-signature-verifier /bin/commit-signature-verifier

ENTRYPOINT ["/bin/commit-signature-verifier"]
