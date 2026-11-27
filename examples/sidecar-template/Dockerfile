# The notes sidecar: built in the Go image, run as one static binary on an empty image.
#
# The FROM line is pinned by digest, because a tag is re-pushed in place. Pin your own when you
# copy this: `docker buildx imagetools inspect golang:<version>` prints the digest.

FROM golang:1.27.4@sha256:5f1b98fa02fe396ebce2a0227a0e08309e11792915b9dd2e1f71053d7e7e6666 AS build
WORKDIR /src
# Standard library only: the build fetches no module, and needs no network
COPY go.mod main.go ./
RUN CGO_ENABLED=0 GOTOOLCHAIN=local go build -trimpath -ldflags="-s -w" -o /notes .

# Nothing but the binary, and the CA certificates a sidecar needs once it calls its service
# over TLS (docs/sidecar-protocol.md, "Reaching a service")
FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /notes /notes
ENTRYPOINT ["/notes"]
