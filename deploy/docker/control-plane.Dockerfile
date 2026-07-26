# Multi-stage build for the Go control plane (aether-control).
#
# Build context: the MONOREPO ROOT.
#   docker build -f deploy/docker/control-plane.Dockerfile .
#
# The generated protobuf stubs live in `control-plane/api/gen/` (committed and
# CI-verified up to date), so they arrive with the `control-plane` copy below.
# There is no top-level `api/gen/` directory — copying one would break the build.

FROM golang:1.24-bookworm AS builder
WORKDIR /build

# Dependency layer first: it changes far less often than the source, so this
# stays cached across ordinary code edits.
COPY control-plane/go.mod control-plane/go.sum /build/control-plane/
WORKDIR /build/control-plane
RUN go mod download

# Now the source.
WORKDIR /build
COPY control-plane /build/control-plane
WORKDIR /build/control-plane

# CGO disabled for a static, portable binary.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/aether-control ./cmd/aether-control

FROM gcr.io/distroless/static-debian12:nonroot AS runtime
COPY --from=builder /out/aether-control /aether-control
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/aether-control"]
