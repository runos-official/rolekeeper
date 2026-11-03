# rolekeeper image: one static binary on distroless, run as a non-root user,
# no shell. It matches the image of the roid applier that it replaces: the
# same base, the same user id and the same entry point style, so the pod
# manifest only changes its image reference.
#
# Both base images are pinned by digest as well as by tag, so one commit
# always builds on the same compiler and runtime layer. To refresh after a
# deliberate bump, resolve the new multi-arch index digest with:
#   docker buildx imagetools inspect golang:1.26.10
#   docker buildx imagetools inspect gcr.io/distroless/static-debian12:nonroot
#
# The build stage runs on the build host and cross-compiles with Go's own
# toolchain, so a multi-architecture build needs no emulation.
#
# Reproducible binaries: -trimpath drops host paths, -buildvcs=false keeps git
# state out of the binary. The version is stamped with -ldflags -X.
FROM --platform=$BUILDPLATFORM public.ecr.aws/docker/library/golang:1.26.10@sha256:3745f1aa11822297b79113f5e84ce2bffeb039734571c39855809cfe9e5d7be6 AS build
WORKDIR /src
# Modules come only through the proxy and are checked against go.sum and the
# checksum database; the module environment is fixed here so no build
# argument or host setting can switch the check off.
ENV CGO_ENABLED=0 GOTOOLCHAIN=local \
	GOFLAGS=-mod=readonly GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org \
	GONOSUMDB= GONOSUMCHECK= GONOPROXY= GOPRIVATE= GOINSECURE=
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
ARG TARGETOS=linux
ARG TARGETARCH
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -buildvcs=false \
	-ldflags "-s -w -X main.version=${VERSION}" -o /out/rolekeeper ./cmd/rolekeeper

# The root filesystem is read-only in the pod and the binary writes only to
# the state directory the pod mounts, so the image needs nothing else.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
LABEL org.opencontainers.image.title="rolekeeper" \
	org.opencontainers.image.description="Keeps Kubernetes RBAC roles and the deny list in line with the access decisions that RunOS signs." \
	org.opencontainers.image.source="https://github.com/runos-official/rolekeeper" \
	org.opencontainers.image.licenses="Elastic-2.0" \
	org.opencontainers.image.vendor="RunOS"
COPY --from=build /out/rolekeeper /rolekeeper
USER 65532:65532
ENTRYPOINT ["/rolekeeper"]
