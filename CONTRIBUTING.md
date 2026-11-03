# Contributing

This repository is **generated** from RunOS's source tree. Nobody edits it by
hand, and **pull requests cannot be merged here**: a change that lands in this
repository only would be overwritten by the next export, and the tree hash in
`SOURCE` would show it.

What you can do:

- **Report a problem or suggest a change** by opening an issue. The RunOS team
  makes the change in the source tree. The next export carries it here, with a
  release.
- **Report a vulnerability** by e-mail, not by an issue. See
  [SECURITY.md](SECURITY.md).
- **Read, build and test the code** to check what the pod does. Nothing in this
  repository needs a RunOS account.

## Build and test

You need Go (the version in `go.mod`) and, for the image, Docker.

```sh
make build        # a static binary, ./rolekeeper
make test         # go test -race ./...
make vet          # go vet ./...
make staticcheck  # staticcheck ./...
make vulncheck    # govulncheck ./...
make image        # the image for this machine's architecture, tag rolekeeper:local
```

Before you send anything, run the gates that CI runs:

```sh
go build ./...
go vet ./...
go test -race ./...
gofmt -l .                       # must print nothing
make leakcheck                   # credentials, internal identifiers, names
make sourcecheck                 # the files match the tree hash in SOURCE
```

## The leak gate

This is a public repository. Three scanners keep internal material out of it,
and they run in CI on every push and pull request:

- `scripts/leakcheck.py`: credential shapes, machine names, account ids and IP
  addresses. The same script is in every public RunOS repository.
- `scripts/denycheck.py`: internal references, such as tracking ids, internal
  hosts and dates. The rules are in `scripts/denycheck.rules`.
- `gitleaks`: a general secret scanner over the files and the history.

Use obvious placeholders in text and tests: the address ranges `192.0.2.0/24`,
`198.51.100.0/24` and `203.0.113.0/24` (RFC 5737), `2001:db8::/32` (RFC 3849)
and the host name `example.com`.

Install the pre-commit hook once per clone, so that you hear about a finding
before you push:

```sh
make hooks
```

## Releasing

Only the RunOS team releases. A release is a `v<version>` tag on `main`. The
workflow checks that the tag equals `VERSION`, that `CHANGELOG.md` has a section
for it and that the files match `SOURCE`. Then it builds and pushes
`ghcr.io/runos-official/rolekeeper` for linux/amd64 and linux/arm64 and
attests the image.
