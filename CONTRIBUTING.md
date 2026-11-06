# Contributing

This repository is the source of rolekeeper. Pull requests are welcome from the
RunOS team and from outside. Work lands on the `dev` branch by pull request;
`main` records what shipped to production.

What you can do:

- **Fix a bug or add a test.** Open a pull request against `dev`. Keep one
  change in one commit, and say in the message what changed and why.
- **Report a problem or suggest a change** by opening an issue.
- **Report a vulnerability** by e-mail, not by an issue. See
  [SECURITY.md](SECURITY.md).
- **Read, build and test the code** to check what the pod does. Nothing in this
  repository needs a RunOS account.

Code that signs, verifies or applies (`signer/`, `bundle/`, `applier/`,
`compile/`, `reconcile/`) holds the security of the product. A change there
needs a test that fails without it.

## Build and test

You need Go (the version in `go.mod`), Python 3 for the gate scripts and, for
the image, Docker.

```sh
make build        # a static binary, ./rolekeeper
make test         # go test -race ./...
make coverage     # the tests, then scripts/coverage-floors
make vet          # go vet ./...
make fmt-check    # gofmt -l . (must print nothing)
make staticcheck  # staticcheck ./...
make vulncheck    # govulncheck ./...
make image        # the image for this machine's architecture, tag rolekeeper:local
```

Before you push, run the gates that CI runs:

```sh
gofmt -l .                       # must print nothing
go build ./...
go vet ./...
go test -race -count=1 ./...
make coverage                    # no package falls below its floor
make leakcheck                   # credentials, internal identifiers, names
```

### Coverage floors

`scripts/coverage-floors.txt` holds the lowest statement coverage that each
package may have. `scripts/coverage-floors` runs the tests with coverage and
fails when a package is below its floor or has no floor listed. Raise a floor
when you raise the coverage; do not lower one to get a change through.

### Conformance vectors

`testdata/conformance/` holds a frozen set of signed tokens and bundles that
the verifier must accept or refuse. It is how RunOS's signing side and this
verifying side keep agreeing. See [docs/conformance.md](docs/conformance.md).

## The leak gate

This is a public repository. Standing gates keep internal material out of it,
and they run in CI on every push and pull request:

- `scripts/leakcheck.py`: credential shapes, machine names, account ids and IP
  addresses. The same script is in every public RunOS repository.
- `scripts/unscannable_check.py`: every tracked file must be one that
  `leakcheck.py` can read.
- `scripts/denycheck.py`: internal references, such as tracking ids, internal
  hosts and dates, in file text and file names. The rules are in
  `scripts/denycheck.rules`. A name appears there only as a hash. To add one
  without typing it into the repository, run
  `python3 scripts/denycheck.py --hash WORD` and add the line it prints.
- `scripts/msgcheck.py`: the same rules over the commit messages and the file
  names of a commit range. A commit message is public text, too.
- `gitleaks`: a general secret scanner over the files and the history.

Use obvious placeholders in text and tests: the address ranges `192.0.2.0/24`,
`198.51.100.0/24` and `203.0.113.0/24` (RFC 5737), `2001:db8::/32` (RFC 3849)
and the host name `example.com`.

Install the hooks once per clone, so that you hear about a finding before it
leaves your machine:

```sh
make hooks
```

The `pre-commit` hook scans the staged diff for credentials and internal
identifiers. The `commit-msg` hook scans the message of the commit that you are
making, and the names and text of the staged files, with the deny rules. The
`pre-push` hook runs the whole-tree gates and scans every commit message and
file name that you are about to push.

## Releasing

Only the RunOS team releases. The release tool stays in the open: you can read
every step and every check.

Two branches record what shipped, and both move by fast-forward only after the
release is verified. `deployed` holds the last commit that was tagged, a
candidate or a final. `main` is the prod record: a final fast-forwards it to the
commit its tag names, and a candidate never moves it. A final is refused before
the tag when `main` is not an ancestor of `dev`. `scripts/record-release.sh`
holds the rule.

A release goes in these steps:

1. Land the change on `dev` by pull request. Set `VERSION` to the base version
   and add a `## v<version>` section to `CHANGELOG.md` in plain words.
2. Run the gates without any side effect:

   ```sh
   scripts/release-check.sh v1.2.3-rc.1
   ```

3. Cut a release candidate, `v<version>-rc.<n>`, from the tip of `dev`. Prove it
   where it will run. `VERSION` holds the base version, so a candidate and its
   final come from one commit.
4. Cut the final, `v<version>`, from the commit that the candidate shipped.

The tag starts the release workflow. The workflow checks the tag against
`VERSION`, checks that `CHANGELOG.md` has a section for the base version, runs
the gates again, builds and pushes `ghcr.io/runos-official/rolekeeper` for
linux/amd64 and linux/arm64, and attests the image. A candidate is never tagged
`latest`. Other RunOS code imports the Go packages by tag, so a tag is also a
Go module version: it never moves and it is never deleted.

Read the digest of a published tag from the registry with:

```sh
scripts/image-digest.sh 1.2.3
```
