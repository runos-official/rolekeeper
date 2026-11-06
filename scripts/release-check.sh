#!/usr/bin/env bash
#
# rolekeeper release gates. They run every check that a release needs and have
# no side effect: no tag, no push, no network write.
#
#   scripts/release-check.sh v1.2.3-rc.1    a release candidate
#   scripts/release-check.sh v1.2.3         the final release
#
# Settings (environment):
#   RELEASE_BRANCH         the branch that is released (default: dev)
#   RELEASE_RECORD_BRANCH  the branch that records what has shipped (default: deployed)
#
# It reports to Foreman (see foreman-observe.sh): the facts version,
# previous_commit (the record branch on origin before this release) and
# new_commit (the commit that is released), and one summary line.
#
# A tag is v<base> for a final or v<base>-rc.<n> for a candidate. VERSION holds
# the base, so a candidate and its final come from one commit.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=foreman-observe.sh
source "$HERE/foreman-observe.sh"
# shellcheck source=foreman-observe-facts.sh
source "$HERE/foreman-observe-facts.sh"

BRANCH="${RELEASE_BRANCH:-dev}"
RECORD="${RELEASE_RECORD_BRANCH:-deployed}"
TAG="${1:-}"

step() { printf '==> %s\n' "$1"; }
ok()   { printf ' ok %s\n' "$1"; }
die()  { printf 'FAIL %s\n' "$1" >&2; fm_summary "release gates failed for ${TAG:-no tag}: $1"; exit 1; }

[[ -n "$TAG" ]] || die "usage: scripts/release-check.sh vX.Y.Z[-rc.N]"
[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$ ]] || die "tag must look like v1.2.3 or v1.2.3-rc.1 (got '$TAG')"
BASE="${TAG#v}"
BASE="${BASE%%-*}"

cd "$HERE/.."

step "Preflight ($TAG)"
for tool in git go gofmt python3; do
  command -v "$tool" >/dev/null 2>&1 || die "required tool not found: $tool"
done
git rev-parse --git-dir >/dev/null 2>&1 || die "not inside a git repository"

fm_fact version "$TAG"
fm_fact new_commit "$(git rev-parse --short=12 HEAD)"
# Read only: the record branch on origin, or "none" before the first release.
previous="$(git ls-remote origin "refs/heads/$RECORD" 2>/dev/null | cut -c1-12)" || previous=""
fm_fact previous_commit "${previous:-none}"

[[ "$(tr -d '[:space:]' < VERSION)" == "$BASE" ]] || die "VERSION is '$(tr -d '[:space:]' < VERSION)' but $TAG has base version $BASE"
ok "VERSION is $BASE"

# The workflow cuts the release notes from this section and the section must
# say something, so an empty heading fails here and not after the tag is pushed.
body="$(awk -v h="## v${BASE}" '$0 == h { f = 1; next } f && /^## / { exit } f && NF { print }' CHANGELOG.md)"
[[ -n "$body" ]] || die "CHANGELOG.md has no section '## v${BASE}', or the section is empty"
ok "CHANGELOG has a section for v${BASE}"

if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
  die "tag $TAG already exists locally"
fi
git fetch --quiet --tags origin "$BRANCH"
if git ls-remote --exit-code --tags origin "refs/tags/$TAG" >/dev/null 2>&1; then
  die "tag $TAG already exists on origin"
fi
ok "tag $TAG is free"

[[ -z "$(git status --porcelain)" ]] || die "working tree is not clean"
[[ "$(git rev-parse HEAD)" == "$(git rev-parse "origin/$BRANCH")" ]] || die "HEAD is not the tip of origin/$BRANCH"
ok "clean tree at the tip of origin/$BRANCH"

step "Source record"
python3 scripts/treehash.py --check || die "the files do not match SOURCE: regenerate them from the RunOS source, do not edit them here"

step "Leak gates"
python3 scripts/leakcheck.py || die "leakcheck failed"
python3 scripts/unscannable_check.py || die "unscannable_check failed"
python3 scripts/denycheck.py || die "denycheck failed"

step "Build, vet, test"
[[ -z "$(gofmt -l .)" ]] || die "gofmt -l lists files: run gofmt"
ok "gofmt"
CGO_ENABLED=0 go build ./... || die "go build failed"
ok "go build"
go vet ./... || die "go vet failed"
ok "go vet"
CGO_ENABLED=1 go test -count=1 -race ./... || die "go test failed"
ok "go test"

printf 'All gates passed for %s. Nothing was tagged or pushed.\n' "$TAG"
fm_summary "all release gates passed for $TAG at $(git rev-parse --short=12 HEAD); nothing was tagged or pushed"
