#!/usr/bin/env bash
#
# Print what a release left behind, for a person or an agent to judge. It only
# reads (git, the GitHub API through gh, the public registry), prints no
# pass or fail word and always exits 0.
#
#   scripts/release-evidence.sh v1.2.3 [output-file]
#
# It reports to Foreman (see foreman-observe.sh): the facts version, new_commit
# (the commit that the tag names), previous_commit (the commit of the release
# before it), workflow_run_url, conclusion, image, digest, platforms and
# evidence (the output file), and one summary line. A fact that cannot be read
# is "unavailable" and never stops the script.
set -uo pipefail

TAG="${1:-}"
FILE="${2:-}"
[[ -n "$TAG" ]] || { echo "usage: scripts/release-evidence.sh vX.Y.Z[-rc.N] [file]" >&2; exit 0; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=foreman-observe.sh
source "$HERE/foreman-observe.sh"
# shellcheck source=foreman-observe-facts.sh
source "$HERE/foreman-observe-facts.sh"

cd "$HERE/.." || exit 0

evidence() {
  local new_commit previous_commit url conclusion image_out
  echo "== tag"
  echo "tag: $TAG"
  echo "local tag commit: $(git rev-parse "$TAG^{commit}" 2>&1)"
  echo "origin tag commit: $(git ls-remote origin "refs/tags/$TAG^{}" "refs/tags/$TAG" 2>&1 | tail -1 | cut -f1)"
  new_commit="$(git rev-parse --short=12 "$TAG^{commit}" 2>/dev/null)" || new_commit=""
  # The release before this one: the nearest tag that is older than the tagged commit.
  previous_commit="$(git rev-parse --short=12 "$(git describe --tags --abbrev=0 --match 'v*' "$TAG^{commit}^" 2>/dev/null)^{commit}" 2>/dev/null)" || previous_commit=""
  echo "== record branches on origin (deployed: last tagged; main: the prod record, moved by a final)"
  git ls-remote origin refs/heads/deployed refs/heads/main 2>&1
  echo "== source record"
  grep -E '^(source|commit|files|exporter):' SOURCE 2>&1
  echo "== workflow run"
  url="unavailable"; conclusion="unavailable"
  run_id="$(gh run list --workflow=release.yml --limit 20 --json databaseId,headBranch,event \
    -q "[.[] | select(.headBranch==\"$TAG\" and .event==\"push\")][0].databaseId" 2>&1)"
  if [[ "$run_id" =~ ^[0-9]+$ ]]; then
    gh run view "$run_id" --json url,status,conclusion,createdAt,updatedAt 2>&1
    echo "-- jobs and steps"
    gh run view "$run_id" --json jobs \
      -q '.jobs[] | "job \(.name): \(.status) \(.conclusion)", (.steps[] | "  step \(.number) \(.name): \(.conclusion)")' 2>&1
    url="$(gh run view "$run_id" --json url -q .url 2>/dev/null)" || url=""
    conclusion="$(gh run view "$run_id" --json conclusion,status -q '.conclusion // .status' 2>/dev/null)" || conclusion=""
  else
    echo "no workflow run found for $TAG: $run_id"
  fi
  echo "== registry"
  image_out="$(bash "$HERE/image-digest.sh" "$TAG" 2>&1)"
  # The plain lines are the evidence; the facts of this script come below.
  printf '%s\n' "$image_out" | grep -v '^::foreman'
  case "$TAG" in
    *-*) echo "candidate: the latest tag is not moved by a candidate" ;;
    *)
      echo "-- latest"
      bash "$HERE/image-digest.sh" latest 2>&1 | grep -E '^(digest|platforms):'
      echo "note: a candidate and its final are built by separate workflow runs, so their digests differ. Pin the digest of the final."
      ;;
  esac
  value() { printf '%s\n' "$image_out" | sed -n "s/^$1: //p"; }
  local digest platforms
  digest="$(value digest)"; platforms="$(value platforms)"
  fm_fact version "$TAG"
  fm_fact new_commit "${new_commit:-unavailable}"
  fm_fact previous_commit "${previous_commit:-none}"
  fm_fact workflow_run_url "${url:-unavailable}"
  fm_fact conclusion "${conclusion:-unavailable}"
  fm_fact image "ghcr.io/runos-official/rolekeeper:${TAG#v}"
  fm_fact digest "${digest:-unavailable}"
  fm_fact platforms "${platforms:-unavailable}"
  fm_fact evidence "${FILE:-output}"
  fm_summary "collected release evidence for $TAG: workflow ${conclusion:-unavailable}, image ${digest:-unavailable}"
}

if [[ -n "$FILE" ]]; then
  evidence | tee "$FILE"
else
  evidence
fi
exit 0
