#!/usr/bin/env bash
#
# Read a published rolekeeper image back from the registry and print what it
# is. Read only: it asks the public registry for the manifest of one tag and
# changes nothing. No credential is used.
#
#   scripts/image-digest.sh 1.2.3          or v1.2.3, or 1.2.3-rc.1, or latest
#
# Prints these lines:
#   image: ghcr.io/runos-official/rolekeeper:<tag>
#   digest: sha256:<64 hex>               the digest of the multi-platform index
#   platforms: linux/amd64,linux/arm64
#   reference: ghcr.io/runos-official/rolekeeper:<tag>@sha256:<64 hex>
#
# The digest is also recomputed from the bytes of the manifest. A registry
# answer that does not match its own digest header is an error.
#
# It also reports to Foreman (see foreman-observe.sh): the facts image, digest,
# platforms and version, and one summary line. They are plain lines that start
# with "::foreman::", so a person can ignore them.
#
# Settings (environment):
#   REQUIRE_PLATFORMS   comma list that the index must hold (default: linux/amd64,linux/arm64)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=foreman-observe.sh
source "$HERE/foreman-observe.sh"
# shellcheck source=foreman-observe-facts.sh
source "$HERE/foreman-observe-facts.sh"

REPO="runos-official/rolekeeper"
IMAGE="ghcr.io/${REPO}"
REQUIRE="${REQUIRE_PLATFORMS:-linux/amd64,linux/arm64}"
TAG="${1:-}"
[[ -n "$TAG" ]] || { echo "usage: scripts/image-digest.sh <version>" >&2; exit 2; }
VERSION="$TAG"
[[ "$TAG" == "latest" ]] || TAG="${TAG#v}"

fail() {
  printf '%s\n' "$1" >&2
  fm_fact version "$VERSION"
  fm_summary "cannot read ${IMAGE}:${TAG}: $1"
  exit 1
}

for tool in curl python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "required tool not found: $tool" >&2; exit 2; }
done

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

token="$(curl -fsS -m 30 "https://ghcr.io/token?scope=repository:${REPO}:pull" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')" \
  || fail "no pull token from the registry"

curl -fsS -m 30 -D "$tmp/headers" -o "$tmp/manifest" \
  -H "Authorization: Bearer ${token}" \
  -H "Accept: application/vnd.oci.image.index.v1+json" \
  "https://ghcr.io/v2/${REPO}/manifests/${TAG}" \
  || fail "the registry has no manifest for the tag"

rc=0
out="$(python3 - "$tmp/headers" "$tmp/manifest" "$IMAGE" "$TAG" "$REQUIRE" <<'PY'
import hashlib, json, sys

headers, manifest, image, tag, require = sys.argv[1:6]
header_digest = None
with open(headers, encoding="utf-8", errors="replace") as fh:
    for line in fh:
        name, _, value = line.partition(":")
        if name.strip().lower() == "docker-content-digest":
            header_digest = value.strip()
raw = open(manifest, "rb").read()
computed = "sha256:" + hashlib.sha256(raw).hexdigest()
if header_digest and header_digest != computed:
    sys.exit("the registry digest %s does not match the manifest bytes %s" % (header_digest, computed))
doc = json.loads(raw)
if doc.get("mediaType") != "application/vnd.oci.image.index.v1+json":
    sys.exit("%s:%s is not a multi-platform index (mediaType %s)" % (image, tag, doc.get("mediaType")))
platforms = []
for m in doc.get("manifests", []):
    p = m.get("platform") or {}
    # Attestation and bill-of-materials entries are listed as unknown/unknown.
    if p.get("os") in (None, "unknown") or p.get("architecture") in (None, "unknown"):
        continue
    platforms.append("%s/%s" % (p["os"], p["architecture"]))
platforms = sorted(set(platforms))
missing = [p for p in require.split(",") if p and p not in platforms]
print("image: %s:%s" % (image, tag))
print("digest: %s" % computed)
print("platforms: %s" % ",".join(platforms))
print("reference: %s:%s@%s" % (image, tag, computed))
if missing:
    sys.exit("the index lacks platform(s): %s" % ",".join(missing))
PY
)" || rc=$?

# The four lines are the output of this script; the facts repeat them.
printf '%s\n' "$out"
value() { printf '%s\n' "$out" | sed -n "s/^$1: //p"; }
fm_fact image "${IMAGE}:${TAG}"
digest="$(value digest)"; platforms="$(value platforms)"
fm_fact digest "${digest:-unavailable}"
fm_fact platforms "${platforms:-unavailable}"
fm_fact version "$VERSION"
if [[ "$rc" -ne 0 ]]; then
  fm_summary "${IMAGE}:${TAG} is not a complete multi-platform image (platforms: ${platforms:-none})"
  exit "$rc"
fi
fm_summary "${IMAGE}:${TAG} is ${digest} on ${platforms}"
