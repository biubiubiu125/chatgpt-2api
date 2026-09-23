#!/usr/bin/env bash
# Fail CI when VERSION already has a complete GitHub Release.
# Incomplete releases (missing update assets) can be deleted with --repair.
set -euo pipefail

repair=0
if [[ "${1:-}" == "--repair" ]]; then
  repair=1
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="$(tr -d '\r\n' < "${root}/VERSION")"
if [[ ! "${version}" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]]; then
  echo "VERSION must be x.y or x.y.z, got ${version}" >&2
  exit 1
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "gh is required to query GitHub Releases" >&2
  exit 1
fi

tag="v${version}"
view_err="$(mktemp)"
trap 'rm -f "${view_err}"' EXIT

set +e
assets="$(gh release view "${tag}" --json assets --jq '.assets[].name' 2>"${view_err}")"
view_rc=$?
set -e

if [[ "${view_rc}" -ne 0 ]]; then
  if grep -Eiq 'HTTP[[:space:]]*404|release not found' "${view_err}"; then
    echo "VERSION ${version} has no GitHub Release yet"
    exit 0
  fi
  cat "${view_err}" >&2
  echo "Failed to query GitHub Release ${tag}" >&2
  exit 1
fi
if printf '%s\n' "${assets}" | grep -Fxq 'chatgpt-2api-app.tar.gz' \
  && printf '%s\n' "${assets}" | grep -Fxq 'checksums.txt'; then
  echo "VERSION ${version} already has a complete GitHub Release; bump VERSION before pushing main" >&2
  exit 1
fi

if [[ "${repair}" == 1 ]]; then
  echo "Incomplete GitHub Release ${tag}; deleting so this run can republish"
  gh release delete "${tag}" --yes --cleanup-tag
  echo "Deleted incomplete ${tag}"
  exit 0
fi

echo "Incomplete GitHub Release ${tag}; release-bundle will replace it"
exit 0
