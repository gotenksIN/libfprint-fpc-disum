#!/usr/bin/env bash
set -euo pipefail

input=${1:?usage: collect-release.sh ARTIFACT_DIR RELEASE_DIR}
output=${2:?usage: collect-release.sh ARTIFACT_DIR RELEASE_DIR}
mkdir -p "$output"

while IFS= read -r file; do
  basename=$(basename "$file")
  [[ ! -e "$output/$basename" ]] || {
    printf 'Duplicate artifact: %s\n' "$basename" >&2
    exit 1
  }
  cp "$file" "$output/$basename"
done < <(find "$input" -type f \( -name '*.deb' -o -name '*.pkg.tar.*' \) | LC_ALL=C sort)

[[ $(find "$output" -maxdepth 1 -name '*.deb' | wc -l) -eq 1 ]]

(
  cd "$output"
  mapfile -t files < <(
    find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%f\n' |
      LC_ALL=C sort
  )
  sha256sum "${files[@]}" > SHA256SUMS
)
