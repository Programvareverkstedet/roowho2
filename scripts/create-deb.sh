#!/usr/bin/env bash

set -euo pipefail

declare -r RUST_PROFILE="releaselto"

if [[ "${CREATE_DEB_DEBUG:-}" == "1" ]]; then
  set -x
fi

if ! command -v cargo &> /dev/null; then
  echo "cargo could not be found" >&2
  exit 1
fi

if ! command -v cargo-deb &> /dev/null; then
  echo "cargo-deb could not be found" >&2
  exit 1
fi

cargo build --profile "$RUST_PROFILE"

mkdir -p assets/completions

for bin in finger ruptime rwho; do
  (
    PATH="./target/$RUST_PROFILE:$PATH"

    "$bin" --completions=bash > "assets/completions/$bin.bash"
    "$bin" --completions=zsh > "assets/completions/_$bin"
    "$bin" --completions=fish > "assets/completions/$bin.fish"
  )
done

DEFAULT_CARGO_DEB_ARGS=(
  --profile "$RUST_PROFILE"
  --no-build
)

cargo deb "${DEFAULT_CARGO_DEB_ARGS[@]}" "$@"
