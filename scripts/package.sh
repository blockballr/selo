#!/bin/sh
# Build the wasm32-wasip2 component and pair it with its manifest under dist/.
set -eu

cd "$(dirname "$0")/.."

# A stale plugin dir survives its crate otherwise. Has bitten twice.
rm -rf dist

cargo build --release --target wasm32-wasip2

crate=selo-tool
artifact="target/wasm32-wasip2/release/$(echo "$crate" | tr '-' '_').wasm"
out="dist/$crate"

# The packager names the output after the crate; the manifest declares it
# separately. They agree by convention, so check rather than assume.
declared=$(sed -n 's/^wasm_path[[:space:]]*=[[:space:]]*"\(.*\)"[[:space:]]*$/\1/p' \
    "crates/$crate/manifest.toml")
if [ "$declared" != "$crate.wasm" ]; then
    echo "$crate: manifest wasm_path is '$declared', packager writes '$crate.wasm'" >&2
    exit 1
fi

mkdir -p "$out"
cp "crates/$crate/manifest.toml" "$out/manifest.toml"
cp "$artifact" "$out/$crate.wasm"
echo "packaged $out"
