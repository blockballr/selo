#!/bin/sh
# Assemble installable plugin directories under dist/.
#
# Builds the wasm32-wasip2 components, then pairs each cargo artifact with its
# crate's manifest.toml. Note the output wasm is named after the crate, not read
# from the manifest's wasm_path: the two agree today by convention rather than by
# construction, and a manifest whose wasm_path diverges would produce a plugin
# directory the host cannot load. The check below catches that.
set -eu

cd "$(dirname "$0")/.."

# Start from nothing. Without this, a plugin directory left by an earlier run
# survives after its crate is deleted from the workspace, and dist/ ships a
# plugin whose source no longer exists. That is exactly what happened when the
# Twilio channel crate was removed.
rm -rf dist

cargo build --release --target wasm32-wasip2

# The plugin crates each vendor their own copy of the ZeroClaw WIT. They were
# byte-identical when there were three of them, and nothing enforced it. Deleting
# one dropped the accidental cross-check, so it is made explicit here: a contract
# that has silently drifted between crates is a rebuild that fails at the
# component boundary rather than at the build.
diff -r crates/solana-compressed-accounts/wit crates/daybook-shop/wit >/dev/null \
    || { echo "vendored wit/ copies have diverged between plugin crates" >&2; exit 1; }

for crate in solana-compressed-accounts daybook-shop; do
    artifact="target/wasm32-wasip2/release/$(echo "$crate" | tr '-' '_').wasm"
    out="dist/$crate"
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
done
