#!/bin/bash
# Script to patch the toml crate for no_std copysign support

set -e

# Path to the toml value.rs file
TOML_VALUE_FILE="deps/toml-nostd/crates/toml/src/value.rs"

# Check if we've already applied the patch
if grep -q "copysign_f64" "$TOML_VALUE_FILE"; then
    echo "Patch already applied to $TOML_VALUE_FILE"
    exit 0
fi

echo "Applying no_std copysign patch to $TOML_VALUE_FILE"

# 1. Add libm dependency to Cargo.toml
TOML_CARGO_FILE="deps/toml-nostd/crates/toml/Cargo.toml"
if ! grep -q "libm =" "$TOML_CARGO_FILE"; then
    echo "Adding libm dependency to $TOML_CARGO_FILE"
    # Find the [dependencies] section and add libm after the last dependency
    sed -i '/^foldhash = .*/a libm = { version = "0.2", default-features = false }' "$TOML_CARGO_FILE"
fi

# 2. Fix workspace references in Cargo.toml
sed -i 's/repository\.workspace = true/repository = "https:\/\/github.com\/toml-rs\/toml"/' "$TOML_CARGO_FILE"
sed -i 's/license\.workspace = true/license = "MIT OR Apache-2.0"/' "$TOML_CARGO_FILE"
sed -i 's/edition\.workspace = true/edition = "2021"/' "$TOML_CARGO_FILE"
sed -i 's/rust-version\.workspace = true/rust-version = "1.66"/' "$TOML_CARGO_FILE"
sed -i 's/include\.workspace = true/include = ["build.rs", "src\/**\/*", "Cargo.toml", "Cargo.lock", "LICENSE*", "README.md", "examples\/**\/*"]/' "$TOML_CARGO_FILE"

# Remove workspace lints reference
sed -i '/\[lints\]/,+1d' "$TOML_CARGO_FILE"

# 3. Replace path dependencies with published versions
sed -i 's/toml_parser = { version = "1.0.1", path = "..\/toml_parser"/toml_parser = { version = "1.0.1"/' "$TOML_CARGO_FILE"
sed -i 's/toml_datetime = { version = "0.7.0", path = "..\/toml_datetime"/toml_datetime = { version = "0.7.0"/' "$TOML_CARGO_FILE"
sed -i 's/toml_writer = { version = "1.0.2", path = "..\/toml_writer"/toml_writer = { version = "1.0.2"/' "$TOML_CARGO_FILE"
sed -i 's/serde_spanned = { version = "1.0.0", path = "..\/serde_spanned"/serde_spanned = { version = "1.0.0"/' "$TOML_CARGO_FILE"

# 4. Add copysign helper function to value.rs after the imports
sed -i '/pub use toml_datetime::{Date, Datetime, DatetimeParseError, Offset, Time};/a \\n// Helper function for copysign in no_std environments\n#[inline]\nfn copysign_f64(magnitude: f64, sign: f64) -> f64 {\n    #[cfg(feature = "std")]\n    {\n        magnitude.copysign(sign)\n    }\n    #[cfg(not(feature = "std"))]\n    {\n        libm::copysign(magnitude, sign)\n    }\n}' "$TOML_VALUE_FILE"

# 5. Replace the copysign usage in serialize_f64
sed -i 's/value = value\.copysign(1\.0);/value = copysign_f64(value, 1.0);/' "$TOML_VALUE_FILE"

echo "Patch applied successfully!"
