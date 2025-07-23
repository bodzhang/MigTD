# TOML no_std Patch for MigTD

This directory contains a Git submodule pointing to the official toml-rs/toml repository at tag `toml-v0.9.2`.

## Why This is Needed

The official `toml` crate version 0.9.2 uses `f64::copysign()` method in its serialization code, which is not available in `no_std` environments (specifically the `x86_64-unknown-none` target used by MigTD).

## How It Works

1. **Submodule**: `deps/toml-nostd` is a Git submodule pointing to https://github.com/toml-rs/toml.git at tag `toml-v0.9.2`
2. **Patch Script**: `src/policy/patch-toml-nostd.sh` automatically applies patches to make the toml crate compatible with no_std
3. **Build Integration**: The patch is automatically applied when building the policy crate for any target via `src/policy/build.rs`

## What the Patch Does

The patch script makes these changes to `deps/toml-nostd/crates/toml/`:

1. **Adds libm dependency** to `Cargo.toml` for no_std math functions
2. **Fixes workspace references** to make the crate standalone
3. **Replaces path dependencies** with published crate versions
4. **Adds copysign helper function** that uses `libm::copysign` in no_std and `f64::copysign` in std
5. **Updates the serialize_f64 function** to use the helper instead of the std method

This creates a uniform TOML package that works across all targets, providing consistent behavior whether building for std or no_std environments.

## Usage

The patch is applied automatically when building the policy crate for any target:
```bash
cargo build -p policy
# or
cargo build -p policy --target x86_64-unknown-none
# or
cargo image
```

This ensures uniform TOML behavior across all build configurations.

You can also manually apply the patch:
```bash
cd src/policy
./patch-toml-nostd.sh
```

## Updating the Submodule

To update to a newer version of the toml crate:

1. Update the submodule to the desired tag:
   ```bash
   cd deps/toml-nostd
   git checkout <new-tag>
   cd ../..
   git add deps/toml-nostd
   git commit -m "Update toml submodule to <new-tag>"
   ```

2. Test that the patch still works:
   ```bash
   cd src/policy
   ./patch-toml-nostd.sh
   cargo check -p policy --target x86_64-unknown-none
   ```

3. Update the patch script if needed for the new version

## Implementation Details

The automatic patching is implemented in `src/policy/build.rs`, which:
- Runs for all targets to ensure uniform TOML behavior
- Executes the local patch script `src/policy/patch-toml-nostd.sh`
- Fails the build if the patch script fails
- Tells cargo to rerun if the patch script or toml submodule changes

This approach provides a consistent TOML implementation while preparing for future upstream fixes.

## Files

- `deps/toml-nostd/` - Git submodule pointing to toml-rs/toml at tag toml-v0.9.2
- `src/policy/patch-toml-nostd.sh` - Script that applies the no_std compatibility patches
- `src/policy/build.rs` - Build script that automatically applies the patch
- `Cargo.toml` - Contains the patch directive to use the local toml version
