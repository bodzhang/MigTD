// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

fn main() {
    // The TOML nostd patch is now applied during the preparation phase (sh_script/preparation.sh)
    // instead of during build. This ensures consistent setup and avoids build-time patching.
    
    // Tell cargo to rerun if the toml submodule changes
    println!("cargo:rerun-if-changed=../../deps/toml-nostd");
}
