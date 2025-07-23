#!/bin/bash

preparation() {
    # Setup td-shim
    pushd deps/td-shim
    bash sh_script/preparation.sh
    popd
    
    # Apply TOML nostd patches
    bash src/policy/patch-toml-nostd.sh
}

preparation
