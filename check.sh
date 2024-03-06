#!/bin/bash
cargo wasm
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cosmwasm-check $SCRIPT_DIR/target/wasm32-unknown-unknown/release/*.wasm
