#!/bin/bash
# Build windham for web browser (Emscripten + ASYNCIFY)
# Output: web/windham.js + web/windham.wasm
#
# ASYNCIFY allows the interactive shell to yield control to JS
# while waiting for stdin.  The wasm instance stays alive with
# the FAT filesystem mounted — no re-decryption per command.

set -e

FLAGS="-std=c11 -O3"
FLAGS="$FLAGS -DWINDHAM_PLAT_WASI"
FLAGS="$FLAGS -DWINDHAM_NO_ISOC_THREAD"
FLAGS="$FLAGS -DCFG_NO_MODULE_KEYRING"
FLAGS="$FLAGS -DWINDHAM_NO_SECCOMP"
FLAGS="$FLAGS -DWINDHAM_NO_DISABLE_ATTACH"
FLAGS="$FLAGS -DWINDHAM_NO_ENFORCE_SPEC_MITIGATION"
FLAGS="$FLAGS -DWINDHAM_NO_SHEBANG_ENTRY"
FLAGS="$FLAGS -DWINDHAM_USING_CMAKE=\"0.0.0\""
FLAGS="$FLAGS -DARGON2_NO_THREADS"
FLAGS="$FLAGS -DWINDHAM_VERSION=\"web\""

EMFLAGS="-s WASM=1"
EMFLAGS="$EMFLAGS -s ASYNCIFY=1"
EMFLAGS="$EMFLAGS -s ALLOW_MEMORY_GROWTH=1"
EMFLAGS="$EMFLAGS -s INITIAL_MEMORY=64MB"
EMFLAGS="$EMFLAGS -s MAXIMUM_MEMORY=512MB"
EMFLAGS="$EMFLAGS -s FORCE_FILESYSTEM=1"
EMFLAGS="$EMFLAGS -s EXPORTED_RUNTIME_METHODS=['ccall','cwrap','FS','callMain']"
EMFLAGS="$EMFLAGS -s EXPORTED_FUNCTIONS=['_main','_malloc','_free']"

cd "$(dirname "$0")/.."
emcc $FLAGS $EMFLAGS frontend.c -o web/windham.js

echo "Done: $(ls -lh web/windham.js web/windham.wasm | awk '{print $5, $NF}')"
