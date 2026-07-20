# WASI toolchain for Windham
#
# Auto-detects wasi-sdk (GitHub release) and Homebrew wasi-libc.
# Override with:
#   cmake -B build/wasi -DWASI_CC=/path/to/clang \
#         -DWASI_SYSROOT=/path/to/sysroot \
#         -DCMAKE_TOOLCHAIN_FILE=cmake/wasi-toolchain.cmake
#
# Usage:
#   cmake -B build/wasi -DCMAKE_TOOLCHAIN_FILE=cmake/wasi-toolchain.cmake
#   cmake --build build/wasi
#
# Output: build/wasi/windham.wasm

set(CMAKE_SYSTEM_NAME WASI)
set(CMAKE_SYSTEM_VERSION 1)
set(CMAKE_SYSTEM_PROCESSOR wasm32)

# ── Compiler ────────────────────────────────────────────────────
if(NOT DEFINED WASI_CC)
    # 1. Try wasi-sdk release (manual download to /tmp)
    set(_wasi_sdk_pattern "/tmp/wasi-sdk-*-arm64-macos")
    file(GLOB _wasi_sdk_candidates ${_wasi_sdk_pattern})
    if(_wasi_sdk_candidates)
        list(GET _wasi_sdk_candidates 0 _wasi_sdk_dir)
        set(WASI_CC "${_wasi_sdk_dir}/bin/clang")
    else()
        # 2. Try Homebrew wasm32-wasi-clang (from emscripten/llvm)
        find_program(WASI_CC_FOUND wasm32-wasi-clang)
        if(WASI_CC_FOUND)
            set(WASI_CC "${WASI_CC_FOUND}")
        else()
            message(FATAL_ERROR
                "No WASI compiler found.\n"
                "  Option A: download wasi-sdk from https://github.com/WebAssembly/wasi-sdk/releases\n"
                "            and extract to /tmp\n"
                "  Option B: brew install emscripten && brew install wasi-libc\n"
                "  Option C: set -DWASI_CC=/path/to/clang")
        endif()
    endif()
endif()
message(STATUS "WASI compiler: ${WASI_CC}")
set(CMAKE_C_COMPILER "${WASI_CC}")
set(CMAKE_C_COMPILER_TARGET wasm32-wasip1)

# ── Sysroot ─────────────────────────────────────────────────────
if(NOT DEFINED WASI_SYSROOT)
    # 1. wasi-sdk release has sysroot inside its tree
    if(DEFINED _wasi_sdk_dir AND EXISTS "${_wasi_sdk_dir}/share/wasi-sysroot")
        set(WASI_SYSROOT "${_wasi_sdk_dir}/share/wasi-sysroot")
    # 2. Homebrew wasi-libc
    elseif(APPLE AND EXISTS "/opt/homebrew/opt/wasi-libc/share/wasi-sysroot")
        set(WASI_SYSROOT "/opt/homebrew/opt/wasi-libc/share/wasi-sysroot")
    elseif(APPLE AND EXISTS "/usr/local/opt/wasi-libc/share/wasi-sysroot")
        set(WASI_SYSROOT "/usr/local/opt/wasi-libc/share/wasi-sysroot")
    else()
        message(FATAL_ERROR
            "WASI sysroot not found.\n"
            "  Option A: brew install wasi-libc\n"
            "  Option B: download wasi-sdk to /tmp\n"
            "  Option C: set -DWASI_SYSROOT=/path/to/wasi-sysroot")
    endif()
endif()
message(STATUS "WASI sysroot: ${WASI_SYSROOT}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --sysroot=${WASI_SYSROOT}")

set(CMAKE_EXECUTABLE_SUFFIX ".wasm")

# ── WASI feature flags ──────────────────────────────────────────
set(WINDHAM_NO_ISOC_THREAD ON CACHE BOOL "" FORCE)
set(CFG_NO_MODULE_KEYRING ON CACHE BOOL "" FORCE)
set(WINDHAM_NO_SECCOMP ON CACHE BOOL "" FORCE)
set(WINDHAM_NO_DISABLE_ATTACH ON CACHE BOOL "" FORCE)
set(WINDHAM_NO_ENFORCE_SPEC_MITIGATION ON CACHE BOOL "" FORCE)
set(WINDHAM_NO_SHEBANG_ENTRY ON CACHE BOOL "" FORCE)
set(CFG_DRIVER_FF ON CACHE BOOL "" FORCE)
set(CFG_FF_CREATE ON CACHE BOOL "" FORCE)
set(CFG_DRIVER_DECRYPT ON CACHE BOOL "" FORCE)

add_compile_definitions(WINDHAM_PLAT_WASI)
add_compile_definitions(WINDHAM_NO_ISOC_THREAD)
add_compile_definitions(CFG_NO_MODULE_KEYRING)
add_compile_definitions(WINDHAM_NO_SECCOMP)
add_compile_definitions(WINDHAM_NO_DISABLE_ATTACH)
add_compile_definitions(WINDHAM_NO_ENFORCE_SPEC_MITIGATION)
add_compile_definitions(WINDHAM_NO_SHEBANG_ENTRY)
