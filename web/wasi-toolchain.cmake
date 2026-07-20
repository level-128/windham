# WASI toolchain for Windham — cross-platform
#
# Detection order:
#   1. $WASI_SDK environment variable
#   2. cmake -DWASI_SDK=/path/to/wasi-sdk
#   3. wasm32-wasi-clang on PATH (Homebrew / distro packages)
#   4. clang with wasm32-wasip1 target
#
# Usage:
#   cmake -B build/wasi -DCMAKE_TOOLCHAIN_FILE=web/wasi-toolchain.cmake
#   cmake --build build/wasi
#   # → build/wasi/windham.wasm

set(CMAKE_SYSTEM_NAME WASI)
set(CMAKE_SYSTEM_VERSION 1)
set(CMAKE_SYSTEM_PROCESSOR wasm32)

# ── Compiler ────────────────────────────────────────────────────
if(NOT DEFINED WASI_CC)
    # WASI_SDK env var or cmake variable
    if(DEFINED ENV{WASI_SDK})
        set(_wasi_sdk_hint "$ENV{WASI_SDK}")
    elseif(DEFINED WASI_SDK)
        set(_wasi_sdk_hint "${WASI_SDK}")
    endif()

    if(DEFINED _wasi_sdk_hint AND EXISTS "${_wasi_sdk_hint}/bin/clang")
        set(WASI_CC "${_wasi_sdk_hint}/bin/clang")
        set(_wasi_sdk_dir "${_wasi_sdk_hint}")
    endif()

    if(NOT DEFINED WASI_CC OR WASI_CC STREQUAL "WASI_CC-NOTFOUND")
        message(FATAL_ERROR
            "No WASI compiler found.\n"
            "  1. Download wasi-sdk: https://github.com/WebAssembly/wasi-sdk/releases\n"
            "  2. Extract it (e.g. to ~/wasi-sdk)\n"
            "  3. export WASI_SDK=~/wasi-sdk\n"
            "     or: cmake -DWASI_SDK=~/wasi-sdk ...")
    endif()
endif()
message(STATUS "WASI compiler: ${WASI_CC}")
set(CMAKE_C_COMPILER "${WASI_CC}")
set(CMAKE_C_COMPILER_TARGET wasm32-wasip1)

# ── Sysroot ─────────────────────────────────────────────────────
if(NOT DEFINED WASI_SYSROOT)
    # 1. wasi-sdk tree: <sdk>/share/wasi-sysroot
    if(DEFINED _wasi_sdk_dir AND EXISTS "${_wasi_sdk_dir}/share/wasi-sysroot")
        set(WASI_SYSROOT "${_wasi_sdk_dir}/share/wasi-sysroot")
    # 2. Common package manager paths for wasi-libc
    else()
        find_path(WASI_SYSROOT
            NAMES include/wasi/api.h include/wasm32-wasip1/wasi/api.h
            PATHS
                /opt/homebrew/opt/wasi-libc/share/wasi-sysroot
                /usr/local/opt/wasi-libc/share/wasi-sysroot
                /usr/share/wasi-sysroot
                /usr/lib/wasi-sysroot
            NO_DEFAULT_PATH
        )
    endif()

    if(NOT WASI_SYSROOT OR WASI_SYSROOT STREQUAL "WASI_SYSROOT-NOTFOUND")
        message(FATAL_ERROR
            "WASI sysroot not found.\n"
            "  macOS: brew install wasi-libc\n"
            "  Linux: install wasi-libc package\n"
            "  Or:    cmake -DWASI_SYSROOT=/path/to/wasi-sysroot ...")
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
