# WASI toolchain for Windham
#
# Auto-detects Homebrew paths.  Override with:
#   cmake -B build/wasi -DWASI_CC=/path/to/clang \
#         -DWASI_SYSROOT=/path/to/sysroot \
#         -DCMAKE_TOOLCHAIN_FILE=cmake/wasi-toolchain.cmake
#
# Output: build/wasi/windham.wasm

set(CMAKE_SYSTEM_NAME WASI)
set(CMAKE_SYSTEM_VERSION 1)
set(CMAKE_SYSTEM_PROCESSOR wasm32)

# ── Compiler ────────────────────────────────────────────────────
if(NOT DEFINED WASI_CC)
    # Homebrew (emscripten LLVM) provides wasm32-wasi-clang on PATH
    find_program(WASI_CC_FOUND wasm32-wasi-clang)
    if(WASI_CC_FOUND)
        set(WASI_CC "${WASI_CC_FOUND}")
    else()
        message(FATAL_ERROR
            "wasm32-wasi-clang not found. Install emscripten or llvm via brew, "
            "or set -DWASI_CC=/path/to/clang")
    endif()
endif()
set(CMAKE_C_COMPILER "${WASI_CC}")
set(CMAKE_C_COMPILER_TARGET wasm32-wasip1)

# ── Sysroot ─────────────────────────────────────────────────────
if(NOT DEFINED WASI_SYSROOT)
    # Homebrew wasi-libc provides the sysroot
    if(APPLE AND EXISTS "/opt/homebrew/opt/wasi-libc/share/wasi-sysroot")
        set(WASI_SYSROOT "/opt/homebrew/opt/wasi-libc/share/wasi-sysroot")
    elseif(APPLE AND EXISTS "/usr/local/opt/wasi-libc/share/wasi-sysroot")
        set(WASI_SYSROOT "/usr/local/opt/wasi-libc/share/wasi-sysroot")
    else()
        message(FATAL_ERROR
            "WASI sysroot not found. Install wasi-libc via brew, "
            "or set -DWASI_SYSROOT=/path/to/wasi-sysroot")
    endif()
endif()
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --sysroot=${WASI_SYSROOT}")

set(CMAKE_EXECUTABLE_SUFFIX ".wasm")

# ── WASI feature flags ──────────────────────────────────────────
# No threads, no kernel keyring, no seccomp, no ptrace
set(WINDHAM_NO_ISOC_THREAD ON CACHE BOOL "" FORCE)
set(CFG_NO_MODULE_KEYRING ON CACHE BOOL "" FORCE)
set(WINDHAM_NO_SECCOMP ON CACHE BOOL "" FORCE)
set(WINDHAM_NO_DISABLE_ATTACH ON CACHE BOOL "" FORCE)
set(WINDHAM_NO_ENFORCE_SPEC_MITIGATION ON CACHE BOOL "" FORCE)
set(WINDHAM_NO_SHEBANG_ENTRY ON CACHE BOOL "" FORCE)

# WASI driver set — file-based, no dm-crypt
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
