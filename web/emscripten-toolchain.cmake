# Emscripten toolchain for Windham — auto-detect
#
# Detection order:
#   1. $EMSDK/upstream/emscripten/emcc (emsdk env)
#   2. emcc on PATH (system install)
#
# Usage:
#   cmake -B build/web -DCMAKE_TOOLCHAIN_FILE=web/emscripten-toolchain.cmake
#   cmake --build build/web
#   # -> build/web/windham.js
#
# Or shortcut via emcmake wrapper:
#   emcmake cmake -B build/web -S .

set(CMAKE_SYSTEM_NAME Emscripten)
set(CMAKE_SYSTEM_PROCESSOR wasm32)

# --- Compiler ---
if(NOT DEFINED EMSCRIPTEN_CC)
    # 1. emsdk environment
    if(DEFINED ENV{EMSDK})
        set(_emsdk_emcc "$ENV{EMSDK}/upstream/emscripten/emcc")
        if(EXISTS "${_emsdk_emcc}")
            set(EMSCRIPTEN_CC "${_emsdk_emcc}")
        endif()
    endif()

    # 2. emcc on PATH
    if(NOT DEFINED EMSCRIPTEN_CC)
        find_program(EMSCRIPTEN_CC emcc)
    endif()

    if(NOT EMSCRIPTEN_CC OR EMSCRIPTEN_CC STREQUAL "EMSCRIPTEN_CC-NOTFOUND")
        message(FATAL_ERROR
            "No Emscripten compiler (emcc) found.\n"
            "  1. Install emsdk: https://emscripten.org/docs/getting_started/downloads.html\n"
            "  2. source emsdk_env.sh\n"
            "  3. Or: cmake -DEMSCRIPTEN_CC=/path/to/emcc ...")
    endif()
endif()
message(STATUS "Emscripten compiler: ${EMSCRIPTEN_CC}")
set(CMAKE_C_COMPILER "${EMSCRIPTEN_CC}")

set(CMAKE_EXECUTABLE_SUFFIX ".js")

# --- Emscripten linker/compiler flags ---
# ASYNCIFY must be a compile flag (instrumentation); the rest are linker-only.
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -s ASYNCIFY=1")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -s ASYNCIFY=1 -s ASSERTIONS=2")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -s ALLOW_MEMORY_GROWTH=1")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -s INITIAL_MEMORY=64MB -s STACK_SIZE=4MB -s MAXIMUM_MEMORY=2GB")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -s FORCE_FILESYSTEM=1")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -s EXPORTED_RUNTIME_METHODS=['ccall','cwrap','FS','callMain']")

# --- Feature flags ---
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

# wasm32 has 4GB address space; override Argon2's conservative 21-bit default
add_compile_definitions(ARGON2_MAX_MEMORY_BITS=32)
