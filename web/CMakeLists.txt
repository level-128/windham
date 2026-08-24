cmake_minimum_required(VERSION 3.16)
project(windham-web C)
set(CMAKE_C_STANDARD 11)

set(CMAKE_EXECUTABLE_SUFFIX ".js")

set(WINDHAM_ROOT ${CMAKE_CURRENT_LIST_DIR}/..)

# --- Build type ---
set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type: Release, Debug, MinSizeRel")
set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Release" "Debug" "MinSizeRel")

option(WINDHAM_WEB_MINIFY "Minify windham.js with Closure Compiler (slower link)" ON)

# --- Version ---
file(READ "${WINDHAM_ROOT}/build_misc/version.txt" WINDHAM_VERSION)
string(STRIP "${WINDHAM_VERSION}" WINDHAM_VERSION)
add_compile_definitions(WINDHAM_VERSION=\"${WINDHAM_VERSION}\")
add_compile_definitions(CMAKE_HOST_ARCH=\"${CMAKE_HOST_SYSTEM_PROCESSOR}\")
add_compile_definitions(CMAKE_TARGET_ARCH=\"${CMAKE_SYSTEM_PROCESSOR}\")
add_compile_definitions(WINDHAM_USING_CMAKE=\"${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION}.${CMAKE_PATCH_VERSION}\")

# --- Emscripten flags ---
set(CMAKE_C_FLAGS           "${CMAKE_C_FLAGS}           -s ASYNCIFY=1")
set(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS}  -s ASYNCIFY=1")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -s ASYNCIFY_STACK_SIZE=65536")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -s ALLOW_MEMORY_GROWTH=1")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -s INITIAL_MEMORY=64MB -s STACK_SIZE=4MB -s MAXIMUM_MEMORY=2GB")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -s FORCE_FILESYSTEM=1")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -s EXPORTED_RUNTIME_METHODS=['FS','lengthBytesUTF8','stringToUTF8','HEAPU8','HEAP32','HEAPU32','wasmMemory']")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -s EXPORTED_FUNCTIONS=['_main','_malloc','_free']")

# --- Optimization ---
set(CMAKE_C_FLAGS_RELEASE              "${CMAKE_C_FLAGS_RELEASE} -O3 -flto")
set(CMAKE_C_FLAGS_MINSIZEREL           "${CMAKE_C_FLAGS_MINSIZEREL} -Oz -flto")
set(CMAKE_EXE_LINKER_FLAGS_RELEASE     "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -O3 -flto")
set(CMAKE_EXE_LINKER_FLAGS_MINSIZEREL  "${CMAKE_EXE_LINKER_FLAGS_MINSIZEREL} -Oz -flto")

if (WINDHAM_WEB_MINIFY)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --closure 1")
    message(STATUS "Closure Compiler minification enabled (WINDHAM_WEB_MINIFY=ON)")
endif ()

# --- Compile definitions ---
add_compile_definitions(WINDHAM_PLAT_EMSCRIPTEN)
add_compile_definitions(WINDHAM_NO_ISOC_THREAD)
add_compile_definitions(CFG_NO_MODULE_KEYRING)
add_compile_definitions(CFG_DRIVER_NO_DMMAPPER)
add_compile_definitions(CFG_DRIVER_NO_DECRYPT)
add_compile_definitions(WINDHAM_NO_SECCOMP)
add_compile_definitions(WINDHAM_NO_DISABLE_ATTACH)
add_compile_definitions(WINDHAM_NO_ENFORCE_SPEC_MITIGATION)
add_compile_definitions(WINDHAM_NO_SHEBANG_ENTRY)
add_compile_definitions(CFG_VFS_DISK_METADATA)
add_compile_definitions(CFG_FF_SHELL_NOINTERACTIVE)
add_compile_definitions(ARGON2_MAX_MEMORY_BITS=32)
add_compile_definitions(ARGON2_NO_THREADS)
add_compile_definitions(CFG_ISOC_HEADERIO_ENABLE_CACHE)
add_compile_definitions(CFG_NO_TEXT)
add_compile_definitions(CFG_TARGET_READONLY)
add_compile_definitions(CFG_NO_ENTROPY_DETECTION)

# --- Build target ---
add_executable(windham ${WINDHAM_ROOT}/frontend.c)

# Copy web assets into the build dir. Modeled as a separate target with proper
# file dependencies so assets are refreshed even when the wasm does not relink.
set(WEB_ASSETS index.html app.js worker.js i18n.js serve.py)
set(WEB_ASSET_OUTPUTS)
foreach(_f ${WEB_ASSETS})
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${_f}
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_CURRENT_SOURCE_DIR}/${_f}
            ${CMAKE_CURRENT_BINARY_DIR}/${_f}
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${_f}
        COMMENT "Copying web asset ${_f}")
    list(APPEND WEB_ASSET_OUTPUTS ${CMAKE_CURRENT_BINARY_DIR}/${_f})
endforeach()
add_custom_target(web-assets ALL DEPENDS ${WEB_ASSET_OUTPUTS})
add_dependencies(web-assets windham)
