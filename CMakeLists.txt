cmake_minimum_required(VERSION 3.13)
project(windham C)
set(CMAKE_C_STANDARD 11)
enable_language(ASM)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(BLAKE3_AMD64_NAMES amd64 AMD64 x86_64)
set(BLAKE3_ARM_NAMES aarch64 AArch64 arm64 ARM64)
set(WINDHAM_RISC_V_NAMES riscv64)

# --------------------------------------------------------------------
# define options


if (CMAKE_SYSTEM_PROCESSOR IN_LIST BLAKE3_AMD64_NAMES)
    set(ARCH "x86_64")
elseif (CMAKE_SYSTEM_PROCESSOR IN_LIST BLAKE3_ARM_NAMES)
    set(ARCH "aarch64")
elseif (CMAKE_SYSTEM_PROCESSOR IN_LIST WINDHAM_RISC_V_NAMES)
    set(ARCH "riscv64")
else ()
    set(ARCH "other")
endif ()

include(cmakelib/top.cmake)

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the build type (default: Release)" FORCE)
endif ()


set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Release" "Debug" "Test" "Language")

set(CONFIG_WINDHAM_DEFAULT_DISK_ENC_MODE_LIST "aes-xts-plain64" "twofish-xts-plain64"
    "serpent-xts-plain64" "twofish-xts-plain64be" "aes-xts-plain64be" "serpent-xts-plain64be")

if (NOT CONFIG_WINDHAM_DEFAULT_DISK_ENC_MODE IN_LIST CONFIG_WINDHAM_DEFAULT_DISK_ENC_MODE_LIST)
    message(FATAL_ERROR "Unknown encryption mode ${WINDHAM_DEFAULT_DISK_ENC_MODE}. accept values are: ${CONFIG_WINDHAM_DEFAULT_DISK_ENC_MODE_LIST}")
endif ()

set(CMAKE_INSTALL_BIN "/usr/sbin" CACHE STRING "Set install location" FORCE)


# --------------------------------------------------------------------
# add files
include_directories(${CMAKE_SOURCE_DIR}/include)

file(GLOB Argon2_SRC ${CMAKE_SOURCE_DIR}/library/Argon2B3/*.c)
file(GLOB SHA256_SRC ${CMAKE_SOURCE_DIR}/library/SHA256/*.c)
file(GLOB tiny_AES_c_SRC ${CMAKE_SOURCE_DIR}/library/tiny_AES_c/*.c)
file(GLOB HUFFMAN_SRC ${CMAKE_SOURCE_DIR}/library/huffman/*.c)
file(GLOB cJSON_SRC ${CMAKE_SOURCE_DIR}/library/cJSON/*.c)

set(BLAKE_DIR ${CMAKE_SOURCE_DIR}/library/blake3)

include_directories(${CMAKE_SOURCE_DIR}/include/linux_fs_system)

# --------------------------------------------------------------------
# arch dependent options

if ((ARCH STREQUAL "x86_64" AND CONFIG_TARGET_ARCHITECTURE_NATIVE) OR CONFIG_TARGET_ARCHITECTURE_AMD64)
    if (CONFIG_SIMD_OPTIMIZE_INTRIN)
        file(GLOB Blake3_SRC ${BLAKE_DIR}/blake3.c ${BLAKE_DIR}/blake3_dispatch.c ${BLAKE_DIR}/blake3_portable.c ${BLAKE_DIR}/blake3_sse2.c
             ${BLAKE_DIR}/blake3_sse41.c ${BLAKE_DIR}/blake3_avx2.c ${BLAKE_DIR}/blake3_avx512.c)
    else ()
        file(GLOB Blake3_SRC ${BLAKE_DIR}/blake3.c ${BLAKE_DIR}/blake3_dispatch.c ${BLAKE_DIR}/blake3_portable.c ${BLAKE_DIR}/blake3_sse2_x86-64_unix.S
             ${BLAKE_DIR}/blake3_sse41_x86-64_unix.S ${BLAKE_DIR}/blake3_avx2_x86-64_unix.S ${BLAKE_DIR}/blake3_avx512_x86-64_unix.S)
    endif ()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprefetch-loop-arrays ")

elseif ((ARCH STREQUAL "aarch64" AND CONFIG_TARGET_ARCHITECTURE_NATIVE) OR CONFIG_TARGET_ARCHITECTURE_AARCH64)
    file(GLOB Blake3_SRC ${BLAKE_DIR}/blake3.c ${BLAKE_DIR}/blake3_dispatch.c ${BLAKE_DIR}/blake3_portable.c ${BLAKE_DIR}/blake3_neon.c)
    if (CONFIG_AARCH64_USE_NEON)
        add_definitions(-DBLAKE3_USE_NEON=1)
    endif ()
else ()
    file(GLOB Blake3_SRC ${BLAKE_DIR}/blake3.c ${BLAKE_DIR}/blake3_dispatch.c ${BLAKE_DIR}/blake3_portable.c)
endif ()

# --------------------------------------------------------------------
# set (build related) options and macros

string(TIMESTAMP CURRENT_TIME "%Y-%m-%d %H:%M:%S" UTC)
set(CMAKE_VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION}.${CMAKE_PATCH_VERSION})
set(SYSTEM_INFO ${CMAKE_SYSTEM})

# Pass the variables to code via preprocessor definitions
add_definitions("-DCURRENT_TIME=\"${CURRENT_TIME}\"")
add_definitions("-DCMAKE_VERSION=\"${CMAKE_VERSION}\"")
execute_process(COMMAND uname -r OUTPUT_VARIABLE KERNEL_VERSION OUTPUT_STRIP_TRAILING_WHITESPACE)
add_definitions("-DTARGET_KERNEL_VERSION=\"${KERNEL_VERSION}\"")
add_definitions("-DHOST_ARCH=\"${CMAKE_HOST_SYSTEM_PROCESSOR}\"")
add_definitions("-DTARGET_ARCH=\"${CMAKE_SYSTEM_PROCESSOR}\"")

if (CONFIG_NO_SIMD_OPTIMIZE STREQUAL ON)
    add_definitions(-D__Argon2_opt_disable__)
endif ()

if (NOT CONFIG_TARGET_ARCHITECTURE_NATIVE)
    if (x86_64_compiler STREQUAL "")
        message(FATAL_ERROR "no compiler given for non-native arch.")
    endif ()
    set(CMAKE_C_COMPILER ${TARGET_COMPILIER})
endif ()

add_definitions(-DDEFAULT_TARGET_TIME=${CONFIG_DEFAULT_TARGET_TIME})
add_definitions(-DMAX_UNLOCK_TIME_FACTOR=${CONFIG_MAX_UNLOCK_TIME_FACTOR})
add_definitions(-DDEFAULT_BLOCK_SIZE=${CONFIG_DEFAULT_BLOCK_SIZE})
add_definitions(-DDEFAULT_DISK_ENC_MEM_RATIO_CAP=${CONFIG_DEFAULT_DISK_ENC_MEM_RATIO_CAP})

if (CONFIG_MODULE_KEYRING STREQUAL 2)
    try_run(
            RUN_RESULT_VAR
            COMPILE_RESULT_VAR
            ${CMAKE_BINARY_DIR}/temp
            SOURCES ${CMAKE_SOURCE_DIR}/build_misc/check_keyctl.c
            COMPILE_OUTPUT_VARIABLE COMPILE_OUTPUT_VAR
            RUN_OUTPUT_VARIABLE RUN_OUTPUT_VAR
    )
    if (NOT COMPILE_RESULT_VAR OR NOT RUN_RESULT_VAR EQUAL 0)
        add_definitions(-DNO_KEYCTL)
        set(NO_MODULE_KEYRING ON)
    endif ()

elseif (CONFIG_MODULE_KEYRING STREQUAL 0)
    add_definitions(-DNO_KEYCTL)
    set(NO_MODULE_KEYRING ON)
endif ()


if (NOT CONFIG_NO_ENFORCE_SPEC_MITIGATION)
    try_run(
            RUN_RESULT_VAR
            COMPILE_RESULT_VAR
            ${CMAKE_BINARY_DIR}/temp
            SOURCES ${CMAKE_SOURCE_DIR}/build_misc/check_prctl_speculation_ctrl.c
            COMPILE_OUTPUT_VARIABLE COMPILE_OUTPUT_VAR
            RUN_OUTPUT_VARIABLE RUN_OUTPUT_VAR
    )
    if (NOT COMPILE_RESULT_VAR OR NOT RUN_RESULT_VAR EQUAL 0)
        message(WARNING "speculation mitigation is disabled.")
        add_definitions(-DWINDHAM_NO_ENFORCE_SPEC_MITIGATION)
    endif ()
else ()
    add_definitions(-DWINDHAM_NO_ENFORCE_SPEC_MITIGATION)
endif ()


if (CMAKE_BUILD_TYPE STREQUAL "Release")
    if (NOT CONFIG_WINDHAM_ALLOW_ATTACH)
        try_run(
                RUN_RESULT_VAR
                COMPILE_RESULT_VAR
                ${CMAKE_BINARY_DIR}/temp
                SOURCES ${CMAKE_SOURCE_DIR}/build_misc/check_prctl_set_dumpable.c
                COMPILE_OUTPUT_VARIABLE COMPILE_OUTPUT_VAR
                RUN_OUTPUT_VARIABLE RUN_OUTPUT_VAR
        )

        if (NOT COMPILE_RESULT_VAR OR NOT RUN_RESULT_VAR EQUAL 0)
            message(WARNING "Allowing debugger to attach")
            add_definitions(-DWINDHAM_ALLOW_ATTACH)
        endif ()
    else ()
        add_definitions(-DWINDHAM_ALLOW_ATTACH)
    endif ()
    set(CMAKE_C_FLAGS "${CONFIG_COMPILIER_OPT} ${CMAKE_C_FLAGS}")
else ()
    add_definitions(-DWINDHAM_ALLOW_ATTACH) # allow attach under debug
endif ()

if (CONFIG_WIPE_MEMORY STREQUAL OFF)
    add_definitions(-DARGON2B3_CLEAR_INTERNAL_MEMORY=0)
else ()
    add_definitions(-DARGON2B3_CLEAR_INTERNAL_MEMORY=1)
endif ()

if (CONFIG_COMPILIER_ENABLE_LTO AND (CMAKE_BUILD_TYPE STREQUAL "Release"))
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -flto=auto -fwhole-program -fno-fat-lto-objects -fipa-pta -fgcse-sm -fgcse-las -funroll-loops -flive-range-shrinkage -fira-region=all")
endif ()

add_definitions(-DDEFAULT_DISK_ENC_MODE="${CONFIG_WINDHAM_DEFAULT_DISK_ENC_MODE}")
if (CONFIG_USE_SWAP)
    add_definitions(-DCONFIG_USE_SWAP)
endif ()

# --------------------------------------------------------------------
# build function
function(add_argon2_and_executables_for_arch target_name)
    if (CONFIG_TARGET_SUB_ARCHITECTURE)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=${CONFIG_TARGET_SUB_ARCHITECTURE}")
    endif ()
    if (CONFIG_TARGET_MTUNE)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mtune=${CONFIG_TARGET_MTUNE}")
    endif ()

    if (target_name STREQUAL "windham_test")
        add_executable(windham test/test.c
                       ${Blake3_SRC} ${Argon2_SRC} ${SHA256_SRC} ${tiny_AES_c_SRC} ${HUFFMAN_SRC} ${cJSON_SRC})
    else ()
        add_executable(windham frontend.c ${CMAKE_SOURCE_DIR}/library_intrnlsrc/ ${CMAKE_SOURCE_DIR}/backend
                       ${Blake3_SRC} ${Argon2_SRC} ${SHA256_SRC} ${tiny_AES_c_SRC} ${HUFFMAN_SRC} ${cJSON_SRC})
    endif ()
    set_target_properties(windham PROPERTIES COMPILE_FLAGS ${CMAKE_C_FLAGS})
    target_link_libraries(windham m dl pthread blkid)
    if (NOT NO_MODULE_KEYRING)
        target_link_libraries(windham keyutils)
    endif ()
    add_definitions("-DCOMPILE_PARAMS=\"${CMAKE_C_FLAGS}\"")
    set_target_properties(windham PROPERTIES OUTPUT_NAME ${target_name})
    install(TARGETS windham
            RUNTIME DESTINATION ${CMAKE_INSTALL_BIN})
endfunction()


# --------------------------------------------------------------------
# build targets

set(CMAKE_AR "gcc-ar")
set(CMAKE_NM "gcc-nm")
set(CMAKE_RANLIB "gcc-ranlib")


if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}  -Wall -Wextra -ggdb -g -O0")
    set(CONFIG_TARGET_SUB_ARCHITECTURE "")
    add_argon2_and_executables_for_arch("windham_debug")

elseif (CMAKE_BUILD_TYPE STREQUAL "Release")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${COMPILIER_OPT}")
    add_argon2_and_executables_for_arch("windham")

elseif (CMAKE_BUILD_TYPE STREQUAL "Test")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -ggdb -O0 -Wno-unused-parameter -Wno-type-limits -Wno-sign-compare -Wno-clobbered")
    add_argon2_and_executables_for_arch("windham_test")

elseif (CMAKE_BUILD_TYPE STREQUAL "Language")
    # update translations
    set(LANGUAGES fr zh_CN)
    add_custom_target(update_translations ALL
                      DEPENDS ${CMAKE_SOURCE_DIR}/locale/windham.pot)

    add_custom_command(
            OUTPUT ${CMAKE_SOURCE_DIR}/locale/windham.pot
            COMMAND xgettext --from-code=UTF-8 -k_ -L C --no-location -o ${CMAKE_SOURCE_DIR}/locale/windham.pot ${CMAKE_SOURCE_DIR}/frontend.c ${CMAKE_SOURCE_DIR}/backend.c ${CMAKE_SOURCE_DIR}/mapper.c
            ${CMAKE_SOURCE_DIR}/argon_bench.c
            ${CMAKE_SOURCE_DIR}/enclib.c ${CMAKE_SOURCE_DIR}/library_intrnlsrc/srclib.c
            COMMENT "Generating windham.pot from source code"
    )

    foreach (LANG ${LANGUAGES})
        add_custom_command(
                TARGET update_translations
                COMMAND msgmerge --update ${CMAKE_SOURCE_DIR}/locale/${LANG}/LC_MESSAGES/windham.po ${CMAKE_SOURCE_DIR}/locale/windham.pot
                COMMENT "Updating ${LANG}/windham.po"
        )
    endforeach ()

    add_custom_target(compile_translations)
    foreach (LANG ${LANGUAGES})
        add_custom_command(
                TARGET compile_translations
                COMMAND msgfmt -c -o locale/${LANG}/LC_MESSAGES/windham.mo locale/${LANG}/LC_MESSAGES/windham.po
                COMMENT "Compiling ${LANG}/windham.po"
        )
    endforeach ()

endif ()
