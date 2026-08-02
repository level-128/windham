cmake_minimum_required(VERSION 3.16)
project(windham C)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "This CMakeLists.txt is for GNU/Linux only.\n"
            "For web/Emscripten builds, use:\n"
            "  emcmake cmake -B build/web -S web\n"
            "  cmake --build build/web")
endif()

set(CMAKE_C_STANDARD 11)

# --------------------------------------------------------------------
# user-configurable options (visible in ccmake / cmake-gui)

option(CFG_USE_SWAP                 "Allow KDF memory to use swap space" OFF)
option(CFG_WIPE_MEMORY              "Wipe Argon2 internal memory after KDF" OFF)
option(CFG_NO_OPT                   "Disable x86-64 SIMD optimization in Argon2" OFF)
option(CFG_NO_MODULE_KEYRING        "Disable kernel key retention service" OFF)
option(CFG_DRIVER_NO_FF             "Disable FatFs interactive shell driver" OFF)
option(CFG_NO_FF_CREATE             "Disable --create-exfat (exFAT creation)" OFF)
option(CFG_DRIVER_NO_DECRYPT        "Disable full-disk decryption driver" OFF)
set(CFG_32BIT_ADDR_SPACE "" CACHE STRING
    "Override ARGON2_MAX_MEMORY_BITS (max m_cost=2^bits KiB). 21=2 GiB, 22=4 GiB, 31=2 TiB. Empty = auto detect.")
option(CFG_ASCII                    "Force ASCII-only mode (mask UTF-16/UTF-32)" OFF)
option(WINDHAM_NO_ISOC_THREAD       "Disable multithreading support" OFF)
option(CFG_FF_SHELL_NOINTERACTIVE   "Disable interactive shell, use ./cmd_queue file as shell input" OFF)
option(CFG_VFS_DISK_METADATA        "Use ./disk_size file as disk metadata" OFF)
option(WINDHAM_NO_SECCOMP           "Disable seccomp filter" OFF)
option(WINDHAM_NO_DISABLE_ATTACH    "Allow debugger to attach under Release" OFF)
option(WINDHAM_NO_ENFORCE_SPEC_MITIGATION "Skip Spectre mitigation enforcement" OFF)
option(WINDHAM_REPRODUCIBLE_BUILD   "Replace build timestamp/kernel version with fixed strings" OFF)
option(CFG_ISOC_HEADERIO_ENABLE_CACHE "Enable read cache under ISOC. Ignored for linux" OFF)
option(CFG_NO_TEXT                  "Strip all help texts for minimal build size" OFF)
option(CFG_TARGET_READONLY          "Enable actions that does not require target writing support" OFF)
option(CFG_NO_ENTROPY_DETECTION     "Diasble huffman encoding for smart KDF entropy detection" OFF)


set(CFG_DEFAULT_TARGET_TIME       "1.5"            CACHE STRING "Target KDF derivation time (seconds)")
set(CFG_MAX_UNLOCK_TIME_FACTOR    "5"              CACHE STRING "Max unlock time = target × factor")
set(CFG_DEFAULT_BLOCK_SIZE        "4096"           CACHE STRING "Default encryption sector size (bytes)")
set(CFG_WINDHAM_DEFAULT_DISK_ENC_MODE "aes-xts-plain64" CACHE STRING "Default cipher-chainmode-ivmode")
set(CFG_DEFAULT_DISK_ENC_MEM_RATIO_CAP "30"        CACHE STRING "Memory cap ratio for encryption KDF")
set(CFG_MIN_MEMLOCK_SIZE          "8388608"        CACHE STRING "Minimum mlock memory (bytes)")
set(CFG_WINDHAMTAB_FILE           "/etc/windhamtab" CACHE STRING "Path to windhamtab config file")

# --------------------------------------------------------------------
# define build type

set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Release" "Debug" "Test")
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the build type <Release | Debug | Test> (default: Release)" FORCE)
endif ()

# --------------------------------------------------------------------
# define CPU arch and version number

file(READ "build_misc/version.txt" WINDHAM_VERSION)
string(STRIP "${WINDHAM_VERSION}" WINDHAM_VERSION)
add_compile_definitions(WINDHAM_VERSION="${WINDHAM_VERSION}")

add_compile_definitions(CMAKE_HOST_ARCH="${CMAKE_HOST_SYSTEM_PROCESSOR}")
add_compile_definitions(CMAKE_TARGET_ARCH="${CMAKE_SYSTEM_PROCESSOR}")

set(WINDHAM_AMD64_NAMES amd64 AMD64 x86_64)
if (CMAKE_SYSTEM_PROCESSOR IN_LIST WINDHAM_AMD64_NAMES)
    set(ARCH "x86_64")
else ()
    set(ARCH "other")
endif ()

# --------------------------------------------------------------------
# define global options

if(CFG_DEFAULT_TARGET_TIME)
    add_compile_definitions(DEFAULT_TARGET_TIME=${CFG_DEFAULT_TARGET_TIME})
endif()

if(CFG_MAX_UNLOCK_TIME_FACTOR)
    add_compile_definitions(MAX_UNLOCK_TIME_FACTOR=${CFG_MAX_UNLOCK_TIME_FACTOR})
endif()

if(CFG_DEFAULT_BLOCK_SIZE)
    add_compile_definitions(DEFAULT_BLOCK_SIZE=${CFG_DEFAULT_BLOCK_SIZE})
endif()

add_compile_definitions(DEFAULT_DISK_ENC_MODE="${CFG_WINDHAM_DEFAULT_DISK_ENC_MODE}")

# --------------------------------------------------------------------
# define compiler options

function(configure_global_flags)
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        if(CMAKE_C_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang|ZigCC|Intel)$")
            set(CMAKE_C_FLAGS "-O3 ${CMAKE_C_FLAGS}" PARENT_SCOPE)
        else()
            message(WARNING "Windham don't know how to set optimization flags for this compiler. "
                    "Use CMAKE_C_FLAGS to pass optimization flags.")
        endif()
    elseif(CMAKE_BUILD_TYPE MATCHES "^(Debug|Test)$")
        if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
            set(CMAKE_C_FLAGS "-Wall -Wextra -ggdb -g -O0 ${CMAKE_C_FLAGS}" PARENT_SCOPE)
        else()
            set(CMAKE_C_FLAGS "-O0 -g ${CMAKE_C_FLAGS}" PARENT_SCOPE)
        endif()
    endif()

    if(CMAKE_BUILD_TYPE STREQUAL "Test")
        set(CMAKE_C_FLAGS "-Wno-unused-variable -Wno-unused-parameter ${CMAKE_C_FLAGS}" PARENT_SCOPE)
    endif()

    add_compile_options(${CMAKE_C_FLAGS})
    add_compile_definitions(CMAKE_COMPILE_PARAMS="${CMAKE_C_FLAGS}")
    target_link_libraries(windham m)

endfunction()
include(GNUInstallDirs)



# --------------------------------------------------------------------
# try-run

if (CMAKE_CROSSCOMPILING)
    set(RUN_RESULT_VAR FALSE)
    set(RUN_RESULT_VAR__TRYRUN_OUTPUT FALSE)
endif()

find_library(IS_BLKID_LIB blkid)
if (IS_BLKID_LIB)
    message(STATUS "Found blkid library for compile-time header definitions")
endif()


# test keyctl
if (CFG_NO_MODULE_KEYRING)
    add_compile_definitions(CFG_NO_MODULE_KEYRING)
    message(STATUS "Linux kernel key retention subsystem disabled by arguments")
else ()
    try_run(
            RUN_RESULT_VAR
            COMPILE_RESULT_VAR
            ${CMAKE_BINARY_DIR}/temp
            SOURCES ${CMAKE_SOURCE_DIR}/build_misc/check_keyctl.c
            COMPILE_OUTPUT_VARIABLE COMPILE_OUTPUT_VAR
            RUN_OUTPUT_VARIABLE RUN_OUTPUT_VAR
    )
    if (NOT COMPILE_RESULT_VAR)
        message(SEND_ERROR "Cannot compile keyctl try run program. Possibly missing kernel header.")
    elseif (NOT CMAKE_CROSSCOMPILING)
        if (RUN_RESULT_VAR STREQUAL FAILED_TO_RUN)
            add_compile_definitions(CFG_NO_MODULE_KEYRING)
            message(WARNING "System call \"SYS_keyctl\" unsupported by this kernel. Disabling Linux kernel key"
                    "retention service.")
        else ()
            find_library(IS_KEYUTILS_LIB keyutils)
            if(IS_KEYUTILS_LIB STREQUAL IS_KEYUTILS_LIB-NOTFOUND)
                message(WARNING "library keyutils not found. Windham compiles with keyctl support but will fail when"
                        "loading keyutils module.")
            else()
                message(STATUS "Linux kernel key retention subsystem detected and enabled.")
            endif()
        endif ()
    else ()
        message(STATUS "Cross compiling, not detecting SYS_keyctl and keyutils. key retention subsystem enabled")
    endif ()
endif ()


# test ISOC threads
try_run(
        RUN_RESULT_VAR
        COMPILE_RESULT_VAR
        ${CMAKE_BINARY_DIR}/temp
        SOURCES ${CMAKE_SOURCE_DIR}/build_misc/check_isoc_thread.c
        COMPILE_OUTPUT_VARIABLE COMPILE_OUTPUT_VAR
        RUN_OUTPUT_VARIABLE RUN_OUTPUT_VAR
)

if (COMPILE_RESULT_VAR EQUAL 0)
    message(WARNING "Cannot compile test <thread.h> program, build may fail. Your system may requires additional"
            "link-time libraries to enable ISO C thread. Use environment CFLAGS= to designate required libraries. Common"
            "platforms may require \"-lpthread\"; try this first.")
elseif (NOT CMAKE_CROSSCOMPILING)
    if (RUN_OUTPUT_VAR EQUAL 1)
        message(WARNING "Sample ISO C multithread program occurred a runtime error. Disabling ISO C thread support."
                "Unlocking will be up to two times slower.")
        set(WINDHAM_NO_ISOC_THREAD ON)
    elseif (RUN_OUTPUT_VAR EQUAL 2)
        message(WARNING "ISO C threading support not available on this platform. Disabling ISO C thread support."
                "Unlocking will be up to two times slower.")
    else ()
        message(STATUS "libc multithread detected and enabled.")
    endif ()
else()
    message(STATUS "Cross compiling, multithread enabled using libc without testing.")
endif()


# test getauxval
try_run(
        RUN_RESULT_VAR
        COMPILE_RESULT_VAR
        ${CMAKE_BINARY_DIR}/temp
        SOURCES ${CMAKE_SOURCE_DIR}/build_misc/check_getauxval.c
        COMPILE_OUTPUT_VARIABLE COMPILE_OUTPUT_VAR
        RUN_OUTPUT_VARIABLE RUN_OUTPUT_VAR
)

if (WINDHAM_NO_SHEBANG_ENTRY STREQUAL OFF)
    if (COMPILE_RESULT_VAR EQUAL 0)
        message(WARNING "Your libc does not support getauxval. Shebang entry will be disabled.")
        set(WINDHAM_NO_SHEBANG_ENTRY ON)
    elseif (NOT CMAKE_CROSSCOMPILING)
        if (RUN_OUTPUT_VAR EQUAL 1)
            message(WARNING "getauxval return 0 for getauxval(AT_EXECFN). Shebang entry will be disabled.")
            set(WINDHAM_NO_SHEBANG_ENTRY ON)
        else ()
            message(STATUS "Shebang entry enabled.")
        endif ()
    else()
        message(STATUS "Cross compiling, Shebang entry enabled without testing.")
    endif()
endif()

# check loop ioctl (compile-only)
# Verifies <linux/loop.h> provides LOOP_SET_FD, LOOP_CLR_FD, LOOP_SET_STATUS64,
# LOOP_CTL_GET_FREE, LOOP_SET_BLOCK_SIZE, struct loop_info64, LO_FLAGS_AUTOCLEAR.
# Uses try_compile (not try_run) because:
#   - Running requires root privileges
#   - Different kernel versions, capabilities, seccomp affect runtime results
#   - Only need to verify the headers can compile
# If compile fails, defines WINDHAM_NO_LOOP_IOCTL to fall back to losetup command.
# This is a compile-time decision — there is no runtime fallback from ioctl to losetup.
try_compile(
        LOOP_IOCTL_COMPILE_RESULT
        ${CMAKE_BINARY_DIR}/temp
        SOURCES ${CMAKE_SOURCE_DIR}/build_misc/check_loop_ioctl.c
)
if (LOOP_IOCTL_COMPILE_RESULT)
    message(STATUS "Loop device ioctl headers available (LOOP_CONFIGURE, LOOP_CTL_GET_FREE, etc.).")
else ()
    message(WARNING "Loop device ioctl headers not available. Falling back to losetup command.")
    add_compile_definitions(WINDHAM_NO_LOOP_IOCTL)
endif ()

# check mntent.h (glibc-specific; unavailable on musl / uclibc)
try_compile(
        HAS_MNTENT
        ${CMAKE_BINARY_DIR}/temp
        SOURCES ${CMAKE_SOURCE_DIR}/build_misc/check_mntent.c
)
if (HAS_MNTENT)
    add_compile_definitions(WINDHAM_HAS_MNTENT)
    message(STATUS "mntent.h available — Probe will show mount info.")
else ()
    message(STATUS "mntent.h not available (non-glibc libc). Probe mount info disabled.")
endif ()

# check only for release

if (CMAKE_BUILD_TYPE STREQUAL "Release")
# debugger attach is not allowed under release.
if (NOT WINDHAM_NO_DISABLE_ATTACH)
    # disallow debugger to attach
    if (NOT CMAKE_CROSSCOMPILING)
        try_run(
                RUN_RESULT_VAR
                COMPILE_RESULT_VAR
                ${CMAKE_BINARY_DIR}/temp
                SOURCES ${CMAKE_SOURCE_DIR}/build_misc/check_prctl_set_dumpable.c
                COMPILE_OUTPUT_VARIABLE COMPILE_OUTPUT_VAR
                RUN_OUTPUT_VARIABLE RUN_OUTPUT_VAR
        )

        if (NOT COMPILE_RESULT_VAR OR NOT RUN_RESULT_VAR EQUAL 0)
            message(WARNING "Allowing debugger to attach under \"Release\" target: failed to set dumpable under prctl.")
            set(WINDHAM_NO_DISABLE_ATTACH ON)
        endif ()
    else ()
        message(STATUS "Disallow debugger attach using prctl. Use WINDHAM_NO_DISABLE_ATTACH to allow.")
    endif ()
else()
    message(WARNING "Allowing debugger to attach under \"Release\" target.")
    set(WINDHAM_NO_DISABLE_ATTACH ON)
endif()

# detect spectre mitigation
if (NOT WINDHAM_NO_ENFORCE_SPEC_MITIGATION AND NOT CMAKE_CROSSCOMPILING)
    try_run(
            RUN_RESULT_VAR
            COMPILE_RESULT_VAR
            ${CMAKE_BINARY_DIR}/temp
            SOURCES ${CMAKE_SOURCE_DIR}/build_misc/check_prctl_speculation_ctrl.c
            COMPILE_OUTPUT_VARIABLE COMPILE_OUTPUT_VAR
            RUN_OUTPUT_VARIABLE RUN_OUTPUT_VAR
    )
    if ((COMPILE_RESULT_VAR EQUAL 0) OR (RUN_RESULT_VAR EQUAL 1))
        message(WARNING "build system cannot determine speculation mitigation status.")
        add_compile_definitions(WINDHAM_NO_ENFORCE_SPEC_MITIGATION)
        add_compile_definitions(WINDHAM_SPEC_MITIGATION=-1)
    else () # 2 (not needed) or 0 (okay) are possible.
        add_compile_definitions(WINDHAM_SPEC_MITIGATION=${RUN_RESULT_VAR})
    endif ()
else ()
    add_compile_definitions(WINDHAM_NO_ENFORCE_SPEC_MITIGATION)
    add_compile_definitions(WINDHAM_SPEC_MITIGATION=-1)
endif ()

endif()

# --------------------------------------------------------------------
# define common options
set(WINDHAM_USING_CMAKE ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION}.${CMAKE_PATCH_VERSION})
add_compile_definitions(WINDHAM_USING_CMAKE="${WINDHAM_USING_CMAKE}")

add_compile_definitions(WINDHAM_PLAT_GNU_LINUX)
add_compile_definitions(CFG_DEFAULT_DRIVER="dm-mapper")

execute_process(COMMAND uname -r OUTPUT_VARIABLE KERNEL_VERSION OUTPUT_STRIP_TRAILING_WHITESPACE)
if (WINDHAM_REPRODUCIBLE_BUILD)
    add_compile_definitions(CMAKE_TARGET_KERNEL_VERSION="WIPED_REPRODUCIBLE")
else ()
    add_compile_definitions(CMAKE_TARGET_KERNEL_VERSION="${KERNEL_VERSION}")
endif ()

if (WINDHAM_REPRODUCIBLE_BUILD)
    add_compile_definitions(CMAKE_BUILD_TIME="WIPED_REPRODUCIBLE")
else ()
    string(TIMESTAMP CURRENT_TIME "%Y-%m-%d %H:%M:%S" UTC)
    add_compile_definitions(CMAKE_BUILD_TIME="${CURRENT_TIME}")
endif ()



# --------------------------------------------------------------------
# add compile def into compiler
if(CFG_DEFAULT_DISK_ENC_MEM_RATIO_CAP)
    add_compile_definitions(DEFAULT_DISK_ENC_MEM_RATIO_CAP=${CFG_DEFAULT_DISK_ENC_MEM_RATIO_CAP})
endif()

if (CFG_USE_SWAP)
    add_compile_definitions(CFG_USE_SWAP)
endif ()

if (CFG_WIPE_MEMORY)
    add_compile_definitions(ARGON2_CLEAR_INTERNAL_MEMORY=1)
else ()
    add_compile_definitions(ARGON2_CLEAR_INTERNAL_MEMORY=0)
endif ()

if (CFG_MIN_MEMLOCK_SIZE)
    add_compile_definitions(DEFAULT_MIN_MEMLOCK_SIZE=${CFG_MIN_MEMLOCK_SIZE})
endif()

if (NOT CFG_WINDHAMTAB_FILE STREQUAL "/etc/windhamtab")
    add_compile_definitions(WINDHAMTAB_FILE="${CFG_WINDHAMTAB_FILE}")
endif()

# driver features
if (CFG_DRIVER_NO_FF)
    add_compile_definitions(CFG_DRIVER_NO_FF)
endif ()

if (CFG_NO_FF_CREATE)
    add_compile_definitions(CFG_NO_FF_CREATE)
endif ()

if (CFG_DRIVER_NO_DECRYPT)
    add_compile_definitions(CFG_DRIVER_NO_DECRYPT)
endif ()

if (WINDHAM_NO_DISABLE_ATTACH)
    add_compile_definitions(WINDHAM_NO_DISABLE_ATTACH)
endif ()

if (WINDHAM_NO_SHEBANG_ENTRY)
    add_compile_definitions(WINDHAM_NO_SHEBANG_ENTRY)
endif ()
# seccomp filter
if (WINDHAM_NO_SECCOMP)
    add_compile_definitions(WINDHAM_NO_SECCOMP)
endif ()

# Override ARGON2_MAX_MEMORY_BITS (bits for max m_cost in KiB)
if (CFG_32BIT_ADDR_SPACE)
    add_compile_definitions(ARGON2_MAX_MEMORY_BITS=${CFG_32BIT_ADDR_SPACE})
endif ()

# force ASCII-only mode (mask UTF-16/UTF-32)
if (CFG_ASCII)
    add_compile_definitions(CFG_ASCII)
endif ()

if (WINDHAM_NO_ISOC_THREAD)
    add_compile_definitions(WINDHAM_NO_ISOC_THREAD)
endif ()

# allow debugger attach
if (WINDHAM_NO_DISABLE_ATTACH)
    add_compile_definitions(WINDHAM_NO_DISABLE_ATTACH)
endif ()

if (CFG_NO_TEXT)
    add_compile_definitions(CFG_NO_TEXT)
endif ()

if (CFG_TARGET_READONLY)
    add_compile_definitions(CFG_TARGET_READONLY)
endif ()

if (CFG_NO_ENTROPY_DETECTION)
    add_compile_definitions(CFG_NO_ENTROPY_DETECTION)
endif ()


# disabling Argon2 threads. We are not going to use them. All KDF has p=1
add_compile_definitions(ARGON2_NO_THREADS)


# --------------------------------------------------------------------
# add files
include_directories(${CMAKE_SOURCE_DIR}/include)

file(GLOB SHA256_SRC ${CMAKE_SOURCE_DIR}/library/SHA256/*.c)
file(GLOB tiny_AES_c_SRC ${CMAKE_SOURCE_DIR}/library/tiny_AES_c/*.c)
file(GLOB cJSON_SRC ${CMAKE_SOURCE_DIR}/library/cJSON/*.c)
file(GLOB GETOPT_SRC ${CMAKE_SOURCE_DIR}/library/getopt_port/*.c)
file(GLOB QRCODE_SRC ${CMAKE_SOURCE_DIR}/library/QRCode/*.c)
set(FATFS_SRC ${CMAKE_SOURCE_DIR}/library/FatFs/ff.c
              ${CMAKE_SOURCE_DIR}/library/FatFs/ffunicode.c
              ${CMAKE_SOURCE_DIR}/library/FatFs/ffsystem.c
              ${CMAKE_SOURCE_DIR}/library/FatFs/ff_diskio.c)

set(ARGON2_DIR ${CMAKE_SOURCE_DIR}/library/Argon2)

if (CFG_NO_ENTROPY_DETECTION STREQUAL OFF)
    file(GLOB HUFFMAN_SRC ${CMAKE_SOURCE_DIR}/library/huffman/*.c)
    set(LIBRARY_SOURCES ${LIBRARY_SOURCES} ${HUFFMAN_SRC})
else ()
    message(STATUS "Huffman library disabled.")
endif ()

if (CFG_NO_OPT)
    add_compile_definitions("__Argon2_opt_disable__")
    message(STATUS "SIMD optimization disabled using options.")
    file(GLOB Argon2_SRC ${ARGON2_DIR}/argon2.c ${ARGON2_DIR}/core.c ${ARGON2_DIR}/encoding.c ${ARGON2_DIR}/ref.c
            ${ARGON2_DIR}/thread.c ${ARGON2_DIR}/blake2/blake2b.c)
elseif (ARCH STREQUAL "x86_64")
    message(STATUS "Use x86-64 platform optimization")
    file(GLOB Argon2_SRC ${ARGON2_DIR}/argon2.c ${ARGON2_DIR}/core.c ${ARGON2_DIR}/encoding.c ${ARGON2_DIR}/opt.c
            ${ARGON2_DIR}/thread.c ${ARGON2_DIR}/blake2/blake2b.c)
else ()
    message(STATUS "No platform optimization available under this architecture: ${CMAKE_SYSTEM_PROCESSOR}")
    file(GLOB Argon2_SRC ${ARGON2_DIR}/argon2.c ${ARGON2_DIR}/core.c ${ARGON2_DIR}/encoding.c ${ARGON2_DIR}/ref.c
            ${ARGON2_DIR}/thread.c ${ARGON2_DIR}/blake2/blake2b.c)
endif ()

set(LIBRARY_SOURCES ${LIBRARY_SOURCES} ${Argon2_SRC} ${SHA256_SRC} ${tiny_AES_c_SRC} ${cJSON_SRC} ${GETOPT_SRC} ${FATFS_SRC} ${QRCODE_SRC})


# --------------------------------------------------------------------
# build targets

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_definitions(WINDHAM_NO_DISABLE_ATTACH) # allow attach under debug
    add_compile_definitions(WINDHAM_NO_ENFORCE_SPEC_MITIGATION)
    add_compile_definitions(WINDHAM_SPEC_MITIGATION=-1)

    set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
    add_executable(windham frontend.c ${LIBRARY_SOURCES})
    set_target_properties(windham PROPERTIES OUTPUT_NAME windham_debug)
    configure_global_flags()


elseif (CMAKE_BUILD_TYPE STREQUAL "Release")

    add_executable(windham frontend.c ${LIBRARY_SOURCES})
    configure_global_flags()
    install(TARGETS windham
            RUNTIME DESTINATION bin)

elseif (CMAKE_BUILD_TYPE STREQUAL "Test")
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    message(STATUS "Found Python3: ${Python3_EXECUTABLE}")
    add_compile_definitions(WINDHAM_NO_DISABLE_ATTACH)
    add_compile_definitions(WINDHAM_NO_ENFORCE_SPEC_MITIGATION)
    add_compile_definitions(WINDHAM_SPEC_MITIGATION=-1)

    set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
    add_executable(windham frontend.c ${LIBRARY_SOURCES})
    set_target_properties(windham PROPERTIES OUTPUT_NAME windham_test)
    configure_global_flags()

    add_custom_target(check
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/run_tests.py --binary $<TARGET_FILE:windham>
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        USES_TERMINAL
        COMMENT "Running test suite"
    )

endif()


install(TARGETS windham RUNTIME DESTINATION bin)
install(FILES README.md DESTINATION share/doc/windham)
install(DIRECTORY docs/ DESTINATION share/doc/windham/docs
        FILES_MATCHING PATTERN "*.md")
install(PROGRAMS scripts/windham-raid-setup.sh
        DESTINATION share/windham)