cmake_minimum_required(VERSION 3.16)
project(windham C)
set(CMAKE_C_STANDARD 11)

# --------------------------------------------------------------------
# user-configurable options (visible in ccmake / cmake-gui)

option(CFG_USE_SWAP                 "Allow KDF memory to use swap space" OFF)
option(CFG_WIPE_MEMORY              "Wipe Argon2 internal memory after KDF" OFF)
option(CFG_NO_OPT                   "Disable x86-64 SIMD optimization in Argon2" OFF)
option(CFG_NO_MODULE_KEYRING        "Disable kernel key retention service" OFF)
option(CFG_DRIVER_FF                "Enable FatFs interactive shell driver" ON)
option(CFG_FF_CREATE                "Enable --create-exfat (exFAT creation)" ON)
option(CFG_DRIVER_DECRYPT           "Enable full-disk decryption driver" ON)
option(CFG_32BIT_ADDR_SPACE         "Limit Argon2 memory for 32-bit address space" OFF)
option(CFG_ASCII                    "Force ASCII-only mode (mask UTF-16/UTF-32)" OFF)
option(WINDHAM_NO_SECCOMP           "Disable seccomp filter" OFF)
option(WINDHAM_NO_DISABLE_ATTACH    "Allow debugger to attach" OFF)
option(WINDHAM_NO_ENFORCE_SPEC_MITIGATION "Skip Spectre mitigation enforcement" OFF)
option(WINDHAM_REPRODUCIBLE_BUILD   "Replace build timestamp/kernel version with fixed strings" OFF)

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
add_compile_definitions(WINDHAM_VERSION=\"${WINDHAM_VERSION}\")

add_compile_definitions(CMAKE_HOST_ARCH=\"${CMAKE_HOST_SYSTEM_PROCESSOR}\")
add_compile_definitions(CMAKE_TARGET_ARCH=\"${CMAKE_SYSTEM_PROCESSOR}\")

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

    if(NOT CMAKE_SYSTEM_NAME STREQUAL "WASI")
        find_library(IS_BLKID_LIB blkid)
        if (IS_BLKID_LIB)
            message(STATUS "Found blkid library for compile-time header definitions")
        endif()
        target_link_libraries(windham m)
    endif()
endfunction()


include(GNUInstallDirs)
# --------------------------------------------------------------------
# define common options
set(WINDHAM_USING_CMAKE ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION}.${CMAKE_PATCH_VERSION})
add_compile_definitions(WINDHAM_USING_CMAKE=\"${WINDHAM_USING_CMAKE}\")

# Platform selection — ISOC is the baseline (no macro needed).
# WASI/Emscripten and GNU/Linux opt in for extra features.
if(CMAKE_SYSTEM_NAME STREQUAL "WASI" OR CMAKE_SYSTEM_NAME STREQUAL "Emscripten")
    add_compile_definitions(WINDHAM_PLAT_WASI)
    # Force-disable all Linux-specific features early (before try_run blocks)
    set(CFG_NO_MODULE_KEYRING ON CACHE BOOL "" FORCE)
    set(WINDHAM_NO_SECCOMP ON CACHE BOOL "" FORCE)
    set(WINDHAM_NO_DISABLE_ATTACH ON CACHE BOOL "" FORCE)
    set(WINDHAM_NO_ENFORCE_SPEC_MITIGATION ON CACHE BOOL "" FORCE)
    set(WINDHAM_NO_SHEBANG_ENTRY ON CACHE BOOL "" FORCE)
    set(CFG_DRIVER_FF ON CACHE BOOL "" FORCE)
    set(CFG_FF_CREATE ON CACHE BOOL "" FORCE)
    set(CFG_DRIVER_DECRYPT ON CACHE BOOL "" FORCE)
else()
    add_compile_definitions(WINDHAM_PLAT_GNU_LINUX)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Emscripten")
    # Web/Emscripten: same platform flags as WASI, plus ASYNCIFY.
    add_compile_definitions(WINDHAM_PLAT_WASI)
    add_compile_definitions(WINDHAM_NO_ISOC_THREAD)
    add_compile_definitions(CFG_NO_MODULE_KEYRING)
    add_compile_definitions(WINDHAM_NO_SECCOMP)
    add_compile_definitions(WINDHAM_NO_DISABLE_ATTACH)
    add_compile_definitions(WINDHAM_NO_ENFORCE_SPEC_MITIGATION)
    add_compile_definitions(WINDHAM_NO_SHEBANG_ENTRY)
    set(CFG_DRIVER_FF ON CACHE BOOL "" FORCE)
    set(CFG_FF_CREATE ON CACHE BOOL "" FORCE)
    set(CFG_DRIVER_DECRYPT ON CACHE BOOL "" FORCE)

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -s ASYNCIFY=1 -s ASSERTIONS=2")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -s ALLOW_MEMORY_GROWTH=1")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -s INITIAL_MEMORY=64MB -s STACK_SIZE=4MB -s MAXIMUM_MEMORY=2GB")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -s FORCE_FILESYSTEM=1")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -s EXPORTED_RUNTIME_METHODS=['ccall','cwrap','FS','callMain']")

    set(CMAKE_EXECUTABLE_SUFFIX ".js")
    add_executable(windham frontend.c)
    set_target_properties(windham PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/web")

elseif(CMAKE_SYSTEM_NAME STREQUAL "WASI")
        add_compile_definitions(CMAKE_TARGET_KERNEL_VERSION=\"wasi\")
        add_compile_definitions(CMAKE_BUILD_TIME=\"WIPED_REPRODUCIBLE\")
    else()
        execute_process(COMMAND uname -r OUTPUT_VARIABLE KERNEL_VERSION OUTPUT_STRIP_TRAILING_WHITESPACE)
        if (WINDHAM_REPRODUCIBLE_BUILD)
            add_compile_definitions(CMAKE_TARGET_KERNEL_VERSION=\"WIPED_REPRODUCIBLE\")
        else ()
            add_compile_definitions(CMAKE_TARGET_KERNEL_VERSION=\"${KERNEL_VERSION}\")
        endif ()

        if (WINDHAM_REPRODUCIBLE_BUILD)
            add_compile_definitions(CMAKE_BUILD_TIME=\"WIPED_REPRODUCIBLE\")
        else ()
            string(TIMESTAMP CURRENT_TIME "%Y-%m-%d %H:%M:%S" UTC)
            add_compile_definitions(CMAKE_BUILD_TIME=\"${CURRENT_TIME}\")
        endif ()
    endif()

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
    if (CFG_DRIVER_FF)
        add_compile_definitions(CFG_DRIVER_FF)
    endif ()

    if (CFG_FF_CREATE)
        add_compile_definitions(CFG_FF_CREATE)
    endif ()

    if (CFG_DRIVER_DECRYPT)
        add_compile_definitions(CFG_DRIVER_DECRYPT)
    endif ()

    # seccomp filter
    if (WINDHAM_NO_SECCOMP)
        add_compile_definitions(WINDHAM_NO_SECCOMP)
    endif ()

    # 32-bit address space limit for Argon2
    if (CFG_32BIT_ADDR_SPACE)
        add_compile_definitions(CFG_32BIT_ADDR_SPACE)
        add_compile_definitions(ARGON2_MAX_MEMORY_BITS=21)
    endif ()

    # force ASCII-only mode (mask UTF-16/UTF-32)
    if (CFG_ASCII)
        add_compile_definitions(CFG_ASCII)
    endif ()

    # allow debugger attach
    if (WINDHAM_NO_DISABLE_ATTACH)
        add_compile_definitions(WINDHAM_NO_DISABLE_ATTACH)
    endif ()

    # disabling Argon2 threads. We are not going to use them. All KDF has p=1
    add_compile_definitions(ARGON2_NO_THREADS)


    # --------------------------------------------------------------------
    # add files
    include_directories(${CMAKE_SOURCE_DIR}/include)

    file(GLOB SHA256_SRC ${CMAKE_SOURCE_DIR}/library/SHA256/*.c)
    file(GLOB tiny_AES_c_SRC ${CMAKE_SOURCE_DIR}/library/tiny_AES_c/*.c)
    file(GLOB HUFFMAN_SRC ${CMAKE_SOURCE_DIR}/library/huffman/*.c)
    file(GLOB cJSON_SRC ${CMAKE_SOURCE_DIR}/library/cJSON/*.c)
    file(GLOB GETOPT_SRC ${CMAKE_SOURCE_DIR}/library/getopt_port/*.c)
    set(FATFS_SRC ${CMAKE_SOURCE_DIR}/library/FatFs/ff.c
                  ${CMAKE_SOURCE_DIR}/library/FatFs/ffunicode.c
                  ${CMAKE_SOURCE_DIR}/library/FatFs/ffsystem.c
                  ${CMAKE_SOURCE_DIR}/library/FatFs/ff_diskio.c)

    set(ARGON2_DIR ${CMAKE_SOURCE_DIR}/library/Argon2)

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

    set(LIBRARY_SOURCES ${Argon2_SRC} ${SHA256_SRC} ${tiny_AES_c_SRC} ${HUFFMAN_SRC} ${cJSON_SRC} ${GETOPT_SRC} ${FATFS_SRC})


    # --------------------------------------------------------------------
    # try-run

    if (CMAKE_CROSSCOMPILING)
        set(RUN_RESULT_VAR FALSE)
        set(RUN_RESULT_VAR__TRYRUN_OUTPUT FALSE)
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
            add_compile_definitions(WINDHAM_NO_ISOC_THREAD)
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

    if (COMPILE_RESULT_VAR EQUAL 0)
        message(WARNING "Your libc does not support getauxval. Shebang entry will be disabled.")
        add_compile_definitions(WINDHAM_NO_SHEBANG_ENTRY)
    elseif (NOT CMAKE_CROSSCOMPILING)
        if (RUN_OUTPUT_VAR EQUAL 1)
            message(WARNING "getauxval return 0 for getauxval(AT_EXECFN). Shebang entry will be disabled.")
            add_compile_definitions(WINDHAM_NO_SHEBANG_ENTRY)
        else ()
            message(STATUS "Shebang entry enabled.")
        endif ()
    else()
        message(STATUS "Cross compiling, Shebang entry enabled without testing.")
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

# --------------------------------------------------------------------
# build targets

if(CMAKE_SYSTEM_NAME STREQUAL "Emscripten")
    # Web/Emscripten: same platform as WASI, compile only frontend.c.
    add_compile_definitions(WINDHAM_NO_ISOC_THREAD)

    set(CMAKE_EXECUTABLE_SUFFIX ".js")
    add_executable(windham-web frontend.c)
    set_target_properties(windham-web PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/web" OUTPUT_NAME windham)

elseif(CMAKE_SYSTEM_NAME STREQUAL "WASI")
    # WASI/ISOC: source files are #include'd via libplat/WASI/init.c
    # and library/include_all_libs.c. Only compile frontend.c.
    add_executable(windham frontend.c)
    set_target_properties(windham PROPERTIES OUTPUT_NAME windham SUFFIX ".wasm")
    configure_global_flags()

elseif (CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_definitions(WINDHAM_NO_DISABLE_ATTACH) # allow attach under debug
    add_compile_definitions(WINDHAM_NO_ENFORCE_SPEC_MITIGATION)
    add_compile_definitions(WINDHAM_SPEC_MITIGATION=-1)

    set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
    add_executable(windham frontend.c ${LIBRARY_SOURCES})
    set_target_properties(windham PROPERTIES OUTPUT_NAME windham_debug)
    configure_global_flags()


elseif (CMAKE_BUILD_TYPE STREQUAL "Release")
    # debugger attach is not allowed under release.
    if (NOT WINDHAM_NO_DISABLE_ATTACH)
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
                add_compile_definitions(WINDHAM_NO_DISABLE_ATTACH)
            endif ()
        else ()
            message(STATUS "Disallow debugger attach using prctl. Use WINDHAM_NO_DISABLE_ATTACH to allow.")
        endif ()
    else()
        message(WARNING "Allowing debugger to attach under \"Release\" target.")
        add_compile_definitions(WINDHAM_NO_DISABLE_ATTACH)
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

# ── Install ──
install(TARGETS windham RUNTIME DESTINATION bin)
install(FILES README.md DESTINATION share/doc/windham)
install(DIRECTORY docs/ DESTINATION share/doc/windham/docs
        FILES_MATCHING PATTERN "*.md")
install(PROGRAMS scripts/windham-raid-setup.sh
        DESTINATION share/windham)