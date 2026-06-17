cmake_minimum_required(VERSION 3.16)
project(windham C)
set(CMAKE_C_STANDARD 11)

# --------------------------------------------------------------------
# define build type

set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Release" "Debug" "Test" "ISOC")
if (NOT CMAKE_BUILD_TYPE)
    if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
        set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the build type <Release | Debug | Test | ISOC>
         (default: Release)" FORCE)
    else()
        set(CMAKE_BUILD_TYPE ISOC CACHE STRING "Choose the build type. ISOC is the only supported build
         type under this system." FORCE)
    endif ()
endif ()

if (NOT CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT CMAKE_BUILD_TYPE STREQUAL "ISOC")
    message(FATAL_ERROR "non-Linux platform only supports ISOC build type.")
endif ()

# --------------------------------------------------------------------
# define CPU arch and version number

file(READ "build_misc/version.txt" WINDHAM_VERSION)
string(STRIP "${WINDHAM_VERSION}" WINDHAM_VERSION)
add_compile_definitions(WINDHAM_VERSION=\"${WINDHAM_VERSION}\")

add_compile_definitions(HOST_ARCH=\"${CMAKE_HOST_SYSTEM_PROCESSOR}\")
add_compile_definitions(TARGET_ARCH=\"${CMAKE_SYSTEM_PROCESSOR}\")

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

set(WINDHAM_DEFAULT_DISK_ENC_MODE_LIST "aes-xts-plain64" "twofish-xts-plain64"
        "serpent-xts-plain64" "twofish-xts-plain64be" "aes-xts-plain64be" "serpent-xts-plain64be" "uninit")
if (NOT CFG_WINDHAM_DEFAULT_DISK_ENC_MODE)
    if(CMAKE_BUILD_TYPE STREQUAL "ISOC")
        set(CFG_WINDHAM_DEFAULT_DISK_ENC_MODE "aes-xts-plain64")
    else()
        set(CFG_WINDHAM_DEFAULT_DISK_ENC_MODE "aes-xts-plain64")
    endif()
elseif (NOT CFG_WINDHAM_DEFAULT_DISK_ENC_MODE IN_LIST WINDHAM_DEFAULT_DISK_ENC_MODE_LIST)
    message(FATAL_ERROR "Unknown encryption mode ${WINDHAM_DEFAULT_DISK_ENC_MODE}. accept values are:
    ${CFG_WINDHAM_DEFAULT_DISK_ENC_MODE_LIST}")
else()
    if(CMAKE_BUILD_TYPE STREQUAL "ISOC" AND CFG_WINDHAM_DEFAULT_DISK_ENC_MODE STREQUAL "uninit")
        message(WARNING "using encryption mode other than uninit under ISOC build type will init the device and"
        "forcing windham to open at such type on other platforms.")
    endif()
endif ()
add_compile_definitions(DEFAULT_DISK_ENC_MODE="${CFG_WINDHAM_DEFAULT_DISK_ENC_MODE}")

# --------------------------------------------------------------------
# define compiler options

function(configure_global_flags)
    if(CMAKE_BUILD_TYPE MATCHES "^(Release|ISOC)$")
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
    add_compile_definitions(COMPILE_PARAMS="${CMAKE_C_FLAGS}")

    if(CMAKE_BUILD_TYPE STREQUAL "ISOC")
        if(UNIX)
            find_library(IS_MATH_LIB m)
            if (IS_MATH_LIB STREQUAL IS_MATH_LIB-NOTFOUND)
                message(WARNING "cannot find math library. Use CMAKE_C_FLAGS to designate the math library for your
                platform. compilation may fail if your libc requires linking with the math library to use math functions.")
            else()
                target_link_libraries(windham m)
            endif()
        else()
            message(WARNING "Please link the math library if your platform requires it. Windham does not know what to
            do because you are not running under UNIX-like systems. You can try compiling first to figure out whether
            explicitly linking with math library is required under your platform.")
        endif()
    else()
        find_library(IS_BLKID_LIB blkid REQUIRED)
        target_link_libraries(windham blkid m)
    endif()
endfunction()


# --------------------------------------------------------------------
# ISOC build type

if (CMAKE_BUILD_TYPE STREQUAL "ISOC")
    add_executable(windham frontend.c)
    configure_global_flags()
    install(TARGETS windham
            RUNTIME DESTINATION ${CMAKE_INSTALL_BIN})
else ()
    include(GNUInstallDirs)
    # --------------------------------------------------------------------
    # define common options
    set(WINDHAM_USING_CMAKE ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION}.${CMAKE_PATCH_VERSION})
    add_compile_definitions(WINDHAM_USING_CMAKE=\"${WINDHAM_USING_CMAKE}\")

    execute_process(COMMAND uname -r OUTPUT_VARIABLE KERNEL_VERSION OUTPUT_STRIP_TRAILING_WHITESPACE)
    add_compile_definitions(TARGET_KERNEL_VERSION=\"${KERNEL_VERSION}\")

    string(TIMESTAMP CURRENT_TIME "%Y-%m-%d %H:%M:%S" UTC)
    add_compile_definitions(CURRENT_TIME=\"${CURRENT_TIME}\")

    if(CFG_DEFAULT_DISK_ENC_MEM_RATIO_CAP)
        add_compile_definitions(DEFAULT_DISK_ENC_MEM_RATIO_CAP=${CFG_DEFAULT_DISK_ENC_MEM_RATIO_CAP})
    endif()

    if (CFG_USE_SWAP)
        add_compile_definitions(CONFIG_USE_SWAP)
    endif ()

    if (CFG_WIPE_MEMORY)
        add_compile_definitions(ARGON2_CLEAR_INTERNAL_MEMORY=1)
    else ()
        add_compile_definitions(ARGON2_CLEAR_INTERNAL_MEMORY=0)
    endif ()

    if (CFG_MIN_MEMLOCK_SIZE)
        add_compile_definitions(DEFAULT_MIN_MEMLOCK_SIZE=${CFG_MIN_MEMLOCK_SIZE})
    endif()

    if (CFG_WINDHAMTAB_FILE)
        add_compile_definitions(WINDHAMTAB_FILE=${CFG_WINDHAMTAB_FILE})
    endif()

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

    set(LIBRARY_SOURCES ${Argon2_SRC} ${SHA256_SRC} ${tiny_AES_c_SRC} ${HUFFMAN_SRC} ${cJSON_SRC} ${GETOPT_SRC})


    # --------------------------------------------------------------------
    # try-run

    if (CMAKE_CROSSCOMPILING)
        set(RUN_RESULT_VAR FALSE)
        set(RUN_RESULT_VAR__TRYRUN_OUTPUT FALSE)
    endif()

    # test keyctl
    if (CFG_NO_MODULE_KEYRING)
        add_compile_definitions(NO_KEYCTL)
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
                add_compile_definitions(NO_KEYCTL)
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

endif ()

# --------------------------------------------------------------------
# build targets

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_definitions(WINDHAM_ALLOW_ATTACH) # allow attach under debug
    add_compile_definitions(WINDHAM_SPEC_MITIGATION=-1)

    set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
    add_executable(windham frontend.c ${LIBRARY_SOURCES})
    set_target_properties(windham PROPERTIES OUTPUT_NAME windham_debug)
    configure_global_flags()


elseif (CMAKE_BUILD_TYPE STREQUAL "Release")
    # debugger attach is not allowed under release.
    if (NOT CFG_WINDHAM_ALLOW_ATTACH)
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
                add_compile_definitions(WINDHAM_ALLOW_ATTACH)
            endif ()
        else ()
            message(STATUS "Disallow debugger attach using prctl. Use CFG_WINDHAM_ALLOW_ATTACH to allow.")
        endif ()
    else()
        message(WARNING "Allowing debugger to attach under \"Release\" target.")
        add_compile_definitions(WINDHAM_ALLOW_ATTACH)
    endif()

    # detect spectre mitigation
    if (NOT CFG_NO_ENFORCE_SPEC_MITIGATION AND NOT CMAKE_CROSSCOMPILING)
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
            add_compile_definitions(WINDHAM_SPEC_MITIGATION=-1)
        else () # 2 (not needed) or 0 (okay) are possible.
            add_compile_definitions(WINDHAM_SPEC_MITIGATION=${RUN_RESULT_VAR})
        endif ()
    else ()
        add_compile_definitions(WINDHAM_SPEC_MITIGATION=-1)
    endif ()

    add_executable(windham frontend.c ${LIBRARY_SOURCES})
    configure_global_flags()
    install(TARGETS windham
            RUNTIME DESTINATION bin)

elseif (CMAKE_BUILD_TYPE STREQUAL "Test")
    message(STATUS "Test build type uses Python test suite (tests/run_tests.py).")
    message(STATUS "Build with Debug or Release type, then run: python3 tests/run_tests.py")
    add_compile_definitions(WINDHAM_TEST)

endif()

# ── Install ──
install(TARGETS windham RUNTIME DESTINATION bin)
install(FILES README.md DESTINATION share/doc/windham)
install(DIRECTORY docs/ DESTINATION share/doc/windham/docs
        FILES_MATCHING PATTERN "*.md")
install(PROGRAMS scripts/windham-raid-setup.sh
        DESTINATION share/windham)