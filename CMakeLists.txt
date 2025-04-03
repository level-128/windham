cmake_minimum_required(VERSION 3.12)
project(windham C)
set(CMAKE_C_STANDARD 11)


if (CMAKE_BUILD_TYPE STREQUAL "ISOC")
    add_executable(windham frontend.c)
    install(TARGETS windham
            RUNTIME DESTINATION ${CMAKE_INSTALL_BIN})
    return()
endif()

if (NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "non-Linux platform only supports ISOC build type. Use -DCMAKE_BUILD_TYPE=ISOC.")
endif ()


set(WINDHAM_AMD64_NAMES amd64 AMD64 x86_64)
if (CMAKE_SYSTEM_PROCESSOR IN_LIST WINDHAM_AMD64_NAMES)
    set(ARCH "x86_64")
else ()
    set(ARCH "other")
endif ()


set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Release" "Debug" "Test")
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the build type (default: Release)" FORCE)
endif ()


# --------------------------------------------------------------------
# define options

file(READ "${CMAKE_CURRENT_SOURCE_DIR}/version.txt" WINDHAM_VERSION)
string(STRIP "${WINDHAM_VERSION}" WINDHAM_VERSION)
add_compile_definitions(WINDHAM_VERSION=\"${WINDHAM_VERSION}\")

string(TIMESTAMP CURRENT_TIME "%Y-%m-%d %H:%M:%S" UTC)
add_compile_definitions(CURRENT_TIME=\"${CURRENT_TIME}\")

set(CMAKE_VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION}.${CMAKE_PATCH_VERSION})
add_compile_definitions(CMAKE_VERSION=\"${CMAKE_VERSION}\")

execute_process(COMMAND uname -r OUTPUT_VARIABLE KERNEL_VERSION OUTPUT_STRIP_TRAILING_WHITESPACE)
add_compile_definitions(TARGET_KERNEL_VERSION=\"${KERNEL_VERSION}\")

add_compile_definitions(HOST_ARCH=\"${CMAKE_HOST_SYSTEM_PROCESSOR}\")
add_compile_definitions(TARGET_ARCH=\"${CMAKE_SYSTEM_PROCESSOR}\")


set(WINDHAM_DEFAULT_DISK_ENC_MODE_LIST "aes-xts-plain64" "twofish-xts-plain64"
    "serpent-xts-plain64" "twofish-xts-plain64be" "aes-xts-plain64be" "serpent-xts-plain64be")
if (NOT CFG_WINDHAM_DEFAULT_DISK_ENC_MODE)
    set(CFG_WINDHAM_DEFAULT_DISK_ENC_MODE "aes-xts-plain64")
elseif (NOT CFG_WINDHAM_DEFAULT_DISK_ENC_MODE IN_LIST WINDHAM_DEFAULT_DISK_ENC_MODE_LIST)
    message(FATAL_ERROR "Unknown encryption mode ${WINDHAM_DEFAULT_DISK_ENC_MODE}. accept values are: ${CFG_WINDHAM_DEFAULT_DISK_ENC_MODE_LIST}")
endif ()
add_compile_definitions(DEFAULT_DISK_ENC_MODE="${CFG_WINDHAM_DEFAULT_DISK_ENC_MODE}")


if(CFG_DEFAULT_TARGET_TIME)
add_compile_definitions(DEFAULT_TARGET_TIME=${CFG_DEFAULT_TARGET_TIME})
endif()

if(CFG_MAX_UNLOCK_TIME_FACTOR)
add_compile_definitions(MAX_UNLOCK_TIME_FACTOR=${CFG_MAX_UNLOCK_TIME_FACTOR})
endif()

if(CFG_DEFAULT_BLOCK_SIZE)
add_compile_definitions(DEFAULT_BLOCK_SIZE=${CFG_DEFAULT_BLOCK_SIZE})
endif()

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

if (CFG_WINDHAMTAB_FILE)
    add_compile_definitions(WINDHAMTAB_FILE=${CFG_WINDHAMTAB_FILE})
endif()

if (CFG_MIN_MEMLOCK_SIZE)
    add_compile_definitions(DEFAULT_MIN_MEMLOCK_SIZE=${CFG_MIN_MEMLOCK_SIZE})
endif()


# disabling Argon2 threads. We are not going to use them.
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
    message("SIMD optimization disabled.")
    file(GLOB Argon2_SRC ${ARGON2_DIR}/argon2.c ${ARGON2_DIR}/core.c ${ARGON2_DIR}/encoding.c ${ARGON2_DIR}/ref.c
            ${ARGON2_DIR}/thread.c ${ARGON2_DIR}/blake2/blake2b.c)
elseif (ARCH STREQUAL "x86_64")
    message("Use x86-64 platform optimization")
    file(GLOB Argon2_SRC ${ARGON2_DIR}/argon2.c ${ARGON2_DIR}/core.c ${ARGON2_DIR}/encoding.c ${ARGON2_DIR}/opt.c
            ${ARGON2_DIR}/thread.c ${ARGON2_DIR}/blake2/blake2b.c)
else ()
    file(GLOB Argon2_SRC ${ARGON2_DIR}/argon2.c ${ARGON2_DIR}/core.c ${ARGON2_DIR}/encoding.c ${ARGON2_DIR}/ref.c
            ${ARGON2_DIR}/thread.c ${ARGON2_DIR}/blake2/blake2b.c)
endif ()


# --------------------------------------------------------------------
# try-run

if (CFG_NO_MODULE_KEYRING)
    add_compile_definitions(NO_KEYCTL)
    message("Linux kernel retention disabled")
else ()
    try_run(
            RUN_RESULT_VAR
            COMPILE_RESULT_VAR
            ${CMAKE_BINARY_DIR}/temp
            SOURCES ${CMAKE_SOURCE_DIR}/build_misc/check_keyctl.c
            COMPILE_OUTPUT_VARIABLE COMPILE_OUTPUT_VAR
            RUN_OUTPUT_VARIABLE RUN_OUTPUT_VAR
    )
    if (NOT COMPILE_RESULT_VAR OR NOT RUN_RESULT_VAR EQUAL 0)
        add_compile_definitions(NO_KEYCTL)
        message(WARNING "System call \"SYS_keyctl\" unsupported by this kernel. Disabling Linux kernel key
        retention service.")
    endif ()
endif ()


if (NOT CFG_NO_ENFORCE_SPEC_MITIGATION)
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


if (CMAKE_BUILD_TYPE STREQUAL "Release")
    if (NOT CFG_WINDHAM_ALLOW_ATTACH)
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
        add_compile_definitions(WINDHAM_ALLOW_ATTACH)
    endif ()
else ()
    add_compile_definitions(WINDHAM_ALLOW_ATTACH) # allow attach under debug
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
    message(WARNING "Cannot compile test <thread.h> program, build may fail. Your system may requires additional\
    link-time libraries to enable ISO C thread. Use environment CFLAGS= to designate required libraries. Common\
    platforms may require \"-lpthread\"; try this first.")
elseif (RUN_OUTPUT_VAR EQUAL 1)
    message(WARNING "Sample ISO C multithread program occurred a runtime error. Disabling ISO C thread support.\
    Unlocking will be up to two times slower.")
    add_compile_definitions(WINDHAM_NO_ISOC_THREAD)
elseif (RUN_OUTPUT_VAR EQUAL 2)
    message(WARNING "ISO C threading support not available on this platform. Disabling ISO C thread support.\
    Unlocking will be up to two times slower.")
endif ()


# --------------------------------------------------------------------
# build function
function(add_argon2_and_executables_for_arch target_name)
    if (target_name STREQUAL "windham_test")
        add_executable(windham test/test.c
                       ${Argon2_SRC} ${SHA256_SRC} ${tiny_AES_c_SRC} ${HUFFMAN_SRC} ${cJSON_SRC} ${GETOPT_SRC})
    else ()
        add_executable(windham frontend.c
                       ${Argon2_SRC} ${SHA256_SRC} ${tiny_AES_c_SRC} ${HUFFMAN_SRC} ${cJSON_SRC} ${GETOPT_SRC})
    endif ()
    set_target_properties(windham PROPERTIES COMPILE_FLAGS ${CMAKE_C_FLAGS})
    target_link_libraries(windham blkid)

    add_definitions("-DCOMPILE_PARAMS=\"${CMAKE_C_FLAGS}\"")
    set_target_properties(windham PROPERTIES OUTPUT_NAME ${target_name})
    install(TARGETS windham
            RUNTIME DESTINATION ${CMAKE_INSTALL_BIN})
endfunction()


# --------------------------------------------------------------------
# build targets

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}  -Wall -Wextra -ggdb -g -O0")
    add_argon2_and_executables_for_arch("windham_debug")

elseif (CMAKE_BUILD_TYPE STREQUAL "Release")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
    add_argon2_and_executables_for_arch("windham")

elseif (CMAKE_BUILD_TYPE STREQUAL "Test")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -ggdb -O0 -Wno-unused-parameter -Wno-type-limits -Wno-sign-compare -Wno-clobbered")
    add_executable(windham test/test.c
            ${Argon2_SRC} ${SHA256_SRC} ${tiny_AES_c_SRC} ${HUFFMAN_SRC} ${cJSON_SRC} ${GETOPT_SRC})

endif()