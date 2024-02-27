cmake_minimum_required(VERSION 3.20)
project(windham C)
set(CMAKE_C_STANDARD 23)
enable_language(ASM)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# --------------------------------------------------------------------
# define options

if (NOT DEFINED TARGET_ARCHITECTURE)
    set(TARGET_ARCHITECTURE "native" CACHE STRING "Target Architecture")
endif ()

if (NOT DEFINED WINDHAM_DEFAULT_DISK_ENC_MODE)
    set(WINDHAM_DEFAULT_DISK_ENC_MODE "aes-xts-plain64" CACHE STRING "default encryption mode")
endif ()

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the build type (default: Release)" FORCE)
endif()

if(NOT DEFINED AARCH64_USE_NEON)
    set(AARCH64_USE_NEON ON CACHE BOOL "Use NEON when TARGET_ARCHITECTURE=aarch64")
endif()

if(NOT DEFINED NO_SIMD_OPTIMIZE)
    set(NO_SIMD_OPTIMIZE OFF CACHE BOOL "Disable SIMD optimization, use portable C implementation instead.")
endif()

if(NOT DEFINED WIPE_MEMORY)
    set(WIPE_MEMORY OFF CACHE BOOL "Wiping the memory after key operations")
endif()

if(NOT DEFINED COMPILIER_OPT)
    set(COMPILIER_OPT "-O3" CACHE STRING "Compilier optmization parameter")
endif()

if(NOT DEFINED COMPILIER_ENABLE_LTO)
    set(COMPILIER_ENABLE_LTO ON CACHE STRING "Enable LTO optmization")
endif()

set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Release" "Debug" "Test" "Language")
set_property(CACHE TARGET_ARCHITECTURE PROPERTY STRINGS "native" "x86_64" "aarch64" "riscv64")
set_property(CACHE WINDHAM_DEFAULT_DISK_ENC_MODE PROPERTY STRINGS "aes-xts-plain64" "twofish-xts-plain64"
        "serpent-xts-plain64" "twofish-xts-plain64be" "aes-xts-plain64be" "serpent-xts-plain64be")
set_property(CACHE COMPILIER_OPT PROPERTY STRINGS "-O3" "-O2" "-Os")


set(CMAKE_INSTALL_BIN "/usr/sbin" CACHE STRING "Set install location" FORCE)
if(NOT DEFINED x86_64_compiler)
set(x86_64_compiler "" CACHE STRING "Set default x86_64 compiler. must be set when target arch is x86_64" FORCE)
endif ()
if(NOT DEFINED aarch64_compiler)
set(aarch64_compiler "" CACHE STRING "Set default aarch64 compiler. must be set when target arch is aarch64" FORCE)
endif ()
if(NOT DEFINED riscv64_compiler)
set(riscv64_compiler "" CACHE STRING "Set default riscv64 compiler. must be set when target arch is riscv64" FORCE)
endif ()

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

# --------------------------------------------------------------------
# add files
include_directories(${CMAKE_SOURCE_DIR}/include)

file(GLOB Argon2_SRC ${CMAKE_SOURCE_DIR}/library/Argon2B3/*.c)
file(GLOB SHA256_SRC ${CMAKE_SOURCE_DIR}/library/SHA256/*.c)
file(GLOB tiny_AES_c_SRC ${CMAKE_SOURCE_DIR}/library/tiny_AES_c/*.c)
file(GLOB PROGRESSBAR_SRC ${CMAKE_SOURCE_DIR}/library/progressbar/*.c)
file(GLOB HUFFMAN_SRC ${CMAKE_SOURCE_DIR}/library/huffman/*.c)
file(GLOB cJSON_SRC ${CMAKE_SOURCE_DIR}/library/cJSON/*.c)

set(BLAKE3_AMD64_NAMES amd64 AMD64 x86_64)
set(BLAKE3_ARM_NAMES aarch64 AArch64 arm64 ARM64)

set(BLAKE_DIR ${CMAKE_SOURCE_DIR}/library/blake3)


if((CMAKE_SYSTEM_PROCESSOR IN_LIST BLAKE3_AMD64_NAMES AND TARGET_ARCHITECTURE STREQUAL "native") OR TARGET_ARCHITECTURE STREQUAL "x86_64")
    file(GLOB Blake3_SRC ${BLAKE_DIR}/blake3.c ${BLAKE_DIR}/blake3_dispatch.c ${BLAKE_DIR}/blake3_portable.c ${BLAKE_DIR}/blake3_sse2_x86-64_unix.S
            ${BLAKE_DIR}/blake3_sse41_x86-64_unix.S ${BLAKE_DIR}/blake3_avx2_x86-64_unix.S ${BLAKE_DIR}/blake3_avx512_x86-64_unix.S)
elseif((CMAKE_SYSTEM_PROCESSOR IN_LIST BLAKE3_ARM_NAMES AND TARGET_ARCHITECTURE STREQUAL "native") OR TARGET_ARCHITECTURE STREQUAL "aarch64")
    file(GLOB Blake3_SRC ${BLAKE_DIR}/blake3.c ${BLAKE_DIR}/blake3_dispatch.c ${BLAKE_DIR}/blake3_portable.c ${BLAKE_DIR}/blake3_neon.c)
else()
    file(GLOB Blake3_SRC ${BLAKE_DIR}/blake3.c ${BLAKE_DIR}/blake3_dispatch.c ${BLAKE_DIR}/blake3_portable.c)
endif ()

# --------------------------------------------------------------------
# compile according to arch
function(add_argon2_and_executables_for_arch arch)
        add_executable(windham${arch} frontend.c  
            ${Blake3_SRC} ${Argon2_SRC} ${SHA256_SRC} ${tiny_AES_c_SRC} ${PROGRESSBAR_SRC} ${HUFFMAN_SRC} ${cJSON_SRC})
        target_link_libraries(windham${arch} ncurses m dl pthread)
        if(NOT arch STREQUAL "")
            set_target_properties(windham${arch} PROPERTIES COMPILE_FLAGS "-march=${arch}")
        endif()
        if(arch STREQUAL "native")
            set_target_properties(windham${arch} PROPERTIES OUTPUT_NAME "windham")
        endif()
        add_definitions("-DCOMPILE_PARAMS=\"${CMAKE_C_FLAGS}\"")
        install(TARGETS windham${arch}
                RUNTIME DESTINATION ${install_location})
endfunction()


# --------------------------------------------------------------------
# build targets

set(CMAKE_AR "gcc-ar")
set(CMAKE_NM "gcc-nm")
set(CMAKE_RANLIB "gcc-ranlib")

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions(-DARGON2_FLAG_CLEAR_MEMORY=0)
    add_definitions(-DDEFAULT_DISK_ENC_MODE="aes-xts-plain64")
    include_directories(${CMAKE_SOURCE_DIR}/include/linux_fs_include)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}  -Wall -Wextra -g -O0")
    add_argon2_and_executables_for_arch("x86-64-v2")

elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
    if(NO_SIMD_OPTIMIZE)
        add_definitions(-D__Argon2_opt_disable__)
    endif ()
    if (NOT WIPE_MEMORY)
        add_definitions(-DARGON2_FLAG_CLEAR_MEMORY=0)
    endif ()
    add_definitions(-DDEFAULT_DISK_ENC_MODE="${WINDHAM_DEFAULT_DISK_ENC_MODE}")

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${COMPILIER_OPT} -g3")
    if (COMPILIER_ENABLE_LTO)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -flto=auto -fwhole-program -fno-fat-lto-objects")
    endif()

    if(TARGET_ARCHITECTURE STREQUAL "x86_64")
        include_directories(${CMAKE_SOURCE_DIR}/include/linux_fs_system)
        if (x86_64_compiler STREQUAL "")
            message( FATAL_ERROR "no x86_64_compiler given." )
        endif ()
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprefetch-loop-arrays ")
        set(CMAKE_C_COMPILER ${x86_64_compiler})
        add_argon2_and_executables_for_arch("x86-64-v2")
        add_argon2_and_executables_for_arch("x86-64-v3")
        add_argon2_and_executables_for_arch("x86-64-v4")

    elseif(TARGET_ARCHITECTURE STREQUAL "aarch64")
        include_directories(${CMAKE_SOURCE_DIR}/include/linux_fs_system)
        if (aarch64_compiler STREQUAL "")
            message( FATAL_ERROR "no aarch64_compiler given." )
        endif ()
        if(AARCH64_USE_NEON)
            add_definitions(-DBLAKE3_USE_NEON=1)
        endif()

        set(CMAKE_C_COMPILER ${aarch64_compiler})
        add_argon2_and_executables_for_arch("armv8.5-a")
        add_argon2_and_executables_for_arch("armv9-a")

    elseif(TARGET_ARCHITECTURE STREQUAL "riscv64")
        include_directories(${CMAKE_SOURCE_DIR}/include/linux_fs_system)
        if (riscv64_compiler STREQUAL "")
            message( FATAL_ERROR "no riscv64_compiler given." )
        endif ()
        set(CMAKE_C_COMPILER ${riscv64_compiler})
        add_argon2_and_executables_for_arch("rv64imafdc")

    elseif(TARGET_ARCHITECTURE STREQUAL "native")
        include_directories(${CMAKE_SOURCE_DIR}/include/linux_fs_system)
        if(CMAKE_SYSTEM_PROCESSOR IN_LIST BLAKE3_AMD64_NAMES)
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mtune=native")
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprefetch-loop-arrays ")
            add_argon2_and_executables_for_arch("native")
        elseif(CMAKE_SYSTEM_PROCESSOR IN_LIST BLAKE3_ARM_NAMES)
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mtune=native")
            add_argon2_and_executables_for_arch("native")
        else()
            add_argon2_and_executables_for_arch("")
        endif()

    else()
        message( FATAL_ERROR "unknown arch. Arch must be one of the x86_64 aarch64 riscv64 or native" )
    endif()

elseif(CMAKE_BUILD_TYPE STREQUAL "Test")

    add_definitions(-DARGON2_FLAG_CLEAR_MEMORY=0)
    add_definitions(-DDEFAULT_DISK_ENC_MODE="aes-xts-plain64")
    include_directories(${CMAKE_SOURCE_DIR}/include/linux_fs_include)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}  -Wall -Wextra -g3 -O3") # ensure speed

    add_executable(windham_test test/test.c  
        ${Blake3_SRC} ${Argon2_SRC} ${SHA256_SRC} ${tiny_AES_c_SRC} ${PROGRESSBAR_SRC} ${HUFFMAN_SRC} ${cJSON_SRC})
    target_link_libraries(windham_test ncurses m dl pthread)
    set_target_properties(windham_test PROPERTIES COMPILE_FLAGS "-march=native")
    add_definitions("-DCOMPILE_PARAMS=\"${CMAKE_C_FLAGS}\"")
    install(TARGETS windham_test RENAME windham_test)

elseif(CMAKE_BUILD_TYPE STREQUAL "Language")
    # update translations
    set(LANGUAGES fr zh_CN)
    add_custom_target(update_translations ALL
            DEPENDS ${CMAKE_SOURCE_DIR}/locale/windham.pot)

    add_custom_command(
            OUTPUT ${CMAKE_SOURCE_DIR}/locale/windham.pot
            COMMAND xgettext --from-code=UTF-8 -k_ -L C --no-location  -o ${CMAKE_SOURCE_DIR}/locale/windham.pot ${CMAKE_SOURCE_DIR}/frontend.c ${CMAKE_SOURCE_DIR}/backend.c ${CMAKE_SOURCE_DIR}/mapper.c
            ${CMAKE_SOURCE_DIR}/argon_bench.c
            ${CMAKE_SOURCE_DIR}/enclib.c ${CMAKE_SOURCE_DIR}/library_intrnlsrc/srclib.c
            COMMENT "Generating windham.pot from source code"
    )

    foreach(LANG ${LANGUAGES})
        add_custom_command(
                TARGET update_translations
                COMMAND msgmerge --update ${CMAKE_SOURCE_DIR}/locale/${LANG}/LC_MESSAGES/windham.po ${CMAKE_SOURCE_DIR}/locale/windham.pot
                COMMENT "Updating ${LANG}/windham.po"
        )
    endforeach()

    add_custom_target(compile_translations)
    foreach(LANG ${LANGUAGES})
        add_custom_command(
                TARGET compile_translations
                COMMAND msgfmt -c -o locale/${LANG}/LC_MESSAGES/windham.mo locale/${LANG}/LC_MESSAGES/windham.po
                COMMENT "Compiling ${LANG}/windham.po"
        )
    endforeach()

endif()
