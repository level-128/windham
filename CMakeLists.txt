# this makefile works on my opensuse tumbleweed. If you are not running this distro, you might need to change your compiler path.

set(x86_64_compiler "gcc")
set(aarch64_compiler "arm-suse-linux-gnueabi-gcc")
set(riscv64_compiler "riscv64-suse-linux-gcc")

set(target_arch "native") # X86_64 aarch64 riscv64 or native


cmake_minimum_required(VERSION 3.24)
project(windham C)
set(CMAKE_C_STANDARD 23)
enable_language(ASM)


if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Set the default build type" FORCE)
endif()

# add files
include_directories(${CMAKE_SOURCE_DIR}/include)

file(GLOB Argon2_SRC ${CMAKE_SOURCE_DIR}/library/Argon2B3/*.c)
file(GLOB SHA256_SRC ${CMAKE_SOURCE_DIR}/library/SHA256/*.c)
file(GLOB tiny_AES_c_SRC ${CMAKE_SOURCE_DIR}/library/tiny_AES_c/*.c)

set(BLAKE3_AMD64_NAMES amd64 AMD64 x86_64)
set(BLAKE3_ARM_NAMES aarch64 AArch64 arm64 ARM64)

set(BLAKE_DIR ${CMAKE_SOURCE_DIR}/library/blake3)
if(CMAKE_SYSTEM_PROCESSOR IN_LIST BLAKE3_AMD64_NAMES)
    set(CMAKE_C_COMPILER ${x86_64_compiler})
    file(GLOB Blake3_SRC ${BLAKE_DIR}/blake3.c ${BLAKE_DIR}/blake3_dispatch.c ${BLAKE_DIR}/blake3_portable.c ${BLAKE_DIR}/blake3_sse2_x86-64_unix.S
            ${BLAKE_DIR}/blake3_sse41_x86-64_unix.S ${BLAKE_DIR}/blake3_avx2_x86-64_unix.S ${BLAKE_DIR}/blake3_avx512_x86-64_unix.S)
elseif(CMAKE_SYSTEM_PROCESSOR IN_LIST BLAKE3_ARM_NAMES)
    set(CMAKE_C_COMPILER ${aarch64_compiler})
    file(GLOB Blake3_SRC ${BLAKE_DIR}/blake3.c ${BLAKE_DIR}/blake3_dispatch.c ${BLAKE_DIR}/blake3_portable.c ${BLAKE_DIR}/blake3_neon.c)
else()
    set(CMAKE_C_COMPILER ${riscv64_compiler})
    file(GLOB Blake3_SRC ${BLAKE_DIR}/blake3.c ${BLAKE_DIR}/blake3_dispatch.c ${BLAKE_DIR}/blake3_portable.c)
endif ()


# compile according to arch
function(add_argon2_and_executables_for_arch arch)
    if(CMAKE_BUILD_TYPE STREQUAL "Test")
        add_executable(windham_test test/test.c  ${Blake3_SRC} ${Argon2_SRC} ${SHA256_SRC} ${tiny_AES_c_SRC})
        set_target_properties(windham_test PROPERTIES COMPILE_FLAGS "-march=${arch}")
        install(TARGETS windham_test
                RUNTIME DESTINATION bin
                RENAME windham_test)
    endif()

    add_executable(windham_${arch} frontend.c  ${Blake3_SRC} ${Argon2_SRC} ${SHA256_SRC} ${tiny_AES_c_SRC})
    set_target_properties(windham_${arch} PROPERTIES COMPILE_FLAGS "-march=${arch}")
    if(arch STREQUAL "native")
        set_target_properties(windham_${arch} PROPERTIES OUTPUT_NAME "windham")
    endif()
    install(TARGETS windham_${arch}
            RUNTIME DESTINATION /usr/sbin)

endfunction()



if(CMAKE_BUILD_TYPE STREQUAL "Test")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}  -Wall -Wextra -g -O0")
    add_argon2_and_executables_for_arch("native")

elseif(CMAKE_BUILD_TYPE STREQUAL "Release")

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -flto=auto")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprefetch-loop-arrays")
    set(CMAKE_AR "gcc-ar")
    set(CMAKE_NM "gcc-nm")
    set(CMAKE_RANLIB "gcc-ranlib")

    if(target_arch STREQUAL "x86_64")

        add_argon2_and_executables_for_arch("haswell")
        add_argon2_and_executables_for_arch("tigerlake")
        add_argon2_and_executables_for_arch("sapphirerapids")
        add_argon2_and_executables_for_arch("znver3")

    elseif(target_arch STREQUAL "aarch64")

        add_argon2_and_executables_for_arch("armv8.5-a")
        add_argon2_and_executables_for_arch("armv9-a")

    elseif(target_arch STREQUAL "riscv64")
        add_argon2_and_executables_for_arch("rv64imafdc")

    elseif(target_arch STREQUAL "native")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mtune=native")
        add_argon2_and_executables_for_arch("native")

    else()
        message( FATAL_ERROR "unknown arch" )
    endif()

elseif(CMAKE_BUILD_TYPE STREQUAL "Language")
    # update translations
    set(LANGUAGES fr zh_CN)
    add_custom_target(update_translations ALL
            DEPENDS ${CMAKE_SOURCE_DIR}/locale/windham.pot)

    add_custom_command(
            OUTPUT ${CMAKE_SOURCE_DIR}/locale/windham.pot
            COMMAND xgettext -k_ -L C --no-location  -o ${CMAKE_SOURCE_DIR}/locale/windham.pot ${CMAKE_SOURCE_DIR}/frontend.c ${CMAKE_SOURCE_DIR}/backend.c ${CMAKE_SOURCE_DIR}/mapper.c
            ${CMAKE_SOURCE_DIR}/enclib.c ${CMAKE_SOURCE_DIR}/srclib.c
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
