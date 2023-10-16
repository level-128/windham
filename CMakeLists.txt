cmake_minimum_required(VERSION 3.24)
project(windham C)

option(USE_SPECIFIC_COMPILER "Use a specific compiler" OFF)
option(INCLUDE_BENCH "Include Argon2 benchmark program" ON)

if(USE_SPECIFIC_COMPILER)
    set(CMAKE_C_COMPILER "/path/to/gcc/compiler")
endif()
set(CMAKE_C_STANDARD 23)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Set the default build type" FORCE)
endif()

include_directories(${CMAKE_SOURCE_DIR}/include)

file(GLOB Argon2_SRC ${CMAKE_SOURCE_DIR}/library/Argon2/*.c)
file(GLOB SHA256_SRC ${CMAKE_SOURCE_DIR}/library/SHA256/*.c)
file(GLOB tiny_AES_c_SRC ${CMAKE_SOURCE_DIR}/library/tiny_AES_c/*.c)


function(add_argon2_and_executables_for_arch arch)

    if(INCLUDE_BENCH)
        add_executable(windham_argonbench_${arch} argon_bench.c ${Argon2_SRC})
        set_target_properties(windham_argonbench_${arch} PROPERTIES COMPILE_FLAGS "-march=${arch} -mtune=intel")
        install(TARGETS windham_argonbench_${arch}
                RUNTIME DESTINATION bin
                RENAME windham_argonbench)
    endif()
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_executable(windham_test test/test.c ${Argon2_SRC} ${SHA256_SRC} ${tiny_AES_c_SRC})
        set_target_properties(windham_test PROPERTIES COMPILE_FLAGS "-march=${arch}")
        install(TARGETS windham_test
                RUNTIME DESTINATION bin
                RENAME windham_test)
    endif()

    add_executable(windham_${arch} frontend.c ${Argon2_SRC} ${SHA256_SRC} ${tiny_AES_c_SRC})
    set_target_properties(windham_${arch} PROPERTIES COMPILE_FLAGS "-march=${arch} -mtune=intel")
    install(TARGETS windham_${arch}
            RUNTIME DESTINATION bin)

endfunction()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}  -Wall -Wextra -g -O0")
    add_argon2_and_executables_for_arch("x86-64")
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -flto")
    set(CMAKE_AR "gcc-ar")
    set(CMAKE_NM "gcc-nm")
    set(CMAKE_RANLIB "gcc-ranlib")

    add_argon2_and_executables_for_arch("haswell")
    add_argon2_and_executables_for_arch("tigerlake")
    add_argon2_and_executables_for_arch("sapphirerapids")
    add_argon2_and_executables_for_arch("znver3")

    set(LANGUAGES fr zh_CN)
    add_custom_target(update_translations ALL)

    add_custom_command(
            TARGET update_translations
            COMMAND xgettext -k_ -L C -o ${CMAKE_SOURCE_DIR}/locale/windham.pot ${CMAKE_SOURCE_DIR}/frontend.c ${CMAKE_SOURCE_DIR}/backend.c ${CMAKE_SOURCE_DIR}/mapper.c ${CMAKE_SOURCE_DIR}/enclib.c
            COMMENT "Generating windham.pot from source code"
    )

    foreach(LANG ${LANGUAGES})
        add_custom_command(
                TARGET update_translations
                COMMAND msgmerge --update ${CMAKE_SOURCE_DIR}/locale/${LANG}/LC_MESSAGES/windham.po ${CMAKE_SOURCE_DIR}/locale/windham.pot
                DEPENDS ${CMAKE_SOURCE_DIR}/locale/windham.pot
                COMMENT "Updating ${LANG}/windham.po"
        )
    endforeach()

    add_dependencies(windham_haswell update_translations)

endif()
