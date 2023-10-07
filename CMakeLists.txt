cmake_minimum_required(VERSION 3.24)
project(windham C)

option(USE_SPECIFIC_COMPILER "Use a specific compiler" OFF)
option(INCLUDE_BENCH "Include Argon2 benchmark program" ON)
option(INCLUDE_NATIVE "arch native" ON)

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

    add_executable(windham frontend.c ${Argon2_SRC} ${SHA256_SRC} ${tiny_AES_c_SRC})
    add_executable(windham_test test/test.c ${Argon2_SRC} ${SHA256_SRC} ${tiny_AES_c_SRC})

    target_link_libraries(windham devmapper m)
    target_link_libraries(windham_test devmapper m)

    set_target_properties(windham PROPERTIES COMPILE_FLAGS "-march=${arch}")
    set_target_properties(windham_test PROPERTIES COMPILE_FLAGS "-march=${arch}")

    if(INCLUDE_BENCH)
        add_executable(windham_argonbench_${arch} argon_bench.c ${Argon2_SRC})
        set_target_properties(windham_argonbench_${arch} PROPERTIES COMPILE_FLAGS "-march=${arch}")
        install(TARGETS windham_argonbench_${arch}
                RUNTIME DESTINATION bin
                RENAME windham_argonbench)
    endif()

    install(TARGETS windham
            ARCHIVE DESTINATION bin
            RENAME windham)
    install(TARGETS windham_test
            ARCHIVE DESTINATION bin
            RENAME windham_test)
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
    if(INCLUDE_NATIVE)
        add_argon2_and_executables_for_arch("native")
    else ()
        add_argon2_and_executables_for_arch("haswell")
    endif()

endif()

# add uninstall target
if(NOT TARGET uninstall)
    configure_file(
            "${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
            "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
            IMMEDIATE @ONLY)

    add_custom_target(uninstall
            COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif()
