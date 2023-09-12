cmake_minimum_required(VERSION 3.24)
project(windham C)

option(USE_SPECIFIC_COMPILER "Use a specific compiler" OFF)

if(USE_SPECIFIC_COMPILER)
    set(CMAKE_C_COMPILER "/path/to/gcc/compiler")
endif()

set(CMAKE_C_STANDARD 23)


if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}  -Wall -Wextra -g")
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -flto")
    set(CMAKE_AR "gcc-ar")
    set(CMAKE_NM "gcc-nm")
    set(CMAKE_RANLIB "gcc-ranlib")
endif()

# Add the directory containing the aaa library to the include path
include_directories(${CMAKE_SOURCE_DIR}/include)

# Collect all the source files from the aaa directory
file(GLOB Argon2_SRC ${CMAKE_SOURCE_DIR}/library/Argon2/*.c)
file(GLOB speck_SRC ${CMAKE_SOURCE_DIR}/library/speck/*.c)
file(GLOB SHA256_SRC ${CMAKE_SOURCE_DIR}/library/SHA256/*.c)
file(GLOB tiny_AES_c_SRC ${CMAKE_SOURCE_DIR}/library/tiny_AES_c/*.c)

# Create a static library target for aaa
add_library(Argon2 STATIC ${Argon2_SRC})
add_library(speck STATIC ${speck_SRC})
add_library(SHA256 STATIC ${SHA256_SRC})
add_library(tiny_AES_c STATIC ${tiny_AES_c_SRC})

# Create an executable target for the main program
add_executable(windham frontend.c )
add_executable(windham_test test/test.c )

# Link the library to the main program
target_link_libraries(windham Argon2 speck SHA256 tiny_AES_c devmapper m)
target_link_libraries(windham_test Argon2 speck SHA256 tiny_AES_c devmapper m)

if((CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64") OR
(CMAKE_SYSTEM_PROCESSOR STREQUAL "amd64") OR
(CMAKE_SYSTEM_PROCESSOR STREQUAL "i386") OR
(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86"))
    add_executable(windham_argonbench argon_bench.c)
    target_link_libraries(windham_argonbench Argon2)
endif()

install(TARGETS windham windham_argonbench windham_test
        RUNTIME DESTINATION bin)
install(TARGETS Argon2 speck SHA256 tiny_AES_c
        ARCHIVE DESTINATION lib)


# add uninstall target
if(NOT TARGET uninstall)
    configure_file(
            "${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
            "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
            IMMEDIATE @ONLY)

    add_custom_target(uninstall
            COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif()
