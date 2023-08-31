cmake_minimum_required(VERSION 3.24)
project(windham C)

set(CMAKE_C_STANDARD 23)

# Add the directory containing the aaa library to the include path
include_directories(${CMAKE_SOURCE_DIR}/include)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")

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
target_link_libraries(windham Argon2 speck SHA256 tiny_AES_c)
target_link_libraries(windham_test Argon2 speck SHA256 tiny_AES_c)
#target_link_libraries(windham speck)
#target_link_libraries(windham SHA256)
#target_link_libraries(windham tiny_AES_c)


