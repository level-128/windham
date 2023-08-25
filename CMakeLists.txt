cmake_minimum_required(VERSION 3.24)
project(windham C)

set(CMAKE_C_STANDARD 23)

# Add the directory containing the aaa library to the include path
include_directories(${CMAKE_SOURCE_DIR}/library)

# Collect all the source files from the aaa directory
file(GLOB Argon2_SRC ${CMAKE_SOURCE_DIR}/library/Argon2/*.c)

# Create a static library target for aaa
add_library(Argon2 STATIC ${Argon2_SRC})

# Create an executable target for the main program
add_executable(windham frontend.c )

# Link the aaa library to the main program
target_link_libraries(windham Argon2)


