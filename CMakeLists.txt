cmake_minimum_required(VERSION 3.21)
project(elfconv)

set(CMAKE_VERBOSE_MAKEFILE FALSE)

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    add_compile_options(-fdiagnostics-color=always)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_compile_options(-fcolor-diagnostics)
endif()

# hide note etc...
add_compile_options(-Wno-extra)
add_compile_options(-Wno-format-extra-args)

# remill build
add_subdirectory(backend/remill)

# front build
add_subdirectory(front)

# aarch64 test build
add_subdirectory(tests/aarch64)
