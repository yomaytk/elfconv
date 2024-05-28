enable_testing()

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

# lifter build
add_subdirectory(lifter)

# tests
if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
  add_subdirectory(tests/aarch64)
endif()
add_subdirectory(tests/elfconv)