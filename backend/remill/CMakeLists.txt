# Copyright (c) 2018 Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.21)

# Setup to use ccache
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/ccache.cmake")

project(remill C CXX ASM)
include(GNUInstallDirs)
include(FetchContent)
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/settings.cmake")
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/utils.cmake")
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/options.cmake")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")

if(REMILL_ENABLE_TESTING)
  include(CTest)
endif()

message(STATUS "Compiler ID is ${CMAKE_C_COMPILER_ID}")

#
# libraries
#

# Z3
find_package(Z3 CONFIG REQUIRED)

# LLVM
find_package(LLVM CONFIG REQUIRED)
# https://github.com/JonathanSalwan/Triton/issues/1082#issuecomment-1030826696
if(LLVM_LINK_LLVM_DYLIB)
  set(llvm_libs LLVM)
else()
  llvm_map_components_to_libnames(llvm_libs
    support core irreader
    bitreader bitwriter
    passes asmprinter
    aarch64info aarch64desc aarch64codegen aarch64asmparser
    armcodegen armasmparser
    interpreter mcjit
    nvptxdesc
    x86info x86codegen x86asmparser
    sparccodegen sparcasmparser
    webassemblydesc)
endif()
message(STATUS "LLVM Libraries: ${llvm_libs}")

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})

string(REPLACE "." ";" LLVM_VERSION_LIST ${LLVM_PACKAGE_VERSION})
list(GET LLVM_VERSION_LIST 0 LLVM_MAJOR_VERSION)
list(GET LLVM_VERSION_LIST 1 LLVM_MINOR_VERSION)

set(LLVM_MAJOR_VERSION "${LLVM_MAJOR_VERSION}")
set(LLVM_MINOR_VERSION "${LLVM_MINOR_VERSION}")

set(REMILL_LLVM_VERSION "${LLVM_MAJOR_VERSION}")

message("Remill llvm version: ${REMILL_LLVM_VERSION}")
set(REMILL_INSTALL_SEMANTICS_DIR "${CMAKE_INSTALL_PREFIX}/${REMILL_INSTALL_SHARE_DIR}/remill/${REMILL_LLVM_VERSION}/semantics" CACHE PATH "Directory into which semantics are installed")
set(REMILL_BUILD_SEMANTICS_DIR_X86 "${CMAKE_CURRENT_BINARY_DIR}/lib/Arch/X86/Runtime")
# set(REMILL_BUILD_SEMANTICS_DIR_AARCH32 "${CMAKE_CURRENT_BINARY_DIR}/lib/Arch/AArch32/Runtime")
set(REMILL_BUILD_SEMANTICS_DIR_AARCH64 "${CMAKE_CURRENT_BINARY_DIR}/lib/Arch/AArch64/Runtime")
# set(REMILL_BUILD_SEMANTICS_DIR_SPARC32 "${CMAKE_CURRENT_BINARY_DIR}/lib/Arch/SPARC32/Runtime")
# set(REMILL_BUILD_SEMANTICS_DIR_SPARC64 "${CMAKE_CURRENT_BINARY_DIR}/lib/Arch/SPARC64/Runtime")
# set(REMILL_BUILD_SEMANTICS_DIR_PPC64_32ADDR "${CMAKE_CURRENT_BINARY_DIR}/lib/Arch/PPC/Runtime")
set(REMILL_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")
set(REMILL_LIB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/lib")

include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/BCCompiler.cmake")

# Intel XED
find_package(XED CONFIG REQUIRED)

# Google glog module
find_package(glog CONFIG REQUIRED)

# Google gflags
set(GFLAGS_USE_TARGET_NAMESPACE ON)
find_package(gflags CONFIG REQUIRED)

set(sleigh_ENABLE_TESTS OFF)
set(sleigh_RELEASE_TYPE "HEAD" CACHE STRING "" FORCE)

file(GLOB sleigh_patches "${CMAKE_CURRENT_SOURCE_DIR}/patches/sleigh/*.patch")

set(sleigh_ADDITIONAL_PATCHES "${sleigh_patches}" CACHE STRING "" FORCE)

# GHIDRA SLEIGH
FetchContent_Declare(sleigh
  GIT_REPOSITORY https://github.com/lifting-bits/sleigh.git
  GIT_TAG 7c6b742
)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-register")

set(sleigh_BUILD_SUPPORT ON CACHE BOOL "" FORCE)
set(sleigh_BUILD_SLEIGHSPECS ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(sleigh)

# For Linux builds, group LLVM libraries into a single group
# that avoids frustrating library ordering issues.
if(UNIX AND NOT APPLE)
  set(LINKER_START_GROUP "-Wl,--start-group")
  set(LINKER_END_GROUP "-Wl,--end-group")
else()
  set(LINKER_START_GROUP "")
  set(LINKER_END_GROUP "")
endif()

#
# Configuration options for semantics
#
option(REMILL_BARRIER_AS_NOP "Remove compiler barriers (inline assembly) in semantics" OFF)
option(REMILL_BUILD_SPARC32_RUNTIME "Build the Runtime for SPARC32. Turn this off if you have include errors with <bits/c++config.h>, or read the README for a fix" OFF)

#
# target settings
#

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${LIFT_DEBUG_MACROS}")

# add everything as public.
add_library(remill_settings INTERFACE)

target_include_directories(remill_settings INTERFACE
  $<BUILD_INTERFACE:${REMILL_INCLUDE_DIR}>
  $<INSTALL_INTERFACE:include>
  $<BUILD_INTERFACE:${LLVM_INCLUDE_DIR}>
)

if(WIN32)
  # warnings and compiler settings
  target_compile_options(remill_settings INTERFACE
    "$<$<CONFIG:Debug>:/MDd>$<$<CONFIG:Release>:/MD>"
    /nologo /W3 /EHsc /wd4141 /wd4146 /wd4180 /wd4244
    /wd4258 /wd4267 /wd4291 /wd4345 /wd4351 /wd4355 /wd4456
    /wd4457 /wd4458 /wd4459 /wd4503 /wd4624 /wd4722 /wd4800
    /wd4100 /wd4127 /wd4512 /wd4505 /wd4610 /wd4510 /wd4702
    /wd4245 /wd4706 /wd4310 /wd4701 /wd4703 /wd4389 /wd4611
    /wd4805 /wd4204 /wd4577 /wd4091 /wd4592 /wd4324
  )

  target_compile_definitions(remill_settings INTERFACE
    _CRT_SECURE_NO_DEPRECATE
    _CRT_SECURE_NO_WARNINGS
    _CRT_NONSTDC_NO_DEPRECATE
    _CRT_NONSTDC_NO_WARNINGS
    _SCL_SECURE_NO_DEPRECATE
    _SCL_SECURE_NO_WARNINGS
    GOOGLE_PROTOBUF_NO_RTTI
  )

else()
  # warnings and compiler settings
  target_compile_options(remill_settings INTERFACE
    -Wall -Wextra -Wno-unused-parameter -Wno-c++98-compat
    -Wno-unreachable-code-return -Wno-nested-anon-types
    -Wno-extended-offsetof
    -Wno-variadic-macros -Wno-return-type-c-linkage
    -Wno-c99-extensions -Wno-ignored-attributes -Wno-unused-local-typedef
    -Wno-unknown-pragmas -Wno-unknown-warning-option -fPIC
    -fno-omit-frame-pointer -fvisibility-inlines-hidden
    -fno-asynchronous-unwind-tables
  )

  # Clang-specific warnings/error options
  if("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang" OR "${CMAKE_C_COMPILER_ID}" STREQUAL "AppleClang")
    target_compile_options(remill_settings INTERFACE
      -Wgnu-alignof-expression -Wno-gnu-anonymous-struct -Wno-gnu-designator
      -Wno-gnu-zero-variadic-macro-arguments -Wno-gnu-statement-expression
      -fno-aligned-allocation
    )
  endif()

  # debug symbols
  if(CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    target_compile_options(remill_settings INTERFACE
      -gdwarf-2 -g3
    )
  endif()

  # optimization flags and definitions
  if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(remill_settings INTERFACE
      -O0
    )
    target_compile_definitions(remill_settings INTERFACE
      "DEBUG"
    )
  else()
    target_compile_options(remill_settings INTERFACE
      -O0
    )
    target_compile_definitions(remill_settings INTERFACE
      "NDEBUG"
    )
  endif()
endif()

target_compile_definitions(remill_settings INTERFACE
  "REMILL_INSTALL_SEMANTICS_DIR=\"${REMILL_INSTALL_SEMANTICS_DIR}\""
  "REMILL_BUILD_SEMANTICS_DIR_X86=\"${REMILL_BUILD_SEMANTICS_DIR_X86}\""
  # "REMILL_BUILD_SEMANTICS_DIR_AARCH32=\"${REMILL_BUILD_SEMANTICS_DIR_AARCH32}\""
  "REMILL_BUILD_SEMANTICS_DIR_AARCH64=\"${REMILL_BUILD_SEMANTICS_DIR_AARCH64}\""
  # "REMILL_BUILD_SEMANTICS_DIR_SPARC32=\"${REMILL_BUILD_SEMANTICS_DIR_SPARC32}\""
  # "REMILL_BUILD_SEMANTICS_DIR_SPARC64=\"${REMILL_BUILD_SEMANTICS_DIR_SPARC64}\""
  # "REMILL_BUILD_SEMANTICS_DIR_PPC64_32ADDR=\"${REMILL_BUILD_SEMANTICS_DIR_PPC64_32ADDR}\""
)

set(ghidra_patch_user "github-actions[bot]")
set(ghidra_patch_email "41898282+github-actions[bot]@users.noreply.github.com")

# pinned stable patches list
set(ghidra_patches
  PATCH_COMMAND "${GIT_EXECUTABLE}" config user.name "${ghidra_patch_user}" &&
  "${GIT_EXECUTABLE}" config user.email "${ghidra_patch_email}" &&
  "${GIT_EXECUTABLE}" am --ignore-space-change --ignore-whitespace --no-gpg-sign)
list(APPEND ghidra_patches ${sleigh_ADDITIONAL_PATCHES})

FetchContent_Declare(ghidra-fork
  GIT_REPOSITORY https://github.com/trail-of-forks/ghidra.git
  GIT_TAG e7196d8
  ${ghidra_patches}
)

FetchContent_MakeAvailable(ghidra-fork)

if(SLEIGH_EXECUTABLE)
  set(sleigh_compiler "${SLEIGH_EXECUTABLE}")
else()
  set(sleigh_compiler "$<TARGET_FILE:sleigh::sleigh>")
endif()

sleigh_compile(
  TARGET ppc_e200_spec
  COMPILER "${sleigh_compiler}"
  SLASPEC "${ghidra-fork_SOURCE_DIR}/Ghidra/Processors/PowerPC/data/languages/ppc_32_e200_be.slaspec"
  LOG_FILE "${sleigh_BINARY_DIR}/sleighspecs/spec_build_logs/ppc_32_e200_be.sla.log"
  OUT_FILE "${sleigh_BINARY_DIR}/specfiles/Ghidra/Processors/PowerPC/data/languages/ppc_32_e200_be.sla"
)

add_custom_target(sleigh_custom_specs)
add_dependencies(sleigh_custom_specs ppc_e200_spec)

target_link_libraries(remill_settings INTERFACE
  ${llvm_libs}
  XED::XED
  glog::glog
  gflags::gflags
  sleigh::sla
  sleigh::decomp
  sleigh::support
)

add_subdirectory(lib/Arch)
add_subdirectory(lib/BC)
add_subdirectory(lib/OS)
add_subdirectory(lib/Version)

add_library(remill INTERFACE)
target_link_libraries(remill INTERFACE
  ${LINKER_START_GROUP}
  ${llvm_libs}
  XED::XED
  glog::glog
  gflags::gflags
  sleigh::sla
  sleigh::decomp
  sleigh::support
  remill_bc
  remill_os
  remill_arch
  remill_version
  ${LINKER_END_GROUP}
)

# add semantics target
add_custom_target(semantics)

# # tests (no tests now)
# if(REMILL_ENABLE_TESTING)
  # Tests require enabling exports on binaries
  # https://cmake.org/cmake/help/latest/variable/CMAKE_ENABLE_EXPORTS.html#variable:CMAKE_ENABLE_EXPORTS
  set(CMAKE_ENABLE_EXPORTS ON)

  find_package(Threads REQUIRED)
  add_custom_target(test_dependencies)

  add_subdirectory(tests/AArch64)
# endif()
