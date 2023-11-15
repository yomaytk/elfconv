# Copyright (c) 2017 Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

find_package(GTest CONFIG REQUIRED)
list(APPEND PROJECT_LIBRARIES GTest::gtest)

enable_testing()
enable_language(ASM)

include_directories("/usr/lib/llvm-16/include")

add_executable(lifting_target_aarch64
  EXCLUDE_FROM_ALL
  binary/loader.cpp
  Lift.cpp
)

set_target_properties(lifting_target_aarch64 PROPERTIES
  POSITION_INDEPENDENT_CODE ON
  COMPILE_FLAGS "-O0 -fPIC -pie"
)

target_compile_options(lifting_target_aarch64
  PRIVATE ${AARCH64_TEST_FLAGS}
  -DIN_TEST_GENERATOR
)

target_link_libraries(
  lifting_target_aarch64 
  PRIVATE
  bfd
  elf
)

file(GLOB AARCH64_TEST_FILES
  "${CMAKE_CURRENT_LIST_DIR}/*/*.S"
)

set_target_properties(lifting_target_aarch64 PROPERTIES OBJECT_DEPENDS "${AARCH64_TEST_FILES}")

target_link_libraries(lifting_target_aarch64 PUBLIC remill ${PROJECT_LIBRARIES} )
target_include_directories(lifting_target_aarch64 PUBLIC ${PROJECT_INCLUDEDIRECTORIES})
target_include_directories(lifting_target_aarch64 PRIVATE ${CMAKE_SOURCE_DIR})
target_link_options(lifting_target_aarch64 PRIVATE -v)

add_custom_command(
  OUTPUT lifted_target_aarch64.bc
  COMMAND lifting_target_aarch64 --arch aarch64 --bc_out lifted_target_aarch64.bc
  DEPENDS lifting_target_aarch64 semantics
)

add_custom_command(
  OUTPUT  lifted_target_aarch64.S
  COMMAND ${CMAKE_BC_COMPILER}
          -Wno-override-module
          -S -O1 -g0
          -c lifted_target_aarch64.bc
          -o lifted_target_aarch64.S
          -mllvm -opaque-pointers
  DEPENDS lifted_target_aarch64.bc
)

message(STATUS "Adding New Target aarch64 as only liftin_target_aarch64: aarch64 as run-aarch64-tests")
add_dependencies(test_dependencies lifting_target_aarch64)
