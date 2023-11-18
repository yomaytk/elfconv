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

enable_language(ASM)

include_directories("/usr/lib/llvm-16/include")

add_executable(elflift
  Binary/Loader.cpp
  MainLifter.cpp
  Lift.cpp
)

set_target_properties(elflift PROPERTIES
  POSITION_INDEPENDENT_CODE ON
  COMPILE_FLAGS "-O0 -fPIC -pie"
)

target_link_libraries(
  elflift 
  PRIVATE
  bfd
  elf
)

target_link_libraries(elflift PUBLIC remill ${PROJECT_LIBRARIES} )
target_include_directories(elflift PUBLIC ${PROJECT_INCLUDEDIRECTORIES})
target_include_directories(elflift PRIVATE ${CMAKE_SOURCE_DIR})
target_link_options(elflift PRIVATE -v)
