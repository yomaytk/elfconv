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

find_package(LLVM CONFIG REQUIRED)
include_directories(${LLVM_INCLUDE_DIRS})

add_executable(elflift
  Binary/Loader.cpp
  MainLifter.cpp
  TraceManager.cpp
  Lift.cpp
  ${CMAKE_SOURCE_DIR}/utils/Util.cpp
)

set_target_properties(elflift PROPERTIES
  POSITION_INDEPENDENT_CODE ON
  COMPILE_FLAGS "-O3 -fPIC"
)

if(CMAKE_ELFCONV_AARCH64_BUILD)
  target_compile_definitions(elflift PUBLIC "ELFCONV_AARCH64_BUILD=1")
elseif(CMAKE_ELFCONV_X86_BUILD)
  target_compile_definitions(elflift PUBLIC "ELFCONV_X86_BUILD=1")
else()
  message(FATAL_ERROR, "CMAKE_ELFCONV_<arch_name>_BUILD must be 1. (lifter/CMakeLists.txt)")
endif()

# static link
if(${CMAKE_ELFLIFT_STATIC_LINK})
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
      set(LIBIBERTY_PATH "/usr/lib/aarch64-linux-gnu/libiberty.a")
  elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
      set(LIBIBERTY_PATH "/usr/lib/x86_64-linux-gnu/libiberty.a")
  else()
      message(FATAL_ERROR "Unsupported architecture: ${CMAKE_SYSTEM_PROCESSOR}")
  endif() 
  target_link_options(elflift PUBLIC -static)
  target_link_libraries(
    elflift
    PRIVATE
    bfd
    elf
    dwarf
    ${LIBIBERTY_PATH}
  )
else()
# dynamic link
  target_link_libraries(
    elflift
    PRIVATE
    bfd
    elf
    dwarf
  )
endif()

target_link_libraries(elflift PUBLIC remill ${PROJECT_LIBRARIES} )
target_include_directories(elflift PUBLIC ${PROJECT_INCLUDEDIRECTORIES})
target_include_directories(elflift PRIVATE ${CMAKE_SOURCE_DIR})
