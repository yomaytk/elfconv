# Copyright (c) 2022 Trail of Bits, Inc.
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

set(REMILL_ARCH_SLEIGH_SRC
  "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/Definitions.h"
  "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/HyperCall.h"
  "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/Intrinsics.h"
  "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/Runtime.h"
  "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/State.h"

  Arch.h
  Arch.cpp
  ControlFlowStructuring.cpp
  ControlFlowStructuring.h
)

if(CMAKE_ELFCONV_AARCH64_BUILD)
  list(APPEND REMILL_ARCH_SLEIGH_SRC 
    "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/Operators.h"
    "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/Types.h"
    "${REMILL_INCLUDE_DIR}/remill/Arch/AArch64/Runtime/Operators.h"
    "${REMILL_INCLUDE_DIR}/remill/Arch/AArch64/Runtime/State.h"
    "${REMILL_INCLUDE_DIR}/remill/Arch/AArch64/Runtime/Types.h"
    AArch64Arch.cpp
    AArch64Arch.h
    AArch64Base.cpp
  )
elseif(CMAKE_ELFCONV_X86_BUILD)
  list(APPEND REMILL_ARCH_SLEIGH_SRC 
    "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/RemillOperators.h"
    "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/RemillTypes.h"
    "${REMILL_INCLUDE_DIR}/remill/Arch/X86/Runtime/Operators.h"
    "${REMILL_INCLUDE_DIR}/remill/Arch/X86/Runtime/State.h"
    "${REMILL_INCLUDE_DIR}/remill/Arch/X86/Runtime/Types.h"
    X86Arch.cpp
  )
else()
  message(FATAL_ERROR, "CMAKE_ELFCONV_<arch_name>_BUILD must be 1. (remill/lib/Arch/Sleigh/CMakeLists.txt: 1)")
endif()

add_library(remill_arch_sleigh STATIC ${REMILL_ARCH_SLEIGH_SRC})
add_dependencies(remill_arch_sleigh sleigh_custom_specs)
set_property(TARGET remill_arch_sleigh PROPERTY POSITION_INDEPENDENT_CODE ON)

target_link_libraries(remill_arch_sleigh LINK_PUBLIC
  remill_settings
)

if(CMAKE_ELFCONV_AARCH64_BUILD)
  target_compile_definitions(remill_arch_sleigh PUBLIC "ELFCONV_AARCH64_BUILD=1")
elseif(CMAKE_ELFCONV_X86_BUILD)
  target_compile_definitions(remill_arch_sleigh PUBLIC "ELFCONV_X86_BUILD=1")
else()
  message(FATAL_ERROR, "CMAKE_ELFCONV_<arch_name>_BUILD must be 1. (remill/lib/Arch/Sleigh/CMakeLists.txt: 2)")
endif()

target_include_directories(remill_arch_sleigh AFTER PRIVATE "${REMILL_SOURCE_DIR}")

if(REMILL_ENABLE_INSTALL_TARGET)
  install(
    TARGETS remill_arch_sleigh
    EXPORT remillTargets
  )
endif()
