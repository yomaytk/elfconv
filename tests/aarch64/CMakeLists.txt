include_directories("/usr/lib/llvm-16/include")

add_executable(aarch64_test_lift
  "${CMAKE_SOURCE_DIR}/lifter/MainLifter.cpp"
  "${CMAKE_SOURCE_DIR}/lifter/TraceManager.cpp"
  "${CMAKE_SOURCE_DIR}/utils/Util.cpp"
  "${CMAKE_SOURCE_DIR}/lifter/Binary/Loader.cpp"
  TestInstructions.cpp
  TestLift.cpp
  TestMainLifter.cpp
)

set_target_properties(aarch64_test_lift PROPERTIES
  POSITION_INDEPENDENT_CODE ON
  COMPILE_FLAGS "-O0 -fPIC"
)

target_link_libraries(
  aarch64_test_lift
  PRIVATE
  bfd
  elf
)

target_link_libraries(aarch64_test_lift PUBLIC remill ${PROJECT_LIBRARIES} )
target_include_directories(aarch64_test_lift PUBLIC ${PROJECT_INCLUDEDIRECTORIES})
target_include_directories(aarch64_test_lift PRIVATE ${CMAKE_SOURCE_DIR})
