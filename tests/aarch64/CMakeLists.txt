include_directories("/usr/lib/llvm-16/include")

add_executable(aarch64_test_lift
  "${CMAKE_SOURCE_DIR}/front/MainLifter.cpp"
  "${CMAKE_SOURCE_DIR}/front/TraceManager.cpp"
  "${CMAKE_SOURCE_DIR}/front/Binary/Loader.cpp"
  TestLift.cpp
)

set_target_properties(aarch64_test_lift PROPERTIES
  POSITION_INDEPENDENT_CODE ON
  COMPILE_FLAGS "-O0 -fPIC -pie"
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
