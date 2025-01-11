cmake_minimum_required(VERSION 3.14)
project(elfconv_test)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/f8d7d77c06936315286eb55f8de22cd23c188571.zip
)

FetchContent_MakeAvailable(googletest)

enable_testing()

add_executable(
  elfconv_test
  ../../utils/Util.cpp
  Run.cpp
)

target_link_libraries(
  elfconv_test
  GTest::gtest_main
)

target_include_directories(elfconv_test PRIVATE ${CMAKE_SOURCE_DIR})

include(GoogleTest)
gtest_discover_tests(elfconv_test)
