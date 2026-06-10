cmake_minimum_required(VERSION 3.14)

# Single source of truth for the version: the REGEXLIB_VERSION macro in the
# header. Extract it so the maintainer never updates the number in two places.
file(STRINGS regexlib.h _raw_version_string
  REGEX "REGEXLIB_VERSION \"([0-9]+\\.[0-9]+\\.[0-9]+)\"")
string(REGEX MATCH "([0-9]+\\.?)+" _regexlib_version "${_raw_version_string}")

project(regexlib
  VERSION ${_regexlib_version}
  LANGUAGES CXX
  DESCRIPTION "A grapheme-aware, linear-time, single-header regex engine."
  HOMEPAGE_URL "https://github.com/yhirose/cpp-regexlib")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /Zc:__cplusplus /utf-8 /D_CRT_SECURE_NO_DEPRECATE")
else()
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")
endif()

# Header-only, single-file, dependency-free interface. The Unicode tables it
# needs (General_Category, grapheme segmentation, case folding, White_Space) are
# generated into regexlib.h by tools/generate_ucd.py — no external include path.
add_library(regexlib INTERFACE)
target_include_directories(regexlib INTERFACE
  ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(regexlib INTERFACE cxx_std_17)

option(BUILD_TESTS "Build cpp-regexlib tests" ON)

if(BUILD_TESTS)
  enable_testing()
  add_subdirectory(test)
endif()

install(FILES regexlib.h DESTINATION include)
