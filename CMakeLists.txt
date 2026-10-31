cmake_minimum_required(VERSION 3.18...3.31)
project(whatfills_core LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

find_package(Python 3.9 COMPONENTS Interpreter Development.Module REQUIRED)
execute_process(
  COMMAND "${Python_EXECUTABLE}" -m nanobind --cmake_dir
  OUTPUT_STRIP_TRAILING_WHITESPACE OUTPUT_VARIABLE nanobind_ROOT)
find_package(nanobind CONFIG REQUIRED)
find_package(Threads REQUIRED)

nanobind_add_module(_core NB_STATIC
  csrc/bindings.cpp
  csrc/scanner.cpp
  csrc/glob.cpp)
target_compile_options(_core PRIVATE -Wall -Wextra)
target_link_libraries(_core PRIVATE Threads::Threads)

install(TARGETS _core LIBRARY DESTINATION whatfills)
