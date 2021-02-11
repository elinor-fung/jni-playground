cmake_minimum_required(VERSION 3.15)
project(src)

set(CMAKE_C_STANDARD 99)

find_package(JNI REQUIRED)

if(WIN32)
  add_compile_definitions(TARGET_WINDOWS)
else(WIN32)
  add_compile_definitions(TARGET_UNIX)
endif(WIN32)

add_subdirectory(bridge)
add_subdirectory(native)