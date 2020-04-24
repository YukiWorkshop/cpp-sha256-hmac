cmake_minimum_required(VERSION 3.2)
project(cpp-sha256-hmac)

set(CMAKE_CXX_STANDARD 17)

add_library(cpp-sha256-hmac cpp-sha256-hmac.cpp cpp-sha256-hmac.hpp)
add_executable(cpp-sha256-hmac_test test.cpp)
target_link_libraries(cpp-sha256-hmac_test cpp-sha256-hmac)
