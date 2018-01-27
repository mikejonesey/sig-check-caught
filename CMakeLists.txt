cmake_minimum_required(VERSION 3.8)
project(sig_check_caught)

set(CMAKE_C_STANDARD 99)

set(SOURCE_FILES main.c)
add_executable(sig_check_caught ${SOURCE_FILES})