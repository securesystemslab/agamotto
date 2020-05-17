cmake_minimum_required(VERSION 3.7.2)

if ("$ENV{GOPATH}" STREQUAL "")
    message(FATAL_ERROR "GOPATH env var is not set")
endif()

if (NOT EXISTS $ENV{GOPATH}/src/github.com/google/syzkaller)
    message(FATAL_ERROR "Syzkaller is not found under GOPATH")
endif()

project(agamotto)

add_subdirectory(libagamotto)
add_subdirectory(libafl)
add_subdirectory(guest)
