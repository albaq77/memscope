cmake_minimum_required(VERSION 3.16)
project(memscope VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(GNUInstallDirs)

set(MEMSCOPE_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(MEMSCOPE_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(MEMSCOPE_VERSION_PATCH ${PROJECT_VERSION_PATCH})
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/src/config.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/config.h
)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(MEMSCOPE_OPT_FLAGS -O3 CACHE INTERNAL "")
else()
    set(MEMSCOPE_OPT_FLAGS -g -O2 CACHE INTERNAL "")
endif()

set(MEMSCOPE_WARN_C -Wall -Wextra -Wno-unused-parameter CACHE INTERNAL "")
set(MEMSCOPE_WARN_CXX -Wall -Wextra -Wno-unused-parameter CACHE INTERNAL "")

set(MEMSCOPE_BPF_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src/bpf CACHE INTERNAL "")
set(MEMSCOPE_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR} CACHE INTERNAL "")

find_package(PkgConfig REQUIRED)

pkg_check_modules(LIBBPF REQUIRED libbpf>=0.5)
pkg_check_modules(LIBELF REQUIRED libelf)
pkg_check_modules(LIBDW REQUIRED libdw)
pkg_check_modules(ZLIB REQUIRED zlib)

find_program(CLANG_BIN clang REQUIRED)
find_program(BPFTOOL_BIN bpftool)

if(NOT BPFTOOL_BIN)
    message(WARNING "bpftool not found, BPF skeleton generation will be skipped")
endif()

execute_process(
    COMMAND uname -m
    OUTPUT_VARIABLE ARCH_NAME
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
if(ARCH_NAME STREQUAL "x86_64")
    set(BPF_ARCH "x86")
elseif(ARCH_NAME STREQUAL "aarch64")
    set(BPF_ARCH "arm64")
else()
    set(BPF_ARCH ${ARCH_NAME})
endif()

set(MEMSCOPE_BPF_ARCH ${BPF_ARCH} CACHE INTERNAL "")
set(MEMSCOPE_ARCH_NAME ${ARCH_NAME} CACHE INTERNAL "")

add_subdirectory(src/bpf)
add_subdirectory(src/collector)
add_subdirectory(src/dwarf)
add_subdirectory(src/resolver)
add_subdirectory(src/benchmark)
add_subdirectory(tests/test_cases)

install(TARGETS memscope-collect memscope-resolve
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/memscope.bpf.o
    DESTINATION ${CMAKE_INSTALL_DATADIR}/memscope
)
