add_library(memscope_resolver_lib STATIC
    address_resolver.cpp
)
target_include_directories(memscope_resolver_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${MEMSCOPE_BPF_INCLUDE_DIR}
    ${MEMSCOPE_BINARY_DIR}
    ${LIBBPF_INCLUDE_DIRS}
)
target_compile_options(memscope_resolver_lib PRIVATE ${MEMSCOPE_OPT_FLAGS} ${MEMSCOPE_WARN_CXX})
target_link_libraries(memscope_resolver_lib PUBLIC memscope_dwarf_lib ${LIBBPF_LIBRARIES})
target_link_directories(memscope_resolver_lib PUBLIC ${LIBBPF_LIBRARY_DIRS})

add_executable(memscope-resolve main.cpp)
target_include_directories(memscope-resolve PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src/dwarf
    ${MEMSCOPE_BPF_INCLUDE_DIR}
    ${MEMSCOPE_BINARY_DIR}
)
target_compile_options(memscope-resolve PRIVATE ${MEMSCOPE_OPT_FLAGS} ${MEMSCOPE_WARN_CXX})
target_link_libraries(memscope-resolve PRIVATE memscope_resolver_lib memscope_dwarf_lib ${LIBDW_LIBRARIES} ${LIBELF_LIBRARIES} ${ZLIB_LIBRARIES} ${LIBBPF_LIBRARIES})
target_link_directories(memscope-resolve PRIVATE ${LIBDW_LIBRARY_DIRS} ${LIBELF_LIBRARY_DIRS} ${ZLIB_LIBRARY_DIRS} ${LIBBPF_LIBRARY_DIRS})
