add_library(memscope_collector_lib STATIC
    collector.c
)
target_include_directories(memscope_collector_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${MEMSCOPE_BPF_INCLUDE_DIR}
    ${MEMSCOPE_BINARY_DIR}
)
target_compile_options(memscope_collector_lib PRIVATE ${MEMSCOPE_OPT_FLAGS} ${MEMSCOPE_WARN_C})
target_link_libraries(memscope_collector_lib PUBLIC ${LIBBPF_LIBRARIES} ${LIBELF_LIBRARIES} ${ZLIB_LIBRARIES})
target_link_directories(memscope_collector_lib PUBLIC ${LIBBPF_LIBRARY_DIRS} ${LIBELF_LIBRARY_DIRS} ${ZLIB_LIBRARY_DIRS})

add_executable(memscope-collect main.c)
target_include_directories(memscope-collect PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${MEMSCOPE_BPF_INCLUDE_DIR}
    ${MEMSCOPE_BINARY_DIR}
)
target_compile_options(memscope-collect PRIVATE ${MEMSCOPE_OPT_FLAGS} ${MEMSCOPE_WARN_C})
target_link_libraries(memscope-collect PRIVATE memscope_collector_lib ${LIBBPF_LIBRARIES} ${LIBELF_LIBRARIES} ${ZLIB_LIBRARIES})
target_link_directories(memscope-collect PRIVATE ${LIBBPF_LIBRARY_DIRS} ${LIBELF_LIBRARY_DIRS} ${ZLIB_LIBRARY_DIRS})
add_dependencies(memscope-collect memscope_bpf_obj)
