add_library(memscope_dwarf_lib STATIC
    dwarf_analyzer.cpp
)
target_include_directories(memscope_dwarf_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${MEMSCOPE_BPF_INCLUDE_DIR}
    ${MEMSCOPE_BINARY_DIR}
)
target_compile_options(memscope_dwarf_lib PRIVATE ${MEMSCOPE_OPT_FLAGS} ${MEMSCOPE_WARN_CXX})
target_link_libraries(memscope_dwarf_lib PUBLIC ${LIBDW_LIBRARIES} ${LIBELF_LIBRARIES} ${ZLIB_LIBRARIES})
target_link_directories(memscope_dwarf_lib PUBLIC ${LIBDW_LIBRARY_DIRS} ${LIBELF_LIBRARY_DIRS} ${ZLIB_LIBRARY_DIRS})
