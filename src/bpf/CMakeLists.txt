add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/memscope.bpf.o
    COMMAND ${CLANG_BIN}
        -g -O2 -target bpf
        -D__TARGET_ARCH_${MEMSCOPE_BPF_ARCH}
        -I${CMAKE_CURRENT_SOURCE_DIR}
        -I/usr/include/${MEMSCOPE_ARCH_NAME}-linux-gnu
        -Wno-unused-value -Wno-unknown-warning-option
        -c ${CMAKE_CURRENT_SOURCE_DIR}/memscope.bpf.c
        -o ${CMAKE_CURRENT_BINARY_DIR}/memscope.bpf.o
    DEPENDS
        ${CMAKE_CURRENT_SOURCE_DIR}/memscope.bpf.c
        ${CMAKE_CURRENT_SOURCE_DIR}/memscope_common.h
        ${CMAKE_CURRENT_SOURCE_DIR}/vmlinux.h
    COMMENT "Compiling BPF program"
)

if(BPFTOOL_BIN)
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/memscope.skel.h
        COMMAND ${BPFTOOL_BIN} gen skeleton
            ${CMAKE_CURRENT_SOURCE_DIR}/memscope.bpf.c
            > ${CMAKE_CURRENT_BINARY_DIR}/memscope.skel.h
            2>/dev/null || true
        DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/memscope.bpf.o
        COMMENT "Generating BPF skeleton"
    )
endif()

add_custom_target(memscope_bpf_obj ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/memscope.bpf.o)
