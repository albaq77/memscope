add_executable(bench_target bench_target.c)
target_compile_options(bench_target PRIVATE -g -O2)
target_link_libraries(bench_target PRIVATE m)

add_executable(bench_target_v2 bench_target_v2.c)
target_compile_options(bench_target_v2 PRIVATE -g -O0)
target_link_libraries(bench_target_v2 PRIVATE m pthread)
