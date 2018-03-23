add_executable(forkprofiler forkprofiler.cpp)
target_link_libraries(forkprofiler executiontracer binaryreaders utils)

install(TARGETS forkprofiler RUNTIME DESTINATION bin)
