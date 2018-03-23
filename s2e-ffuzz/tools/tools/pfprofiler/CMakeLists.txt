add_executable(pfprofiler pfprofiler.cpp CacheProfiler.cpp)
target_link_libraries(pfprofiler executiontracer binaryreaders utils)

install(TARGETS pfprofiler RUNTIME DESTINATION bin)
