add_executable(cacheprof cacheprof.cpp)
target_link_libraries(cacheprof executiontracer binaryreaders utils)

install(TARGETS cacheprof RUNTIME DESTINATION bin)
