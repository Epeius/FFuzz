add_executable(lcoverage Coverage.cpp)
target_link_libraries(lcoverage executiontracer binaryreaders utils)

install(TARGETS lcoverage RUNTIME DESTINATION bin)
