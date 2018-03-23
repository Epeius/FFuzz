add_executable(coverage Coverage.cpp)
target_link_libraries(coverage executiontracer binaryreaders utils)

install(TARGETS coverage RUNTIME DESTINATION bin)
