add_executable(analysis Analysis.cpp)
target_link_libraries(analysis executiontracer binaryreaders cfg utils)

install(TARGETS analysis RUNTIME DESTINATION bin)
