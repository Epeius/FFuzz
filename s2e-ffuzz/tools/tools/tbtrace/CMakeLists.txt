add_executable(tbtrace TbTrace.cpp)
target_link_libraries(tbtrace executiontracer binaryreaders utils)

install(TARGETS tbtrace RUNTIME DESTINATION bin)
