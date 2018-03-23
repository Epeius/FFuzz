add_executable(debugger Debugger.cpp)
target_link_libraries(debugger executiontracer binaryreaders utils)

install(TARGETS debugger RUNTIME DESTINATION bin)
