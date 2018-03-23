add_executable(hardening Hardening.cpp)
target_link_libraries(hardening executiontracer binaryreaders utils vmi)

install(TARGETS hardening RUNTIME DESTINATION bin)
