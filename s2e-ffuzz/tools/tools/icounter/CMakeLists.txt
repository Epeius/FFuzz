add_executable(icounter icounter.cpp)
target_link_libraries(icounter executiontracer binaryreaders utils)

install(TARGETS icounter RUNTIME DESTINATION bin)
