cmake_minimum_required(VERSION 3.4.3)

project(s2etools)
set(s2etools_VERSION_MAJOR 0)
set(s2etools_VERSION_MINOR 1)
set(s2etools_VERSION_PATCH 0)
set(s2etools_PACKAGE_VERSION
    "${s2etools_VERSION_MAJOR}.${s2etools_VERSION_MINOR}.${s2etools_VERSION_PATCH}")

include(CMakePackageConfigHelpers)
set(CMAKE_VERSION_FILE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Version.cmake")
write_basic_package_version_file(${CMAKE_VERSION_FILE}
                                 VERSION ${s2etools_PACKAGE_VERSION}
                                 COMPATIBILITY AnyNewerVersion)

include(FindPkgConfig)
pkg_check_modules(GLIB2 glib-2.0)

find_package(LLVM REQUIRED)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")

find_package(VMI REQUIRED)
message(STATUS "Found VMI ${VMI_PACKAGE_VERSION}")

if(S2E_SRC_DIR)
  message(STATUS "S2E source directory: ${S2E_SRC_DIR}")
else()
 message(FATAL_ERROR "No S2E source directory specified")
endif()

if(NOT QEMU_TARGET)
  set(QEMU_TARGET "i386" CACHE STRING "QEMU target")
endif()

add_definitions(${LLVM_DEFINITIONS})

include_directories("include"
                    ${CMAKE_CURRENT_SOURCE_DIR}
                    ${LLVM_INCLUDE_DIRS}
                    ${S2E_SRC_DIR}
                    ${VMI_INCLUDE_DIR})
link_directories(${VMI_LIBRARY_DIR})

llvm_map_components_to_libnames(LLVM_LIBS core
                                          debuginfodwarf
                                          ipo
                                          bitwriter
                                          mcjit
                                          x86codegen
                                          x86desc
                                          x86info)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -Werror")

add_subdirectory(lib)
add_subdirectory(tools)
