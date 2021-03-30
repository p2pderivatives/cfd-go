cmake_minimum_required(VERSION 3.13)

# configure.ac: AC_INIT([cfd-go], [1.0]
set(PACKAGE_VERSION   1.0.0)

####################
# options
####################
include(./cmake/CfdCommonOption.cmake)
include(./cmake/CfdWallyOption.cmake)

option(CFD_SHARED "force shared build (ON or OFF. default:OFF)" OFF)
option(ENABLE_CAPI  "enable c-api (ON or OFF. default:ON)" ON)
option(ENABLE_JSONAPI  "enable json-api (ON or OFF. default:ON)" ON)

set(GENERATE_WALLY ON CACHE BOOL "" FORCE)
set(EXCLUDE_WALLYCORE_LIB ON CACHE BOOL "" FORCE)

####################
# common setting
####################
include(./cmake/CfdCommonSetting.cmake)


####################
# test
####################
project(cfdgo_all_test CXX)
if(ENABLE_TESTS)
enable_testing()
endif()		# ENABLE_TESTS

####################
# subdirectories
####################
if(NOT CFD_SINGLE_BUILD)
add_subdirectory(external)
endif()

####################
# uninstall
####################
if(NOT TARGET uninstall)
configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/pc/cmake_uninstall.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake
  IMMEDIATE @ONLY)

add_custom_target(uninstall
  COMMAND ${CMAKE_COMMAND} -P
  ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif()
