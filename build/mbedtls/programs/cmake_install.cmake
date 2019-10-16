# Install script for directory: D:/projects/net_loom/mbedtls/programs

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "C:/Program Files (x86)/ns")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Debug")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("D:/projects/net_loom/build/mbedtls/programs/aes/cmake_install.cmake")
  include("D:/projects/net_loom/build/mbedtls/programs/hash/cmake_install.cmake")
  include("D:/projects/net_loom/build/mbedtls/programs/pkey/cmake_install.cmake")
  include("D:/projects/net_loom/build/mbedtls/programs/random/cmake_install.cmake")
  include("D:/projects/net_loom/build/mbedtls/programs/ssl/cmake_install.cmake")
  include("D:/projects/net_loom/build/mbedtls/programs/test/cmake_install.cmake")
  include("D:/projects/net_loom/build/mbedtls/programs/x509/cmake_install.cmake")
  include("D:/projects/net_loom/build/mbedtls/programs/util/cmake_install.cmake")

endif()

