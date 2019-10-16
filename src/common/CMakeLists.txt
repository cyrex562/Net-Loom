cmake_minimum_required(VERSION 3.13)

# project name
project(netloom_common)

# compile fmt
# add_subdirectory(../../fmt)

# include_directories(${CMAKE_CURRENT_SOURCE_DIR})

set(SOURCE
   ${SOURCE}
   ${CMAKE_CURRENT_SOURCE_DIR}/init.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/ip6_addr.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/netloom_sys.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/network_interface.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/packet.cpp
   ${CMAKE_CURRENT_SOURCE_DIR}/timeouts.cpp
   PARENT_SCOPE
)

# set(HEADERS
#    ${HEADERS}
#    ${CMAKE_CURRENT_SOURCE_DIR}/*.h
#    PARENT_SCOPE
# )