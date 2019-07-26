cmake_minimum_required(VERSION 3.13)

# project name
project(lwip)

# set c++ standard to C++ 17
set(CMAKE_CXX_STANDARD 17)
# set c standard to C11
set(CMAKE_C_STANDARD 11)
set(LWIP_DIR ${CMAKE_CURRENT_SOURCE_DIR})


# Package generation
#set(CPACK_SOURCE_GENERATOR "ZIP")
#set(CPACK_SOURCE_PACKAGE_DESCRIPTION_SUMMARY "lwIP lightweight IP stack")
#set(CPACK_PACKAGE_VERSION_MAJOR "${LWIP_VERSION_MAJOR}")
#set(CPACK_PACKAGE_VERSION_MINOR "${LWIP_VERSION_MINOR}")
#set(CPACK_PACKAGE_VERSION_PATCH "${LWIP_VERSION_REVISION}")
#set(CPACK_SOURCE_IGNORE_FILES "/build/;${CPACK_SOURCE_IGNORE_FILES};.git")
#set(CPACK_SOURCE_PACKAGE_FILE_NAME "lwip-${LWIP_VERSION_MAJOR}.${LWIP_VERSION_MINOR}.${LWIP_VERSION_REVISION}")
#include(CPack)

# Target for package generation
#add_custom_target(dist COMMAND ${CMAKE_MAKE_PROGRAM} package_source)
#add_dependencies(dist lwipdocs)

# compile fmt
#add_subdirectory(fmt)
#add_subdirectory(fmt/build)

file(GLOB SRC_FILES src/*.c src/*.cpp)

# add src
add_library(lwip STATIC ${SRC_FILES})
target_include_directories(lwip PUBLIC src)
#target_include_directories(lwip PUBLIC npcap/Include)
#target_include_directories(lwip PUBLIC npcap/Include/pcap)
#target_link_libraries(lwip fmt)
#target_link_libraries(lwip npcap/Lib/x64/wpcap.lib)
#target_link_libraries(lwip npcap/Lib/x64/Packet.lib)





