cmake_minimum_required(VERSION 3.13)

# project name
project(net_loom)

# set c++ standard to C++ 17
set(CMAKE_CXX_STANDARD 17)


set(SOURCE src/main.cpp)

# compile fmt
add_subdirectory(fmt)

# compile libzmq
add_subdirectory(libzmq)

# compile mbedtls
add_subdirectory(mbedtls)

# compile stduuid
add_subdirectory(stduuid)

# compile netloom_common
add_subdirectory(src/common)

# compile common


# add src
# add_library(net_loom STATIC ${SRC_FILES})
# includes
add_library(net_loom STATIC ${SOURCE})
target_include_directories(net_loom PUBLIC src)
target_include_directories(net_loom PUBLIC npcap/Include)
target_include_directories(net_loom PUBLIC npcap/Include/pcap)
target_include_directories(net_loom PUBLIC mbedtls/include)
target_include_directories(net_loom PUBLIC spdlog/include)
target_include_directories(net_loom PUBLIC stduuid/include)
target_include_directories(net_loom PUBLIC src/common)

# libraries to link
target_link_libraries(net_loom fmt)
target_link_libraries(net_loom libzmq)
target_link_libraries(net_loom spdlog)
target_link_libraries(net_loom npcap/Lib/x64/wpcap.lib)
target_link_libraries(net_loom npcap/Lib/x64/Packet.lib)
target_link_libraries(net_loom stduuid)

#
# END OF FILE
#




