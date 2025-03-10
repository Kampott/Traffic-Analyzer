cmake_minimum_required(VERSION 3.10)
project(PacketSniffer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)


include_directories(headers)

# pcap
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

add_executable(PacketSniffer src/main.cpp src/PacketSniffer.cpp)

target_link_libraries(PacketSniffer ${PCAP_LIBRARIES})
target_include_directories(PacketSniffer PRIVATE ${PCAP_INCLUDE_DIRS})

