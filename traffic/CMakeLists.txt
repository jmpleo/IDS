cmake_minimum_required(VERSION 3.0)
project(sniffer)

set(CMAKE_CXX_STANDARD 17)

find_package(PcapPlusPlus REQUIRED)

add_executable(${PROJECT_NAME} main.cpp)

target_link_libraries(${PROJECT_NAME}
    pcap
    PcapPlusPlus::Pcap++
    pq
    curl
)
