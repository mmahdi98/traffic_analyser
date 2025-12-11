cmake_minimum_required(VERSION 3.10)
project(TrafficAnalyser C)

include_directories(include)

set(SOURCES
    src/main.c
    src/traffic_table.c
    src/sniffer.c
)

add_executable(traffic_analyser ${SOURCES})

find_library(PCAP_LIB pcap)
if(PCAP_LIB)
    target_link_libraries(traffic_analyser PRIVATE ${PCAP_LIB})
else()
    message(FATAL_ERROR "libpcap not found. Please install libpcap-dev.")
endif()

enable_testing()

add_subdirectory(tests)
