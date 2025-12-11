cmake_minimum_required(VERSION 3.10)
project(TrafficAnalyser C)

# 1. Define your source files
set(SOURCES src/main.c)

# 2. specificy the executable name and sources
add_executable(traffic_analyser ${SOURCES})

# 3. Find the pcap library file
find_library(PCAP_LIB pcap)

# 4. Link the library to your executable
if(PCAP_LIB)
    target_link_libraries(traffic_analyser PRIVATE ${PCAP_LIB})
else()
    message(FATAL_ERROR "libpcap not found. Please install libpcap-dev.")
endif()

