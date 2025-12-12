# TrafficAnalyser

A lightweight, C-based network traffic analysis tool that captures IPv4 packets (TCP/UDP) on a specified network interface. It aggregates traffic statistics based on flow (Source IP, Destination IP, and Protocol) and generates a summary report.

## 🚀 Features

-   **Real-time Capture:** Uses `libpcap` to capture packets directly from the network interface.
-   **Traffic Aggregation:** Groups packets efficiently using a Hash Table (seeded with `jhash`) based on:
    -   Source IP Address
    -   Destination IP Address
    -   Protocol (TCP/UDP)
-   **Protocol Filtering:** Automatically filters for IPv4 TCP and UDP traffic.
-   **Graceful Shutdown:** Handles `SIGINT` (Ctrl+C) and `SIGALRM` (timer) to safely stop the sniffer and print the report.
-   **Human-Readable Output:** Displays traffic volume in Bytes, KB, MB, or GB.

## 📂 Project Structure
```text
.
├── CMakeLists.txt        # Main build configuration
├── include
│   ├── jhash.h           # Jenkins Hash implementation
│   ├── sniffer.h         # Sniffer module interface
│   └── traffic_table.h   # Hash table interface
├── src
│   ├── main.c            # Entry point, argument parsing, signal handling
│   ├── sniffer.c         # Libpcap interaction and packet filtering
│   └── traffic_table.c   # Hash table logic and report generation
└── tests
├── CMakeLists.txt    # Test build configuration
└── test_hash.c       # Unit tests

## 🛠️ Prerequisites

Before building the project, ensure you have the following installed on your Linux system:

1.  **C Compiler:** GCC or Clang.
2.  **CMake:** Version 3.10 or higher.
3.  **libpcap Development Libraries:**
*   **Debian/Ubuntu:** `sudo apt-get install libpcap-dev`
*   **RHEL/CentOS:** `sudo yum install libpcap-devel`
*   **Arch Linux:** `sudo pacman -S libpcap`

## 🔨 Building the Project

Use the standard CMake workflow to build the application:

bash
mkdir build
cd build
cmake ..
make -j16

## 💻 Usage

To run the analyser, you must provide the **network interface** name and the **duration** (in seconds) for the capture.

> **Note:** Root privileges (`sudo`) are required to capture packets in promiscuous mode.

### Syntax
bash
sudo ./traffic_analyser <interface> <duration>

### Example
Capture traffic on interface `eth0` for `30` seconds:

bash
sudo ./traffic_analyser eth0 30

### Output Example
After the duration expires or you press `Ctrl+C`, the application produces a report:

text
Starting traffic analysis on eth0 for 30 seconds...

--- Traffic Report ---
Src IP           Dst IP           Proto  Count      Total Vol                                                       
-----------------------------------------------------------------------
192.168.1.105    142.250.180.14   TCP    152        142.5KB
192.168.1.105    8.8.8.8          UDP    4          256B
10.0.0.5         10.0.0.1         TCP    1052       1.2MB

## 🧪 Testing
Testing is not fully implemented yet.

The project is configured with CTest (`enable_testing()`). To run the included unit tests:

1.  Build the project first (see "Building the Project" above).
2.  Run the tests from the `build` directory:

bash
cd build
make test
# OR for more verbose output:
ctest -V

## 🧠 Technical Details

### Traffic Table (Hash Map)
The core data structure is defined in `traffic_table.c`. It uses a fixed-size hash table (`65536` buckets) with linked-list chaining for collision resolution. The hashing algorithm used is **Jenkins Hash (`jhash_3words`)**, which hashes the triplet `{src_ip, dst_ip, protocol}` to an index.

### Packet Handling
1.  **Sniffer:** `sniffer.c` initializes `pcap_open_live` and compiles a BPF filter (`ip and (tcp or udp)`).
2.  **Callback:** For every packet passing the filter, `packet_handler` extracts IP headers.
3.  **Update:** `traffic_table_update` is called to atomically increment the packet count and byte volume for the specific flow in the hash table.

## 📜 License

MIT License.
