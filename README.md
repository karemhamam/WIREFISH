
# Packet Sniffer

This is a packet sniffer program implemented in C using the `libpcap` library. The program captures and processes network packets, providing detailed information about various protocols (IP, TCP, UDP, ICMP) and application-layer protocols (HTTP, HTTPS, SSH).

The code demonstrates Object-Oriented Programming (OOP) concepts in C, including abstraction, encapsulation, polymorphism, and inheritance, by using structs to represent different protocol layers.

## Features

- Captures network packets using `libpcap`.
- Parses and displays fields from the IP layer, including source and destination IPs.
- Handles multiple transport-layer protocols:
  - TCP
  - UDP
  - ICMP
- Supports filtering captured packets based on IP and port using filter expressions.
- Captures and parses application-layer protocols:
  - HTTP
  - HTTPS
  - SSH
- Supports saving the captured data to a file in pcap format, which can be opened with tools like Wireshark.

## Requirements

- C Compiler (GCC or similar)
- `libpcap` library (often available via `libpcap-dev` package on Linux)
- Linux or macOS system with `libpcap` support

## Installation

### 1. Install libpcap

On Linux (Ubuntu/Debian):

```bash
sudo apt-get update
sudo apt-get install libpcap-dev
```


### 2. Clone the Repository

Clone the repository to your local machine:

```bash
git clone https://github.com/yourusername/packet-sniffer.git
cd packet-sniffer
```

### 3. Compile the Program

Use `make` to compile the program:

```bash
gcc -o sniffer main.c sniffer.c -lpcap
```

## Usage

### Command-Line Arguments

The program expects two arguments:
1. **Filter Expression** (string): A `libpcap` filter expression used to capture specific packets (e.g., `ip`, `tcp`, `udp`).
2. **Output File** (string): The filename where the captured packets will be saved.

### Example Command

```bash
./sniffer "tcp port 80" output.pcap
```

This command captures only TCP packets on port 80 (HTTP traffic) and saves the captured packets to `output.pcap`.

### List of Supported Protocols

- **IP Layer**: Displays source and destination IP addresses.
- **Transport Layer**:
  - **TCP**: Displays source and destination ports.
  - **UDP**: Displays source and destination ports.
  - **ICMP**: Displays ICMP type and code.
- **Application Layer**: Identifies protocols like HTTP, HTTPS, and SSH.

### Saving and Viewing Captures

Captured packets are saved in the **PCAP** format, which can be viewed using Wireshark or any other compatible network packet analysis tool.

### Example Output

For an HTTP packet:

```plaintext
IP Packet: Source: 192.168.0.1, Destination: 192.168.0.2
TCP Packet: Source Port: 443, Destination Port: 80
```

For an ICMP packet:

```plaintext
IP Packet: Source: 192.168.0.1, Destination: 192.168.0.2
ICMP Packet: Type: 8, Code: 0
```