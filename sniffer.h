/**
 * @file sniffer.h
 * @brief Header file for the packet sniffer program.
 * 
 * This file defines the structures and function prototypes for capturing
 * and processing network packets. The code uses Object-Oriented Programming
 * (OOP) concepts such as encapsulation and polymorphism in C to handle
 * different protocol layers (IP, TCP, UDP, ICMP).
 * 
 * @author Mohamed Hamam
 * @date 30-02-2025
 */

#ifndef SNIFFER_H
#define SNIFFER_H

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

/**
 * @brief Packet structure to represent a raw packet.
 * 
 * This structure encapsulates the raw packet data and its size.
 */
typedef struct {
    const u_char *raw_data; /**< Pointer to raw packet data */
    int size;               /**< Size of the packet */
} Packet;

/**
 * @brief Base Protocol structure for packet protocols.
 * 
 * This is an abstract base structure representing a network protocol. It contains
 * a function pointer to parse the protocol data, which will be overridden by
 * derived protocol structures.
 */
typedef struct {
    void (*parse)(Packet *); /**< Function pointer to parse the packet */
} Protocol;

/**
 * @brief IP Protocol structure, derived from the base Protocol.
 * 
 * This structure represents the IP protocol. It contains the IP header and inherits
 * from the base Protocol structure.
 */
typedef struct {
    Protocol base; /**< Base protocol for polymorphism */
    struct ip *header; /**< Pointer to the IP header */
} IP_Protocol;

/**
 * @brief TCP Protocol structure, derived from the base Protocol.
 * 
 * This structure represents the TCP protocol. It contains the TCP header and inherits
 * from the base Protocol structure.
 */
typedef struct {
    Protocol base; /**< Base protocol for polymorphism */
    struct tcphdr *header; /**< Pointer to the TCP header */
} TCP_Protocol;

/**
 * @brief UDP Protocol structure, derived from the base Protocol.
 * 
 * This structure represents the UDP protocol. It contains the UDP header and inherits
 * from the base Protocol structure.
 */
typedef struct {
    Protocol base; /**< Base protocol for polymorphism */
    struct udphdr *header; /**< Pointer to the UDP header */
} UDP_Protocol;

/**
 * @brief ICMP Protocol structure, derived from the base Protocol.
 * 
 * This structure represents the ICMP protocol. It contains the ICMP header and inherits
 * from the base Protocol structure.
 */
typedef struct {
    Protocol base; /**< Base protocol for polymorphism */
    struct icmphdr *header; /**< Pointer to the ICMP header */
} ICMP_Protocol;

/**
 * @brief Start sniffing network traffic.
 * 
 * This function opens the network interface for packet capture and applies
 * a filter expression (such as for a specific IP or port). It also saves
 * captured packets to a specified output file.
 * 
 * @param filter_expr A string representing the filter expression (e.g., "ip", "tcp").
 * @param output_file The name of the file to save the captured packets.
 */
void start_sniffing(const char *filter_expr, const char *output_file);

/**
 * @brief Process each captured packet.
 * 
 * This function is called for every packet captured by libpcap. It analyzes
 * the packet and delegates the parsing to the appropriate protocol function
 * (IP, TCP, UDP, ICMP).
 * 
 * @param args Additional arguments passed to the callback function (not used here).
 * @param header The packet header containing metadata such as packet length.
 * @param packet A pointer to the raw packet data.
 */
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

/**
 * @brief Parse an IP packet.
 * 
 * This function processes the packet data for the IP protocol, extracting and
 * displaying relevant fields such as source and destination IP addresses.
 * 
 * @param packet The packet structure containing the raw data of the captured packet.
 */
void parse_ip(Packet *packet);

/**
 * @brief Parse a TCP packet.
 * 
 * This function processes the packet data for the TCP protocol, extracting
 * and displaying relevant fields such as source/destination ports and sequence numbers.
 * 
 * @param packet The packet structure containing the raw data of the captured packet.
 */
void parse_tcp(Packet *packet);

/**
 * @brief Parse a UDP packet.
 * 
 * This function processes the packet data for the UDP protocol, extracting
 * and displaying relevant fields such as source/destination ports.
 * 
 * @param packet The packet structure containing the raw data of the captured packet.
 */
void parse_udp(Packet *packet);

/**
 * @brief Parse an ICMP packet.
 * 
 * This function processes the packet data for the ICMP protocol, extracting
 * and displaying relevant fields such as type and code for ICMP messages.
 * 
 * @param packet The packet structure containing the raw data of the captured packet.
 */
void parse_icmp(Packet *packet);

#endif
