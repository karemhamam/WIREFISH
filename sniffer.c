/**
 * @file sniffer.c
 * @brief Implementation file for the packet sniffer program.
 * 
 * This file contains the function definitions for capturing and processing
 * network packets. It applies Object-Oriented Programming (OOP) concepts in C
 * to parse different protocol layers (IP, TCP, UDP, ICMP).
 * 
 * The packet sniffer uses libpcap to capture packets from a specified network
 * interface and filter them based on user-defined criteria. It then processes
 * and prints relevant fields of different protocols.
 * 
 * @author Mohamed Hamam
 * @date 30-02-2025
 */

#include "sniffer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

/**
 * @brief Parse an IP packet and identify the next protocol layer.
 * 
 * This function parses the IP header from the captured packet, prints the
 * source and destination IP addresses, and then identifies the next protocol
 * (TCP, UDP, ICMP) based on the IP header's protocol field. The appropriate
 * parsing function is then called for the next protocol layer.
 * 
 * @param packet The captured packet containing raw data to parse.
 */
void parse_ip(Packet *packet) {
    IP_Protocol ip;
    ip.header = (struct ip *)(packet->raw_data + 14); // Skip Ethernet Header
    printf("IP Packet: Source: %s, Destination: %s\n",
           inet_ntoa(ip.header->ip_src), inet_ntoa(ip.header->ip_dst));
    
    // Call the next protocol handler dynamically
    switch (ip.header->ip_p) {
        case IPPROTO_TCP:
            parse_tcp(packet);
            break;
        case IPPROTO_UDP:
            parse_udp(packet);
            break;
        case IPPROTO_ICMP:
            parse_icmp(packet);
            break;
        default:
            printf("Unknown protocol\n");
    }
}

/**
 * @brief Parse a TCP packet and print its source and destination ports.
 * 
 * This function parses the TCP header from the captured packet, which follows
 * the IP header, and prints the source and destination port numbers.
 * 
 * @param packet The captured packet containing raw data to parse.
 */
void parse_tcp(Packet *packet) {
    TCP_Protocol tcp;
    tcp.header = (struct tcphdr *)(packet->raw_data + 14 + sizeof(struct ip)); // After IP Header
    printf("TCP Packet: Source Port: %d, Destination Port: %d\n",
           ntohs(tcp.header->source), ntohs(tcp.header->dest));
}

/**
 * @brief Parse a UDP packet and print its source and destination ports.
 * 
 * This function parses the UDP header from the captured packet, which follows
 * the IP header, and prints the source and destination port numbers.
 * 
 * @param packet The captured packet containing raw data to parse.
 */
void parse_udp(Packet *packet) {
    UDP_Protocol udp;
    udp.header = (struct udphdr *)(packet->raw_data + 14 + sizeof(struct ip)); // After IP Header
    printf("UDP Packet: Source Port: %d, Destination Port: %d\n",
           ntohs(udp.header->source), ntohs(udp.header->dest));
}

/**
 * @brief Parse an ICMP packet and print its type and code.
 * 
 * This function parses the ICMP header from the captured packet, which follows
 * the IP header, and prints the ICMP type and code values.
 * 
 * @param packet The captured packet containing raw data to parse.
 */
void parse_icmp(Packet *packet) {
    ICMP_Protocol icmp;
    icmp.header = (struct icmphdr *)(packet->raw_data + 14 + sizeof(struct ip)); // After IP Header
    printf("ICMP Packet: Type: %d, Code: %d\n",
           icmp.header->type, icmp.header->code);
}

/**
 * @brief Callback function for processing each captured packet.
 * 
 * This function is called for each captured packet and delegates the parsing
 * of the packet to the appropriate protocol handler. It extracts the packet data
 * and passes it to the `parse_ip` function for further processing.
 * 
 * @param args Additional arguments passed to the callback function (not used here).
 * @param header The packet header containing metadata such as packet length.
 * @param packet A pointer to the raw packet data.
 */
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    Packet pkt = {packet, header->caplen};
    parse_ip(&pkt);
}

/**
 * @brief Start packet sniffing with a specific filter and output file.
 * 
 * This function opens a live packet capture session using libpcap, applies a
 * user-defined filter expression (e.g., "ip", "tcp", "udp"), and starts capturing
 * packets from the specified network interface. The captured packets are processed
 * using the `process_packet` function.
 * 
 * @param filter_expr A string representing the filter expression (e.g., "ip", "tcp").
 * @param output_file The name of the file to save the captured packets.
 */
void start_sniffing(const char *filter_expr, const char *output_file) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 net;

    // Open live capture
    handle = pcap_open_live("wlp59s0", BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    // Apply filter
    if (pcap_compile(handle, &fp, filter_expr, 0, net) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Could not apply filter %s\n", filter_expr);
        exit(EXIT_FAILURE);
    }

    // Start packet capture
    pcap_loop(handle, -1, process_packet, NULL);
    
    // Close the session
    pcap_close(handle);
}
