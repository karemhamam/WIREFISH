/**
 * @file main.c
 * @brief Main entry point for the packet sniffer program.
 *
 * This file contains the main function for the packet sniffer program. It processes
 * command-line arguments, validates them, and calls the packet sniffing function.
 *
 * The program requires two arguments: 
 * - A filter expression for packet capturing
 * - An output file to save the captured packets
 *
 * It uses the start_sniffing function from the sniffer module to begin packet sniffing.
 */

#include "sniffer.h"
#include <stdio.h>
#include <stdlib.h>

/**
 * @brief Main function for the packet sniffer program.
 *
 * This function checks if the correct number of arguments are passed (at least two).
 * It then calls the `start_sniffing` function to initiate packet capture using 
 * the provided filter expression and output file name.
 * 
 * @param argc Number of command-line arguments.
 * @param argv Array of command-line argument strings.
 * 
 * @return 0 if the program executes successfully, exits with failure code if
 *         arguments are incorrect.
 */
int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <filter expression> <output file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    start_sniffing(argv[1], argv[2]);
    return 0;
}
