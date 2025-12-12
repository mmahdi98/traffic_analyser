#ifndef SNIFFER_H
#define SNIFFER_H

#include "traffic_table.h"

/**
 * @brief Starts the packet capture loop on the specified interface.
 * 
 * This function blocks indefinitely until sniffer_stop() is called or 
 * a critical error occurs. It captures only TCP/UDP over IPv4.
 * 
 * @param interface_name The name of the network interface (e.g., "eth0", "docker0").
 * @param table          Pointer to an initialized TrafficTable to store stats.
 * 
 * @return 0 on normal exit, -1 on initialization error.
 */
int sniffer_start(const char *interface_name, TrafficTable *table);

/**
 * @brief Signals the capture loop to stop.
 * 
 * This function is safe to call from a signal handler (e.g., SIGINT).
 */
void sniffer_stop(void);

#endif //SNIFFER_H
