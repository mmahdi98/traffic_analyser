#ifndef TRAFFIC_TABLE_H
#define TRAFFIC_TABLE_H

#include <stdint.h>

/**
 * Opaque handle to the Traffic Table structure.
 */
typedef struct TrafficTable TrafficTable;

/**
 * @brief Allocates and initializes a new Traffic Table.
 * 
 * @return TrafficTable* Pointer to the new table, or NULL if allocation fails.
 *         The caller is responsible for freeing this memory using traffic_table_destroy().
 */
TrafficTable* traffic_table_create(void);

/**
 * @brief Frees all memory associated with the Traffic Table.
 * 
 * @param table Pointer to the table to destroy. Safe to pass NULL.
 */
void traffic_table_destroy(TrafficTable *table);

/**
 * @brief Updates the statistics for a specific flow.
 * 
 * If the flow (src/dst/proto) exists, counters are incremented.
 * If not, a new entry is created (malloc).
 * 
 * @param table       Pointer to the Traffic Table.
 * @param src_ip      Source IP address in Network Byte Order.
 * @param dst_ip      Destination IP address in Network Byte Order.
 * @param protocol    IP Protocol (e.g., IPPROTO_TCP, IPPROTO_UDP).
 * @param packet_len  Length of the packet in bytes (including headers).
 */
void traffic_table_update(TrafficTable *table, 
                          uint32_t src_ip, 
                          uint32_t dst_ip, 
                          uint8_t protocol, 
                          uint32_t packet_len);

/**
 * @brief Prints a formatted summary of all flows to stdout.
 * 
 * @param table Pointer to the Traffic Table.
 */
void traffic_table_print_report(const TrafficTable *table);

#endif // TRAFFIC_TABLE_H
