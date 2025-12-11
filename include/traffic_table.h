#ifndef TRAFFIC_TABLE_H
#define TRAFFIC_TABLE_H

#include <stdint.h>

typedef struct TrafficTable TrafficTable;

TrafficTable* traffic_table_create(void);
void traffic_table_destroy(TrafficTable *table);
void traffic_table_update(TrafficTable *table, 
                          uint32_t src_ip, 
                          uint32_t dst_ip, 
                          uint8_t protocol, 
                          uint32_t packet_len);
void traffic_table_print_report(const TrafficTable *table);

#endif // TRAFFIC_TABLE_H
