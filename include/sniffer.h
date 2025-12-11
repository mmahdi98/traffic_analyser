#ifndef SNIFFER_H
#define SNIFFER_H

#include "traffic_table.h"

/*
    returns 0 on success.
*/
int sniffer_start(const char *interface_name, TrafficTable *table);
void sniffer_stop(void);

#endif //SNIFFER_H
