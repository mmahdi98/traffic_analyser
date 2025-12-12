#include "traffic_table.h"
#include "jhash.h"
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

#define TABLE_SIZE 65536

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t  protocol;
} TrafficKey;

typedef struct TrafficEntry {
    TrafficKey key;
    uint64_t packet_count;
    uint64_t total_bytes;
    struct TrafficEntry *next;
} TrafficEntry;

struct TrafficTable {
    TrafficEntry *buckets[TABLE_SIZE];
};

TrafficTable* traffic_table_create(void)
{
    TrafficTable *t = calloc(1, sizeof(TrafficTable));
    if (!t) {
        perror("Fatal: Could not allocate Traffic Table");
        exit(EXIT_FAILURE);
    }
    return t;
}

static uint32_t calculate_hash(const TrafficKey *key)
{
    return jhash_3words(key->src_ip, key->dst_ip, key->protocol, 0); // Seed 0, should be changed later.
}

void traffic_table_update(TrafficTable *table, 
                          uint32_t src_ip, 
                          uint32_t dst_ip, 
                          uint8_t protocol, 
                          uint32_t packet_len)
{
    TrafficKey key;
    key.src_ip = src_ip;
    key.dst_ip = dst_ip;
    key.protocol = protocol;
    uint32_t idx = calculate_hash(&key) % TABLE_SIZE;

    for (TrafficEntry *entry = table->buckets[idx]; entry; entry = entry->next)
        if (entry->key.src_ip == key.src_ip && 
            entry->key.dst_ip == key.dst_ip && 
            entry->key.protocol == key.protocol) 
        {
            entry->packet_count++;
            entry->total_bytes += packet_len;
            return; // TABLE HIT
        }

    TrafficEntry *new_entry = malloc(sizeof(TrafficEntry)); // TABLE MISS
    if (!new_entry)
    {
        perror("Warning: Failed to allocate traffic entry, packet dropped");
        return;
    }
    new_entry->key = key;
    new_entry->packet_count = 1;
    new_entry->total_bytes = packet_len;
    new_entry->next = table->buckets[idx];
    table->buckets[idx] = new_entry;
}

static char *ip_to_str(uint32_t ip, char *buf)
{
    struct in_addr addr = { .s_addr = ip };
    inet_ntop(AF_INET, &addr, buf, INET_ADDRSTRLEN);
    return buf;
}

static char *format_volume(char *buffer, size_t size, uint64_t bytes) {
    double kb = 1024.0;
    double mb = kb * 1024.0;
    double gb = mb * 1024.0;
    if (bytes >= gb)
        snprintf(buffer, size, "%luB(%.1fGB)", bytes, (double)bytes / gb);
    else if (bytes >= mb) 
        snprintf(buffer, size, "%luB(%.1fMB)", bytes, (double)bytes / mb);
    else if (bytes >= kb) 
        snprintf(buffer, size, "%luB(%.1fKB)", bytes, (double)bytes / kb);
    else 
        snprintf(buffer, size, "%luB", bytes);
    return buffer;
}

void traffic_table_print_report(const TrafficTable *table) 
{
    printf("%-16s %-16s %-6s %-10s %-64s\n", "Src IP", "Dst IP", "Proto", "Count", "Total Vol"); // printing the headr of the table
    printf("-----------------------------------------------------------------------\n");
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN]; // buffer for src_ip, dst_ip strings
    char vol_str[64]; // buffer for formatted size string
    for (int i = 0; i < TABLE_SIZE; i++)
        for (TrafficEntry *entry = table->buckets[i]; entry; entry = entry->next)
            printf("%-16s %-16s %-6s %-10lu %s\n", 
                ip_to_str(entry->key.src_ip, src), 
                ip_to_str(entry->key.dst_ip, dst), 
                (entry->key.protocol == 6) ? "TCP" : "UDP",
                entry->packet_count,
                format_volume(vol_str, sizeof(vol_str), entry->total_bytes)
            ); // printing the entries of the table
}

void traffic_table_destroy(TrafficTable *table) 
{
    if (!table) return;
    for (int i = 0; i < TABLE_SIZE; i++) 
    {
        TrafficEntry *entry = table->buckets[i];
        while (entry)
        {
            TrafficEntry *temp = entry;
            entry = entry->next;
            free(temp);
        }
    }
    free(table);
}
