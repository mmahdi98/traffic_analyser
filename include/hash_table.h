#ifndef HASH_TABLE_H
#define HASH_TABLE_H
#include <stdio.h>
#include "jhash.h"
#define HASH_TABLE_SIZE 65536 // 2^16 buckets for efficient distribution

typedef struct {
    uint32_t dst_ip;	// Destination IP address (in network byte order)
    uint32_t src_ip;	// Destination IP address (in network byte order)
    uint8_t  protocol;	// IPPROTO_TCP(6) or IPPROTO_UDP(17)
} traffic_key_t;

// Helper to print keys in a readable format
void print_hash_table_key(const char* label, traffic_key_t *k) {
    printf("%s [Src: %08x | Dst: %08x | Proto: %u]\n", 
           label, k->src_ip, k->dst_ip, k->protocol);
}

uint32_t get_hash(traffic_key_t *key) {
    return jhash_3words(key->src_ip, key->dst_ip, key->protocol, 0); // change 0 to some seed!
}

typedef struct {
	unsigned long packet_count;		// Number Of Packets on a specific traffic
    unsigned long long  total_bytes; // Total bytes Of data on a specific traffic
} traffic_stats_t;

typedef struct traffic_node {
    traffic_key_t key;
    traffic_stats_t stats;
    struct traffic_node *next;
} traffic_node_t;

//@todo tests for hash table

#endif /* HASH_TABLE_H */