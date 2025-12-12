#include "sniffer.h"
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static pcap_t *g_pcap_handle = NULL;

static void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *header, const unsigned char *packet)
{
    TrafficTable *table = (TrafficTable *)user_data;
    if (header->caplen < sizeof(struct ether_header)) return; // truncated packet

    struct ether_header *eth = (struct ether_header *)packet;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return; // not ip packet, problem with pcap filter

    size_t ip_offset = sizeof(struct ether_header);
    if (header->caplen < ip_offset + sizeof(struct ip)) return;  // truncated packet

    struct ip *ip_header = (struct ip *)(packet + ip_offset);
    if (ip_header->ip_v != 4) return; // not version 4, probably problem with pcap filter
    
    size_t ip_hdr_len = ip_header->ip_hl * 4;
    if (ip_hdr_len < 20 || header->caplen < ip_offset + ip_hdr_len) return;  // invalid or truncated ip header

    uint8_t protocol = ip_header->ip_p;
    if (protocol != 6 && protocol != 17) return; // not tcp or udp,  probably problem with pcap filter

    traffic_table_update(
        table, 
        ip_header->ip_src.s_addr,
        ip_header->ip_dst.s_addr,
        ip_header->ip_p,
        header->len
    );
}

static int interface_exists(const char *interface_name, char *errbuf)
{
    pcap_if_t *all_devs = NULL;
    
    if (pcap_findalldevs(&all_devs, errbuf) == -1)
        return -1;  // Error occurred
    
    int found = 0;
    for (pcap_if_t *dev = all_devs; dev != NULL; dev = dev->next)
        if (strcmp(dev->name, interface_name) == 0) 
        {
            found = 1;
            break;
        }
    
    pcap_freealldevs(all_devs);
    return found;
}

int sniffer_start(const char *interface_name, TrafficTable *table)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    int exists = interface_exists(interface_name, errbuf);
    if (exists == -1) 
    {
        fprintf(stderr, "Error checking interfaces: %s\n", errbuf);
        return -1;
    }

    if (exists == 0)
    {
        fprintf(stderr, "Error: Interface '%s' not found.\n", interface_name);
        return -1;
    }

    g_pcap_handle = pcap_open_live(interface_name, BUFSIZ, 1, 1000, errbuf);
    if (!g_pcap_handle)
    {
        fprintf(stderr, "PCAP Error: %s\n", errbuf);
        return -1;
    }

    struct bpf_program fp;
    const char *filter_exp = "ip and (tcp or udp)";
    if (pcap_compile(g_pcap_handle, &fp, filter_exp, 1, PCAP_NETMASK_UNKNOWN) != -1)
    {
        pcap_setfilter(g_pcap_handle, &fp);
        pcap_freecode(&fp);
    }

    pcap_loop(g_pcap_handle, -1, packet_handler, (unsigned char*)table);
    pcap_close(g_pcap_handle);
    g_pcap_handle = NULL;
    return 0;
}

void sniffer_stop(void)
{
    if (g_pcap_handle)
        pcap_breakloop(g_pcap_handle);
}
