#include "traffic_table.h"
#include "sniffer.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

void handle_signal(int sig)
{
    (void)sig; 
    sniffer_stop();
}

int parse_duration(const char *input_str, int *duration) {
    char *endptr;
    long val = strtol(input_str, &endptr, 10); 	// decimal

    if (endptr == input_str) // no digits were found
	{
		fprintf(stderr, "Error: Duration '%s' is not a number.\n", input_str);
		return -1;
	}

	if (*endptr != '\0') // has non-numerical endings like "15abc"
	{
		fprintf(stderr, "Error: Duration '%s' has non digit parts.\n", input_str);
		return -1;
	}

    if (val <= 0) // must be a postivie integer
	{
		fprintf(stderr, "Error: Duration must be a positive integer > 0.\n");
		return -1;
	}
	*duration = (int)val;
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc != 3)
	{
        fprintf(stderr, "Usage: %s <interface> <duration>\n", argv[0]);
        return EXIT_FAILURE;
    }

    char iface[65];
	snprintf(iface, 65, "%s", argv[1]); //64 seems to be enough for that

    int duration;
	if (parse_duration(argv[2], &duration) != 0) {
		return EXIT_FAILURE;  // error is already printed in function
	}

    TrafficTable *table = traffic_table_create();

    signal(SIGINT, handle_signal);
    signal(SIGALRM, handle_signal);
    alarm(duration);

    printf("Starting traffic analysis on %s for %d seconds...\n", iface, duration);
    if (sniffer_start(iface, table) != 0)
	{
        traffic_table_destroy(table);
        return EXIT_FAILURE;
    }

    printf("\n--- Traffic Report ---\n");
    traffic_table_print_report(table);
    traffic_table_destroy(table);
    return EXIT_SUCCESS;
}
