#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>

#include <pcap.h>

const suseconds_t US_PER_S = 1000000;

const int snaplen = 1 << 16;
const int is_promiscous = 1;
const int time_limit_ms = 0;  /* unlimited */
const int do_optimize = 1;    /* yes */

void
on_packet(u_char* user, const struct pcap_pkthdr* packet, const u_char* bytes) {
    printf("%llu,%u\n", packet->ts.tv_sec * US_PER_S + packet->ts.tv_usec, packet->len);
}

int
main(int argc, char* argv[]) {
    pcap_t* pcap = NULL;
    char message[PCAP_ERRBUF_SIZE];
    int result;

    const char* filter = NULL;
    struct bpf_program program;

    if ((argc < 2) || ((argc == 2) && (strcmp(argv[1], "-h") == 0))) {
        fprintf(stderr, "Records series of packet lengths and arrival times (SPLT) "
                "for incoming traffic to NIC and outputs it as CSV to stdout.\n");
        fprintf(stderr, "Usage: %s NIC [FILTER] >output.csv\n", argv[0]);
        return EXIT_SUCCESS;
    }

    if (argc == 3) {
        filter = argv[2];
    }

    message[0] = '\0';
    pcap = pcap_open_live(argv[1], snaplen, is_promiscous, time_limit_ms, message);
    if (pcap == NULL) {
        fprintf(stderr, "ERROR: pcap_open_live: %s\n", message);
        return EXIT_FAILURE;
    } else if (message[0] != '\0') {
        fprintf(stderr, "WARNING: pcap_open_live: %s\n", message);
    }

    if (pcap_setdirection(pcap, PCAP_D_IN) < 0) {
        pcap_perror(pcap, "pcap_setdirection");
        return EXIT_FAILURE;
    }

    if (pcap_compile(pcap, &program, filter, do_optimize, PCAP_NETMASK_UNKNOWN) < 0) {
        pcap_perror(pcap, "pcap_compile");
        return EXIT_FAILURE;
    }
    if (pcap_setfilter(pcap, &program) < 0) {
        pcap_perror(pcap, "pcap_setfilter");
        return EXIT_FAILURE;
    }

    puts("time_us,length");

    result = pcap_loop(pcap, -1, on_packet, NULL);
    if (result < 0) {
        pcap_perror(pcap, "pcap_loop");
        fflush(stdout);
        return EXIT_FAILURE;
    }

    fflush(stdout);
    return EXIT_SUCCESS;
}
