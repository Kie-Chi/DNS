#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

// 全局变量
long long packet_count = 0;
pcap_t *handle;

void cleanup(int signum) {
    printf("\n\n[*] Interrupted by user.\n");
    printf("==============================\n");
    printf("[*] Final packet count: %lld\n", packet_count);
    printf("==============================\n");
    
    if (handle) {
        pcap_breakloop(handle);
        pcap_close(handle);
    }
    exit(0);
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    packet_count++;
    // 减少打印频率
    if (packet_count % 10000 == 0) {
        printf("\rPackets received: %lld", packet_count);
        fflush(stdout);
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "udp port 53";
    bpf_u_int32 net;

    signal(SIGINT, cleanup);

    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device eth0: %s\n", errbuf);
        return 2;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    
    printf("[*] Starting C-based packet counter on interface 'eth0'...\n");
    printf("[*] Press Ctrl+C to stop and see the final count.\n");

    pcap_loop(handle, -1, packet_handler, NULL);

    cleanup(0); // Should not be reached, but for completeness
    return 0;
}