#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/if_packet.h>
#include <time.h>
#include <getopt.h>
#include <stdint.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>

#define DEFAULT_USERS 100
#define DEFAULT_WEBS  5
#define DEFAULT_WAS   2
#define DEFAULT_DBS   1

#define DEFAULT_USER_IP "10.0.1.1"
#define DEFAULT_WEB_IP  "10.0.2.1"
#define DEFAULT_WAS_IP  "10.0.3.1"
#define DEFAULT_DB_IP   "10.0.4.1"

#define PORT_HTTP 80
#define PORT_WAS  8080
#define PORT_DB   3306 // MySQL default

#define LOG_FILE_NAME "pktgen_summary.log"

// Signal flag to control the loop execution
volatile int keep_running = 1;

// Signal handler for SIGINT (Ctrl+C)
void handle_sigint(int sig) {
    (void)sig;
    keep_running = 0;
}

// TCP Pseudo Header for Checksum
struct pseudo_header {
    uint32_t source_address;
    uint32_t destination_address;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_length;
};

// Checksum calculation function
unsigned short calculate_checksum(unsigned short *addr, int count) {
    long sum = 0;
    while (count > 1) {
        sum += *addr++;
        count -= 2;
    }
    if (count > 0) {
        sum += *(unsigned char *)addr;
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return (unsigned short)(~sum);
}

// Compute TCP checksum including Pseudo Header
unsigned short compute_tcp_checksum(struct iphdr *iph, struct tcphdr *tcph, const char *payload, int payload_len) {
    int tcp_len = sizeof(struct tcphdr) + payload_len;
    struct pseudo_header psh;
    psh.source_address = iph->saddr;
    psh.destination_address = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(tcp_len);

    int psize = sizeof(struct pseudo_header) + tcp_len;
    char *pseudogram = malloc(psize);
    if (!pseudogram) return 0;

    memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));
    if (payload_len > 0) {
        memcpy(pseudogram + sizeof(struct pseudo_header) + sizeof(struct tcphdr), payload, payload_len);
    }

    unsigned short chksum = calculate_checksum((unsigned short*)pseudogram, psize);
    free(pseudogram);
    return chksum;
}

// Generate IP address based on base and index
uint32_t get_ip(uint32_t base_ip, int index) {
    uint32_t host_ip = ntohl(base_ip);
    host_ip += index;
    return htonl(host_ip);
}

// Generate unique MAC address based on tier and index
void get_mac(uint8_t mac[6], int tier, int index) {
    mac[0] = 0x02;
    mac[1] = (uint8_t)tier;
    mac[2] = 0x00;
    mac[3] = 0x00;
    mac[4] = (uint8_t)((index >> 8) & 0xFF);
    mac[5] = (uint8_t)(index & 0xFF);
}

// Payload templates
const char *PAYLOAD_USER_HTTP_REQ = 
    "GET /index.html HTTP/1.1\r\n"
    "Host: www.company.local\r\n"
    "User-Agent: RockyPktGen/1.0\r\n"
    "Accept: */*\r\n\r\n";

const char *PAYLOAD_WEB_HTTP_RES = 
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html\r\n"
    "Content-Length: 62\r\n"
    "Connection: close\r\n\r\n"
    "<html><body><h1>Rocky Linux Packet Generator Response</h1></body></html>";

const char *PAYLOAD_WEB_WAS_REQ = 
    "POST /api/v1/auth HTTP/1.1\r\n"
    "Host: was.company.local\r\n"
    "Content-Type: application/json\r\n"
    "Content-Length: 35\r\n\r\n"
    "{\"username\":\"admin\",\"pass\":\"admin\"}";

const char *PAYLOAD_WAS_WEB_RES = 
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: application/json\r\n"
    "Content-Length: 42\r\n\r\n"
    "{\"status\":\"success\",\"token\":\"jwt_dummy_123\"}";

const char *PAYLOAD_WAS_DB_REQ = 
    "\x03\x00\x00\x00\x03SELECT password FROM users WHERE username = 'admin' LIMIT 1;"; // MySQL COM_QUERY

const char *PAYLOAD_DB_WAS_RES = 
    "\x01\x00\x00\x01\x01\x1b\x00\x00\x02\x03" "def" "\x04" "test" "\x05" "users" "\x05" "users" "\x08" "password" "\x08" "password" "\x0c\x3f\x00\xff\x00\x00\x00\xfd\x00\x00\x1f\x00\x00";

// Write IP and MAC map to ip.log
void write_ip_log(const char *filename, uint32_t ip_users, int num_users,
                  uint32_t ip_webs, int num_webs,
                  uint32_t ip_was, int num_was,
                  uint32_t ip_dbs, int num_dbs) {
    FILE *f = fopen(filename, "w");
    if (!f) {
        perror("Failed to create ip.log");
        return;
    }
    fprintf(f, "=== Simulated IP & MAC Allocation Map ===\n\n");
    
    fprintf(f, "[User Nodes]\n");
    for (int i = 0; i < num_users; i++) {
        struct in_addr addr;
        addr.s_addr = get_ip(ip_users, i);
        uint8_t mac[6];
        get_mac(mac, 1, i);
        fprintf(f, "  IP: %-15s | MAC: %02x:%02x:%02x:%02x:%02x:%02x | Role: User_%d\n",
                inet_ntoa(addr), mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], i);
    }
    fprintf(f, "\n");

    fprintf(f, "[Web Server Nodes]\n");
    for (int i = 0; i < num_webs; i++) {
        struct in_addr addr;
        addr.s_addr = get_ip(ip_webs, i);
        uint8_t mac[6];
        get_mac(mac, 2, i);
        fprintf(f, "  IP: %-15s | MAC: %02x:%02x:%02x:%02x:%02x:%02x | Role: Web_%d\n",
                inet_ntoa(addr), mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], i);
    }
    fprintf(f, "\n");

    fprintf(f, "[WAS Server Nodes]\n");
    for (int i = 0; i < num_was; i++) {
        struct in_addr addr;
        addr.s_addr = get_ip(ip_was, i);
        uint8_t mac[6];
        get_mac(mac, 3, i);
        fprintf(f, "  IP: %-15s | MAC: %02x:%02x:%02x:%02x:%02x:%02x | Role: WAS_%d\n",
                inet_ntoa(addr), mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], i);
    }
    fprintf(f, "\n");

    fprintf(f, "[DB Server Nodes]\n");
    for (int i = 0; i < num_dbs; i++) {
        struct in_addr addr;
        addr.s_addr = get_ip(ip_dbs, i);
        uint8_t mac[6];
        get_mac(mac, 4, i);
        fprintf(f, "  IP: %-15s | MAC: %02x:%02x:%02x:%02x:%02x:%02x | Role: DB_%d\n",
                inet_ntoa(addr), mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], i);
    }
    
    fclose(f);
    printf("IP allocation map successfully logged to '%s'\n", filename);
}

int main(int argc, char *argv[]) {
    // Register signal handler for Ctrl+C
    signal(SIGINT, handle_sigint);

    // Reconstruct the command line command and options
    char cmd_line[1024] = {0};
    for (int i = 0; i < argc; i++) {
        strncat(cmd_line, argv[i], sizeof(cmd_line) - strlen(cmd_line) - 1);
        if (i < argc - 1) {
            strncat(cmd_line, " ", sizeof(cmd_line) - strlen(cmd_line) - 1);
        }
    }

    char *if_name = NULL;
    int num_users = DEFAULT_USERS;
    int num_webs = DEFAULT_WEBS;
    int num_was = DEFAULT_WAS;
    int num_dbs = DEFAULT_DBS;

    uint32_t ip_users = inet_addr(DEFAULT_USER_IP);
    uint32_t ip_webs = inet_addr(DEFAULT_WEB_IP);
    uint32_t ip_was = inet_addr(DEFAULT_WAS_IP);
    uint32_t ip_dbs = inet_addr(DEFAULT_DB_IP);

    int target_pps = 0; // 0 means maximum speed
    int duration_min = 0; // 0 means infinite

    struct option long_options[] = {
        {"interface", required_argument, 0, 'i'},
        {"users", required_argument, 0, 'u'},
        {"webs", required_argument, 0, 'w'},
        {"was", required_argument, 0, 'a'},
        {"dbs", required_argument, 0, 'd'},
        {"user-ip", required_argument, 0, 1000},
        {"web-ip", required_argument, 0, 1001},
        {"was-ip", required_argument, 0, 1002},
        {"db-ip", required_argument, 0, 1003},
        {"pps", required_argument, 0, 'r'},
        {"duration", required_argument, 0, 't'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:u:w:a:d:r:t:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'i': if_name = strdup(optarg); break;
            case 'u': num_users = atoi(optarg); break;
            case 'w': num_webs = atoi(optarg); break;
            case 'a': num_was = atoi(optarg); break;
            case 'd': num_dbs = atoi(optarg); break;
            case 1000: ip_users = inet_addr(optarg); break;
            case 1001: ip_webs = inet_addr(optarg); break;
            case 1002: ip_was = inet_addr(optarg); break;
            case 1003: ip_dbs = inet_addr(optarg); break;
            case 'r': target_pps = atoi(optarg); break;
            case 't': duration_min = atoi(optarg); break;
            case 'h':
            default:
                printf("Usage: %s -i <interface> [options]\n", argv[0]);
                printf("Options:\n");
                printf("  -i, --interface  Network interface to inject packets (e.g., eth0)\n");
                printf("  -u, --users      Number of simulated users (default: %d)\n", DEFAULT_USERS);
                printf("  -w, --webs       Number of simulated Web servers (default: %d)\n", DEFAULT_WEBS);
                printf("  -a, --was        Number of simulated WAS servers (default: %d)\n", DEFAULT_WAS);
                printf("  -d, --dbs        Number of simulated DB servers (default: %d)\n", DEFAULT_DBS);
                printf("  --user-ip        Base IP of users (default: %s)\n", DEFAULT_USER_IP);
                printf("  --web-ip         Base IP of Web servers (default: %s)\n", DEFAULT_WEB_IP);
                printf("  --was-ip         Base IP of WAS servers (default: %s)\n", DEFAULT_WAS_IP);
                printf("  --db-ip          Base IP of DB servers (default: %s)\n", DEFAULT_DB_IP);
                printf("  -r, --pps        Target Packets Per Second (default: max)\n");
                printf("  -t, --duration   Execution duration in minutes (default: infinite)\n");
                return 1;
        }
    }

    if (!if_name) {
        fprintf(stderr, "Error: Network interface (-i) is required.\n");
        return 1;
    }

    // Set up socket
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("Socket creation failed (Must run as root/sudo)");
        return 1;
    }

    // Find interface index
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("Failed to get interface index");
        close(sock);
        return 1;
    }
    int if_index = ifr.ifr_ifindex;

    // Set up socket address
    struct sockaddr_ll saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sll_family = AF_PACKET;
    saddr.sll_ifindex = if_index;
    saddr.sll_halen = ETH_ALEN;

    printf("Starting Packet Generator on interface: %s\n", if_name);
    printf("Simulation counts: Users=%d, Web=%d, WAS=%d, DB=%d\n", num_users, num_webs, num_was, num_dbs);
    if (duration_min > 0) {
        printf("Execution time limit: %d minutes\n", duration_min);
    } else {
        printf("Execution time limit: infinite (Press Ctrl+C to stop)\n");
    }

    // Packet buffers
    char pkt_buf[2048];
    struct ethhdr *eth = (struct ethhdr *)pkt_buf;
    struct iphdr *iph = (struct iphdr *)(pkt_buf + sizeof(struct ethhdr));
    struct tcphdr *tcph = (struct tcphdr *)(pkt_buf + sizeof(struct ethhdr) + sizeof(struct iphdr));
    char *payload_ptr = pkt_buf + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);

    uint64_t total_sent = 0;
    uint64_t total_bytes = 0;
    uint64_t flow_counts[6] = {0};

    time_t start_time = time(NULL);
    time_t last_report = start_time;
    uint64_t last_sent_count = 0;

    struct timespec sleep_time;
    if (target_pps > 0) {
        uint64_t ns_delay = 1000000000ULL / target_pps;
        sleep_time.tv_sec = ns_delay / 1000000000ULL;
        sleep_time.tv_nsec = ns_delay % 1000000000ULL;
    }

    // Main injection loop
    int step = 0;
    while (keep_running) {
        // Check duration limit
        time_t now = time(NULL);
        if (duration_min > 0 && (now - start_time) >= (duration_min * 60)) {
            printf("\nDuration limit (%d min) reached. Stopping...\n", duration_min);
            break;
        }

        // Select random index for nodes
        int u_idx = rand() % num_users;
        int w_idx = rand() % num_webs;
        int a_idx = rand() % num_was;
        int d_idx = rand() % num_dbs;

        uint32_t ip_u = get_ip(ip_users, u_idx);
        uint32_t ip_w = get_ip(ip_webs, w_idx);
        uint32_t ip_a = get_ip(ip_was, a_idx);
        uint32_t ip_d = get_ip(ip_dbs, d_idx);

        uint8_t mac_u[6], mac_w[6], mac_a[6], mac_d[6];
        get_mac(mac_u, 1, u_idx);
        get_mac(mac_w, 2, w_idx);
        get_mac(mac_a, 3, a_idx);
        get_mac(mac_d, 4, d_idx);

        uint16_t port_u = 49152 + (rand() % 16383);
        uint16_t port_w_to_was = 49152 + (rand() % 16383);
        uint16_t port_was_to_db = 49152 + (rand() % 16383);

        const char *payload = NULL;
        int payload_len = 0;
        int current_flow = step % 6;

        switch (current_flow) {
            case 0: // User -> Web HTTP Request
                memcpy(eth->h_source, mac_u, 6);
                memcpy(eth->h_dest, mac_w, 6);
                iph->saddr = ip_u;
                iph->daddr = ip_w;
                tcph->source = htons(port_u);
                tcph->dest = htons(PORT_HTTP);
                payload = PAYLOAD_USER_HTTP_REQ;
                break;
            case 1: // Web -> User HTTP Response
                memcpy(eth->h_source, mac_w, 6);
                memcpy(eth->h_dest, mac_u, 6);
                iph->saddr = ip_w;
                iph->daddr = ip_u;
                tcph->source = htons(PORT_HTTP);
                tcph->dest = htons(port_u);
                payload = PAYLOAD_WEB_HTTP_RES;
                break;
            case 2: // Web -> WAS API Request
                memcpy(eth->h_source, mac_w, 6);
                memcpy(eth->h_dest, mac_a, 6);
                iph->saddr = ip_w;
                iph->daddr = ip_a;
                tcph->source = htons(port_w_to_was);
                tcph->dest = htons(PORT_WAS);
                payload = PAYLOAD_WEB_WAS_REQ;
                break;
            case 3: // WAS -> Web API Response
                memcpy(eth->h_source, mac_a, 6);
                memcpy(eth->h_dest, mac_w, 6);
                iph->saddr = ip_a;
                iph->daddr = ip_w;
                tcph->source = htons(PORT_WAS);
                tcph->dest = htons(port_w_to_was);
                payload = PAYLOAD_WAS_WEB_RES;
                break;
            case 4: // WAS -> DB SQL Query
                memcpy(eth->h_source, mac_a, 6);
                memcpy(eth->h_dest, mac_d, 6);
                iph->saddr = ip_a;
                iph->daddr = ip_d;
                tcph->source = htons(port_was_to_db);
                tcph->dest = htons(PORT_DB);
                payload = PAYLOAD_WAS_DB_REQ;
                break;
            case 5: // DB -> WAS SQL Response
                memcpy(eth->h_source, mac_d, 6);
                memcpy(eth->h_dest, mac_a, 6);
                iph->saddr = ip_d;
                iph->daddr = ip_a;
                tcph->source = htons(PORT_DB);
                tcph->dest = htons(port_was_to_db);
                payload = PAYLOAD_DB_WAS_RES;
                break;
        }

        payload_len = strlen(payload);
        memcpy(payload_ptr, payload, payload_len);

        eth->h_proto = htons(ETH_P_IP);

        iph->version = 4;
        iph->ihl = 5;
        iph->tos = 0;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len);
        iph->id = htons(rand() % 65535);
        iph->frag_off = 0;
        iph->ttl = 64;
        iph->protocol = IPPROTO_TCP;
        iph->check = 0;
        iph->check = calculate_checksum((unsigned short *)iph, sizeof(struct iphdr));

        tcph->seq = htonl(rand() % 1000000);
        tcph->ack_seq = htonl(rand() % 1000000);
        tcph->doff = 5;
        tcph->fin = 0;
        tcph->syn = 0;
        tcph->rst = 0;
        tcph->psh = 1;
        tcph->ack = 1;
        tcph->urg = 0;
        tcph->window = htons(14600);
        tcph->check = 0;
        tcph->urg_ptr = 0;

        tcph->check = compute_tcp_checksum(iph, tcph, payload, payload_len);

        int packet_size = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len;
        
        if (sendto(sock, pkt_buf, packet_size, 0, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
            perror("Packet injection failed");
            close(sock);
            return 1;
        }

        total_sent++;
        total_bytes += packet_size;
        flow_counts[current_flow]++;
        step++;

        if (target_pps > 0) {
            nanosleep(&sleep_time, NULL);
        }

        // Periodic report
        now = time(NULL);
        if (now - last_report >= 1) {
            uint64_t diff = total_sent - last_sent_count;
            double pps = (double)diff / (now - last_report);
            printf("[Stats] Total sent: %lu packets | Current Speed: %.2f PPS\n", total_sent, pps);
            last_report = now;
            last_sent_count = total_sent;
        }
    }

    // End statistics calculation
    time_t end_time = time(NULL);
    uint64_t duration_sec = end_time - start_time;
    if (duration_sec == 0) duration_sec = 1; // Prevent division by zero

    double avg_pps = (double)total_sent / duration_sec;
    double avg_kbps = (double)(total_bytes * 8) / (duration_sec * 1000.0);

    // Format start/end times
    char start_time_str[26], end_time_str[26];
    struct tm *tm_info;
    
    tm_info = localtime(&start_time);
    strftime(start_time_str, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    
    tm_info = localtime(&end_time);
    strftime(end_time_str, 26, "%Y-%m-%d %H:%M:%S", tm_info);

    // Create log directory based on end_time (YYYYMMDD-HHMMSS)
    char dir_name[64];
    strftime(dir_name, sizeof(dir_name), "%Y%m%d-%H%M%S", tm_info);
    if (mkdir(dir_name, 0777) == 0) {
        printf("Created log directory: '%s'\n", dir_name);
    } else {
        perror("Failed to create log directory (or directory already exists)");
    }

    char summary_log_path[128];
    char ip_log_path[128];
    snprintf(summary_log_path, sizeof(summary_log_path), "%s/pktgen_summary.log", dir_name);
    snprintf(ip_log_path, sizeof(ip_log_path), "%s/ip.log", dir_name);

    // Output stats to console
    printf("\n=== Execution Summary ===\n");
    printf("Command Run:        %s\n", cmd_line);
    printf("Start Time:         %s\n", start_time_str);
    printf("End Time:           %s\n", end_time_str);
    printf("Duration:           %lu seconds\n", duration_sec);
    printf("Total Packets Sent: %lu\n", total_sent);
    printf("Total Bytes Sent:   %lu bytes\n", total_bytes);
    printf("Average Rate:       %.2f PPS\n", avg_pps);
    printf("Average Bandwidth:  %.2f Kbps\n", avg_kbps);
    printf("-------------------------\n");
    printf("Flow Breakdown:\n");
    printf("  Flow 1 (User -> Web HTTP Req): %lu\n", flow_counts[0]);
    printf("  Flow 2 (Web -> User HTTP Res): %lu\n", flow_counts[1]);
    printf("  Flow 3 (Web -> WAS API Req):   %lu\n", flow_counts[2]);
    printf("  Flow 4 (WAS -> Web API Res):   %lu\n", flow_counts[3]);
    printf("  Flow 5 (WAS -> DB SQL Query):  %lu\n", flow_counts[4]);
    printf("  Flow 6 (DB -> WAS SQL Res):    %lu\n", flow_counts[5]);
    printf("=========================\n");

    // Write to log file
    FILE *log_file = fopen(summary_log_path, "w");
    if (log_file != NULL) {
        fprintf(log_file, "=== Packet Generator Execution Summary ===\n");
        fprintf(log_file, "Command Run:        %s\n", cmd_line);
        fprintf(log_file, "Start Time:         %s\n", start_time_str);
        fprintf(log_file, "End Time:           %s\n", end_time_str);
        fprintf(log_file, "Duration:           %lu seconds\n", duration_sec);
        fprintf(log_file, "Total Packets Sent: %lu\n", total_sent);
        fprintf(log_file, "Total Bytes Sent:   %lu bytes\n", total_bytes);
        fprintf(log_file, "Average Rate:       %.2f PPS\n", avg_pps);
        fprintf(log_file, "Average Bandwidth:  %.2f Kbps\n", avg_kbps);
        fprintf(log_file, "-------------------------\n");
        fprintf(log_file, "Flow Breakdown:\n");
        fprintf(log_file, "  Flow 1 (User -> Web HTTP Req): %lu\n", flow_counts[0]);
        fprintf(log_file, "  Flow 2 (Web -> User HTTP Res): %lu\n", flow_counts[1]);
        fprintf(log_file, "  Flow 3 (Web -> WAS API Req):   %lu\n", flow_counts[2]);
        fprintf(log_file, "  Flow 4 (WAS -> Web API Res):   %lu\n", flow_counts[3]);
        fprintf(log_file, "  Flow 5 (WAS -> DB SQL Query):  %lu\n", flow_counts[4]);
        fprintf(log_file, "  Flow 6 (DB -> WAS SQL Res):    %lu\n", flow_counts[5]);
        fprintf(log_file, "=========================\n");
        fclose(log_file);
        printf("Statistics successfully saved to '%s'\n", summary_log_path);
    } else {
        perror("Failed to open log file for writing");
    }

    // Write IP Allocation map to directory
    write_ip_log(ip_log_path, ip_users, num_users, ip_webs, num_webs, ip_was, num_was, ip_dbs, num_dbs);

    close(sock);
    free(if_name);
    return 0;
}
