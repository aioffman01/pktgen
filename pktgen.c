#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
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
#include <pthread.h>

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

// Batch size for sendmmsg
#define BATCH_SIZE 64

// Signal flag to control the loop execution
volatile int keep_running = 1;

// Signal handler for SIGINT (Ctrl+C)
void handle_sigint(int sig) {
    (void)sig;
    keep_running = 0;
}

// Trim spaces from string
char *trim_space(char *str) {
    char *end;
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return str;
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

// INI Config Parser
int parse_config(const char *filename, 
                 char **if_name, int *target_pps, int *duration_min,
                 uint32_t *ip_users, int *num_users,
                 uint32_t *ip_webs, int *num_webs,
                 uint32_t *ip_was, int *num_was,
                 uint32_t *ip_dbs, int *num_dbs,
                 double *min_kb, double *max_kb,
                 int *use_thread) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open config file");
        return -1;
    }

    char line[256];
    char current_section[64] = {0};

    while (fgets(line, sizeof(line), file)) {
        char *trimmed = trim_space(line);
        
        // Skip comments and empty lines
        if (trimmed[0] == ';' || trimmed[0] == '#' || trimmed[0] == '\0') {
            continue;
        }

        // Section header
        if (trimmed[0] == '[' && trimmed[strlen(trimmed) - 1] == ']') {
            strncpy(current_section, trimmed + 1, strlen(trimmed) - 2);
            current_section[strlen(trimmed) - 2] = '\0';
            continue;
        }

        // Key-Value pair
        char *eq = strchr(trimmed, '=');
        if (eq) {
            *eq = '\0';
            char *key = trim_space(trimmed);
            char *val = trim_space(eq + 1);

            if (strcmp(current_section, "system") == 0) {
                if (strcmp(key, "interface") == 0) {
                    if (*if_name == NULL) {
                        *if_name = strdup(val);
                    }
                } else if (strcmp(key, "pps") == 0) {
                    if (*target_pps == -1) {
                        *target_pps = atoi(val);
                    }
                } else if (strcmp(key, "duration") == 0) {
                    if (*duration_min == -1) {
                        *duration_min = atoi(val);
                    }
                }
            } else if (strcmp(current_section, "user") == 0) {
                if (strcmp(key, "ip") == 0) {
                    if (*ip_users == 0) {
                        char ip_str[64];
                        int mask;
                        if (sscanf(val, "%[^/]/%d", ip_str, &mask) >= 1) {
                            *ip_users = inet_addr(ip_str);
                        }
                    }
                } else if (strcmp(key, "count") == 0) {
                    if (*num_users == -1) {
                        *num_users = atoi(val);
                    }
                }
            } else if (strcmp(current_section, "web") == 0) {
                if (strcmp(key, "ip") == 0) {
                    if (*ip_webs == 0) {
                        char ip_str[64];
                        int mask;
                        if (sscanf(val, "%[^/]/%d", ip_str, &mask) >= 1) {
                            *ip_webs = inet_addr(ip_str);
                        }
                    }
                } else if (strcmp(key, "count") == 0) {
                    if (*num_webs == -1) {
                        *num_webs = atoi(val);
                    }
                }
            } else if (strcmp(current_section, "was") == 0) {
                if (strcmp(key, "ip") == 0) {
                    if (*ip_was == 0) {
                        char ip_str[64];
                        int mask;
                        if (sscanf(val, "%[^/]/%d", ip_str, &mask) >= 1) {
                            *ip_was = inet_addr(ip_str);
                        }
                    }
                } else if (strcmp(key, "count") == 0) {
                    if (*num_was == -1) {
                        *num_was = atoi(val);
                    }
                }
            } else if (strcmp(current_section, "db") == 0) {
                if (strcmp(key, "ip") == 0) {
                    if (*ip_dbs == 0) {
                        char ip_str[64];
                        int mask;
                        if (sscanf(val, "%[^/]/%d", ip_str, &mask) >= 1) {
                            *ip_dbs = inet_addr(ip_str);
                        }
                    }
                } else if (strcmp(key, "count") == 0) {
                    if (*num_dbs == -1) {
                        *num_dbs = atoi(val);
                    }
                }
            } else if (strcmp(current_section, "data") == 0) {
                if (strcmp(key, "min_kb") == 0) {
                    if (*min_kb < 0.0) {
                        *min_kb = atof(val);
                    }
                } else if (strcmp(key, "max_kb") == 0) {
                    if (*max_kb < 0.0) {
                        *max_kb = atof(val);
                    }
                } else if (strcmp(key, "use_thread") == 0) {
                    if (*use_thread == -1) {
                        if (strcmp(val, "true") == 0 || strcmp(val, "1") == 0) {
                            *use_thread = 1;
                        } else {
                            *use_thread = 0;
                        }
                    }
                }
            }
        }
    }

    fclose(file);
    return 0;
}

// Multi-thread arguments structure
struct thread_arg {
    int thread_id; // 1, 2, or 3
    char *if_name;
    int num_users;
    int num_webs;
    int num_was;
    int num_dbs;
    uint32_t ip_users;
    uint32_t ip_webs;
    uint32_t ip_was;
    uint32_t ip_dbs;
    int target_pps;
    int duration_min;
    double min_kb;
    double max_kb;
    time_t start_time;
};

// Multi-thread statistics result structure
struct thread_result {
    uint64_t total_sent;
    uint64_t total_bytes;
    uint64_t flow_counts[6];
};

// Thread runner function
void *packet_generator_thread(void *arg) {
    struct thread_arg *targ = (struct thread_arg *)arg;
    
    // Set up raw socket for this thread
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("Thread socket creation failed");
        pthread_exit(NULL);
    }

    // Find interface index
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, targ->if_name, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("Thread failed to get interface index");
        close(sock);
        pthread_exit(NULL);
    }
    int if_index = ifr.ifr_ifindex;

    // Set up socket address
    struct sockaddr_ll saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sll_family = AF_PACKET;
    saddr.sll_ifindex = if_index;
    saddr.sll_halen = ETH_ALEN;

    // Allocate result structure
    struct thread_result *res = calloc(1, sizeof(struct thread_result));
    if (!res) {
        close(sock);
        pthread_exit(NULL);
    }

    // Batching structures
    struct mmsghdr msgs[BATCH_SIZE];
    struct iovec iovecs[BATCH_SIZE];
    char packet_buffers[BATCH_SIZE][2048];
    int batch_idx = 0;

    memset(msgs, 0, sizeof(msgs));
    for (int i = 0; i < BATCH_SIZE; i++) {
        iovecs[i].iov_base = packet_buffers[i];
        msgs[i].msg_hdr.msg_name = &saddr;
        msgs[i].msg_hdr.msg_namelen = sizeof(saddr);
        msgs[i].msg_hdr.msg_iov = &iovecs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }

    struct timespec sleep_time;
    int thread_pps = targ->target_pps;
    if (thread_pps > 0) {
        uint64_t ns_delay = 1000000000ULL / thread_pps;
        sleep_time.tv_sec = ns_delay / 1000000000ULL;
        sleep_time.tv_nsec = ns_delay % 1000000000ULL;
    }

    srand(time(NULL) + targ->thread_id);

    int step = 0;
    while (keep_running) {
        time_t now = time(NULL);
        if (targ->duration_min > 0 && (now - targ->start_time) >= (targ->duration_min * 60)) {
            break;
        }

        // Assign flow logic depending on thread ID
        int current_flow = 0;
        if (targ->thread_id == 1) {
            current_flow = step % 2;        // Flow 0, 1 (User <-> Web)
        } else if (targ->thread_id == 2) {
            current_flow = 2 + (step % 2);  // Flow 2, 3 (Web <-> WAS)
        } else if (targ->thread_id == 3) {
            current_flow = 4 + (step % 2);  // Flow 4, 5 (WAS <-> DB)
        }

        // Random index for nodes
        int u_idx = rand() % targ->num_users;
        int w_idx = rand() % targ->num_webs;
        int a_idx = rand() % targ->num_was;
        int d_idx = rand() % targ->num_dbs;

        uint32_t ip_u = get_ip(targ->ip_users, u_idx);
        uint32_t ip_w = get_ip(targ->ip_webs, w_idx);
        uint32_t ip_a = get_ip(targ->ip_was, a_idx);
        uint32_t ip_d = get_ip(targ->ip_dbs, d_idx);

        uint8_t mac_u[6], mac_w[6], mac_a[6], mac_d[6];
        get_mac(mac_u, 1, u_idx);
        get_mac(mac_w, 2, w_idx);
        get_mac(mac_a, 3, a_idx);
        get_mac(mac_d, 4, d_idx);

        uint16_t port_u = 49152 + (rand() % 16383);
        uint16_t port_w_to_was = 49152 + (rand() % 16383);
        uint16_t port_was_to_db = 49152 + (rand() % 16383);

        const char *payload = NULL;
        switch (current_flow) {
            case 0: payload = PAYLOAD_USER_HTTP_REQ; break;
            case 1: payload = PAYLOAD_WEB_HTTP_RES; break;
            case 2: payload = PAYLOAD_WEB_WAS_REQ; break;
            case 3: payload = PAYLOAD_WAS_WEB_RES; break;
            case 4: payload = PAYLOAD_WAS_DB_REQ; break;
            case 5: payload = PAYLOAD_DB_WAS_RES; break;
        }

        int base_payload_len = strlen(payload);

        // Custom data sizing & padding logic
        int target_payload_len = base_payload_len;
        if (targ->min_kb > 0.0 && targ->max_kb >= targ->min_kb) {
            int min_bytes = (int)(targ->min_kb * 1024.0);
            int max_bytes = (int)(targ->max_kb * 1024.0);
            if (max_bytes > min_bytes) {
                target_payload_len = min_bytes + (rand() % (max_bytes - min_bytes + 1));
            } else {
                target_payload_len = min_bytes;
            }
        }

        int max_allowed_bytes = 10000 * 1024;
        if (target_payload_len > max_allowed_bytes) {
            target_payload_len = max_allowed_bytes;
        }

        int remaining_bytes = target_payload_len;
        int max_chunk = 1400; // MTU-safe TCP payload size
        uint32_t seq_offset = rand() % 1000000;

        while (remaining_bytes > 0) {
            int chunk_len = (remaining_bytes > max_chunk) ? max_chunk : remaining_bytes;

            char *curr_pkt = packet_buffers[batch_idx];
            struct ethhdr *curr_eth = (struct ethhdr *)curr_pkt;
            struct iphdr *curr_iph = (struct iphdr *)(curr_pkt + sizeof(struct ethhdr));
            struct tcphdr *curr_tcph = (struct tcphdr *)(curr_pkt + sizeof(struct ethhdr) + sizeof(struct iphdr));
            char *curr_payload_ptr = curr_pkt + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);

            switch (current_flow) {
                case 0:
                    memcpy(curr_eth->h_source, mac_u, 6);
                    memcpy(curr_eth->h_dest, mac_w, 6);
                    curr_iph->saddr = ip_u;
                    curr_iph->daddr = ip_w;
                    curr_tcph->source = htons(port_u);
                    curr_tcph->dest = htons(PORT_HTTP);
                    break;
                case 1:
                    memcpy(curr_eth->h_source, mac_w, 6);
                    memcpy(curr_eth->h_dest, mac_u, 6);
                    curr_iph->saddr = ip_w;
                    curr_iph->daddr = ip_u;
                    curr_tcph->source = htons(PORT_HTTP);
                    curr_tcph->dest = htons(port_u);
                    break;
                case 2:
                    memcpy(curr_eth->h_source, mac_w, 6);
                    memcpy(curr_eth->h_dest, mac_a, 6);
                    curr_iph->saddr = ip_w;
                    curr_iph->daddr = ip_a;
                    curr_tcph->source = htons(port_w_to_was);
                    curr_tcph->dest = htons(PORT_WAS);
                    break;
                case 3:
                    memcpy(curr_eth->h_source, mac_a, 6);
                    memcpy(curr_eth->h_dest, mac_w, 6);
                    curr_iph->saddr = ip_a;
                    curr_iph->daddr = ip_w;
                    curr_tcph->source = htons(PORT_WAS);
                    curr_tcph->dest = htons(port_w_to_was);
                    break;
                case 4:
                    memcpy(curr_eth->h_source, mac_a, 6);
                    memcpy(curr_eth->h_dest, mac_d, 6);
                    curr_iph->saddr = ip_a;
                    curr_iph->daddr = ip_d;
                    curr_tcph->source = htons(port_was_to_db);
                    curr_tcph->dest = htons(PORT_DB);
                    break;
                case 5:
                    memcpy(curr_eth->h_source, mac_d, 6);
                    memcpy(curr_eth->h_dest, mac_a, 6);
                    curr_iph->saddr = ip_d;
                    curr_iph->daddr = ip_a;
                    curr_tcph->source = htons(PORT_DB);
                    curr_tcph->dest = htons(port_was_to_db);
                    break;
            }

            // Fill payload
            if (remaining_bytes == target_payload_len) {
                int copy_len = (chunk_len > base_payload_len) ? base_payload_len : chunk_len;
                memcpy(curr_payload_ptr, payload, copy_len);
                if (chunk_len > copy_len) {
                    memset(curr_payload_ptr + copy_len, 'A', chunk_len - copy_len);
                }
            } else {
                memset(curr_payload_ptr, 'A', chunk_len);
            }

            curr_eth->h_proto = htons(ETH_P_IP);

            curr_iph->version = 4;
            curr_iph->ihl = 5;
            curr_iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + chunk_len);
            curr_iph->id = htons(rand() % 65535);
            curr_iph->frag_off = 0;
            curr_iph->ttl = 64;
            curr_iph->protocol = IPPROTO_TCP;
            curr_iph->check = 0;
            curr_iph->check = calculate_checksum((unsigned short *)curr_iph, sizeof(struct iphdr));

            curr_tcph->seq = htonl(seq_offset);
            curr_tcph->ack_seq = htonl(rand() % 1000000);
            curr_tcph->doff = 5;
            curr_tcph->fin = 0;
            curr_tcph->syn = 0;
            curr_tcph->rst = 0;
            curr_tcph->psh = 1;
            curr_tcph->ack = 1;
            curr_tcph->urg = 0;
            curr_tcph->window = htons(14600);
            curr_tcph->check = 0;
            curr_tcph->urg_ptr = 0;

            curr_tcph->check = compute_tcp_checksum(curr_iph, curr_tcph, curr_payload_ptr, chunk_len);

            int packet_size = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + chunk_len;
            iovecs[batch_idx].iov_len = packet_size;

            batch_idx++;

            if (batch_idx == BATCH_SIZE) {
                int sent = sendmmsg(sock, msgs, batch_idx, 0);
                if (sent > 0) {
                    for (int i = 0; i < sent; i++) {
                        res->total_bytes += iovecs[i].iov_len;
                    }
                    res->total_sent += sent;
                }
                batch_idx = 0;
            }

            seq_offset += chunk_len;
            remaining_bytes -= chunk_len;
        }

        res->flow_counts[current_flow]++;
        step++;

        if (thread_pps > 0) {
            nanosleep(&sleep_time, NULL);
        }
    }

    // Flush batch
    if (batch_idx > 0) {
        int sent = sendmmsg(sock, msgs, batch_idx, 0);
        if (sent > 0) {
            for (int i = 0; i < sent; i++) {
                res->total_bytes += iovecs[i].iov_len;
            }
            res->total_sent += sent;
        }
    }

    close(sock);
    pthread_exit(res);
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
    char *config_file = NULL;

    // Initialize all options to sentinel/invalid values to allow CLI to override config settings
    int num_users = -1;
    int num_webs = -1;
    int num_was = -1;
    int num_dbs = -1;

    uint32_t ip_users = 0;
    uint32_t ip_webs = 0;
    uint32_t ip_was = 0;
    uint32_t ip_dbs = 0;

    int target_pps = -1;
    int duration_min = -1;
    double min_kb = -1.0;
    double max_kb = -1.0;
    int use_thread = -1;

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
        {"config", required_argument, 0, 'c'},
        {"min-size", required_argument, 0, 1004},
        {"max-size", required_argument, 0, 1005},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:u:w:a:d:r:t:c:h", long_options, NULL)) != -1) {
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
            case 'c': config_file = strdup(optarg); break;
            case 1004: min_kb = atof(optarg); break;
            case 1005: max_kb = atof(optarg); break;
            case 'h':
            default:
                printf("Usage: %s [options]\n", argv[0]);
                printf("Options:\n");
                printf("  -c, --config     Path to config file (default: pktgen.cfg in current dir)\n");
                printf("  -i, --interface  Network interface to inject packets (overrides config)\n");
                printf("  -u, --users      Number of simulated users (overrides config)\n");
                printf("  -w, --webs       Number of simulated Web servers (overrides config)\n");
                printf("  -a, --was        Number of simulated WAS servers (overrides config)\n");
                printf("  -d, --dbs        Number of simulated DB servers (overrides config)\n");
                printf("  -r, --pps        Target Packets Per Second (overrides config)\n");
                printf("  -t, --duration   Execution duration in minutes (overrides config)\n");
                return 1;
        }
    }

    // Resolve configuration file. If not specified, look for default "pktgen.cfg"
    if (!config_file) {
        if (access("pktgen.cfg", F_OK) == 0) {
            config_file = strdup("pktgen.cfg");
        }
    }

    // Load settings from config file if found
    if (config_file) {
        printf("Loading configuration file: %s\n", config_file);
        if (parse_config(config_file, &if_name, &target_pps, &duration_min,
                         &ip_users, &num_users, &ip_webs, &num_webs, &ip_was, &num_was, &ip_dbs, &num_dbs,
                         &min_kb, &max_kb, &use_thread) == 0) {
            printf("Configuration successfully loaded.\n");
        } else {
            fprintf(stderr, "Warning: Failed to load config from file.\n");
        }
    }

    // Fall back to default values for settings that were NOT set by either CLI or CFG
    if (num_users == -1) num_users = DEFAULT_USERS;
    if (num_webs == -1) num_webs = DEFAULT_WEBS;
    if (num_was == -1) num_was = DEFAULT_WAS;
    if (num_dbs == -1) num_dbs = DEFAULT_DBS;

    if (ip_users == 0) ip_users = inet_addr(DEFAULT_USER_IP);
    if (ip_webs == 0) ip_webs = inet_addr(DEFAULT_WEB_IP);
    if (ip_was == 0) ip_was = inet_addr(DEFAULT_WAS_IP);
    if (ip_dbs == 0) ip_dbs = inet_addr(DEFAULT_DB_IP);

    if (target_pps == -1) target_pps = 0; // Default: maximum speed
    if (duration_min == -1) duration_min = 0; // Default: infinite
    if (min_kb < 0.0) min_kb = 0.0;
    if (max_kb < 0.0) max_kb = 0.0;
    if (use_thread == -1) use_thread = 0; // Default: single thread

    // Check mandatory parameters
    if (!if_name) {
        fprintf(stderr, "Error: Network interface is required. Specify in pktgen.cfg under [system] or via -i <interface>.\n");
        if (config_file) free(config_file);
        return 1;
    }

    // Safety checks on packet payload size limits (Cap at 10000.0 KB)
    if (min_kb > 10000.0) {
        printf("Warning: min-size (%.2f KB) exceeds 10000 KB limit. Capping to 10000 KB.\n", min_kb);
        min_kb = 10000.0;
    }
    if (max_kb > 10000.0) {
        printf("Warning: max-size (%.2f KB) exceeds 10000 KB limit. Capping to 10000 KB.\n", max_kb);
        max_kb = 10000.0;
    }

    printf("Starting Packet Generator on interface: %s\n", if_name);
    printf("Simulation counts: Users=%d, Web=%d, WAS=%d, DB=%d\n", num_users, num_webs, num_was, num_dbs);
    if (min_kb > 0.0 && max_kb >= min_kb) {
        printf("Data (Payload) Size Limits: %.2f KB ~ %.2f KB (Randomized & Padded)\n", min_kb, max_kb);
    } else {
        printf("Data (Payload) Size Limits: Template size (No Padding)\n");
    }
    
    printf("Thread Mode: %s\n", use_thread ? "Enabled (3 Threads Parallel)" : "Disabled (Single Thread Sequential)");

    if (duration_min > 0) {
        printf("Execution time limit: %d minutes\n", duration_min);
    } else {
        printf("Execution time limit: infinite (Press Ctrl+C to stop)\n");
    }

    uint64_t total_sent = 0;
    uint64_t total_bytes = 0;
    uint64_t flow_counts[6] = {0};
    time_t start_time = time(NULL);

    if (use_thread) {
        // --- MULTI-THREAD RUNNER ---
        pthread_t threads[3];
        struct thread_arg args[3];

        for (int i = 0; i < 3; i++) {
            args[i].thread_id = i + 1;
            args[i].if_name = if_name;
            args[i].num_users = num_users;
            args[i].num_webs = num_webs;
            args[i].num_was = num_was;
            args[i].num_dbs = num_dbs;
            args[i].ip_users = ip_users;
            args[i].ip_webs = ip_webs;
            args[i].ip_was = ip_was;
            args[i].ip_dbs = ip_dbs;
            
            if (target_pps > 0) {
                args[i].target_pps = target_pps / 3;
                if (args[i].target_pps == 0) args[i].target_pps = 1;
            } else {
                args[i].target_pps = 0;
            }
            
            args[i].duration_min = duration_min;
            args[i].min_kb = min_kb;
            args[i].max_kb = max_kb;
            args[i].start_time = start_time;

            if (pthread_create(&threads[i], NULL, packet_generator_thread, &args[i]) != 0) {
                perror("Failed to create thread");
                if (config_file) free(config_file);
                if (if_name) free(if_name);
                return 1;
            }
        }

        // Wait for threads and collect results
        for (int i = 0; i < 3; i++) {
            struct thread_result *res = NULL;
            pthread_join(threads[i], (void **)&res);
            if (res) {
                total_sent += res->total_sent;
                total_bytes += res->total_bytes;
                for (int f = 0; f < 6; f++) {
                    flow_counts[f] += res->flow_counts[f];
                }
                free(res);
            }
        }
    } else {
        // --- SINGLE-THREAD RUNNER ---
        int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (sock < 0) {
            perror("Socket creation failed");
            if (config_file) free(config_file);
            if (if_name) free(if_name);
            return 1;
        }

        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);
        if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
            perror("Failed to get interface index");
            close(sock);
            if (config_file) free(config_file);
            if (if_name) free(if_name);
            return 1;
        }
        int if_index = ifr.ifr_ifindex;

        struct sockaddr_ll saddr;
        memset(&saddr, 0, sizeof(saddr));
        saddr.sll_family = AF_PACKET;
        saddr.sll_ifindex = if_index;
        saddr.sll_halen = ETH_ALEN;

        struct mmsghdr msgs[BATCH_SIZE];
        struct iovec iovecs[BATCH_SIZE];
        char packet_buffers[BATCH_SIZE][2048];
        int batch_idx = 0;

        memset(msgs, 0, sizeof(msgs));
        for (int i = 0; i < BATCH_SIZE; i++) {
            iovecs[i].iov_base = packet_buffers[i];
            msgs[i].msg_hdr.msg_name = &saddr;
            msgs[i].msg_hdr.msg_namelen = sizeof(saddr);
            msgs[i].msg_hdr.msg_iov = &iovecs[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
        }

        struct timespec sleep_time;
        if (target_pps > 0) {
            uint64_t ns_delay = 1000000000ULL / target_pps;
            sleep_time.tv_sec = ns_delay / 1000000000ULL;
            sleep_time.tv_nsec = ns_delay % 1000000000ULL;
        }

        srand(time(NULL));
        int step = 0;
        time_t last_report = start_time;
        uint64_t last_sent_count = 0;

        while (keep_running) {
            time_t now = time(NULL);
            if (duration_min > 0 && (now - start_time) >= (duration_min * 60)) {
                printf("\nDuration limit (%d min) reached. Stopping...\n", duration_min);
                break;
            }

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
            int base_payload_len = 0;
            int current_flow = step % 6;

            switch (current_flow) {
                case 0: payload = PAYLOAD_USER_HTTP_REQ; break;
                case 1: payload = PAYLOAD_WEB_HTTP_RES; break;
                case 2: payload = PAYLOAD_WEB_WAS_REQ; break;
                case 3: payload = PAYLOAD_WAS_WEB_RES; break;
                case 4: payload = PAYLOAD_WAS_DB_REQ; break;
                case 5: payload = PAYLOAD_DB_WAS_RES; break;
            }

            base_payload_len = strlen(payload);

            int target_payload_len = base_payload_len;
            if (min_kb > 0.0 && max_kb >= min_kb) {
                int min_bytes = (int)(min_kb * 1024.0);
                int max_bytes = (int)(max_kb * 1024.0);
                if (max_bytes > min_bytes) {
                    target_payload_len = min_bytes + (rand() % (max_bytes - min_bytes + 1));
                } else {
                    target_payload_len = min_bytes;
                }
            }

            int max_allowed_bytes = 10000 * 1024;
            if (target_payload_len > max_allowed_bytes) {
                target_payload_len = max_allowed_bytes;
            }

            int remaining_bytes = target_payload_len;
            int max_chunk = 1400;
            uint32_t seq_offset = rand() % 1000000;

            while (remaining_bytes > 0) {
                int chunk_len = (remaining_bytes > max_chunk) ? max_chunk : remaining_bytes;

                char *curr_pkt = packet_buffers[batch_idx];
                struct ethhdr *curr_eth = (struct ethhdr *)curr_pkt;
                struct iphdr *curr_iph = (struct iphdr *)(curr_pkt + sizeof(struct ethhdr));
                struct tcphdr *curr_tcph = (struct tcphdr *)(curr_pkt + sizeof(struct ethhdr) + sizeof(struct iphdr));
                char *curr_payload_ptr = curr_pkt + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);

                switch (current_flow) {
                    case 0:
                        memcpy(curr_eth->h_source, mac_u, 6);
                        memcpy(curr_eth->h_dest, mac_w, 6);
                        curr_iph->saddr = ip_u;
                        curr_iph->daddr = ip_w;
                        curr_tcph->source = htons(port_u);
                        curr_tcph->dest = htons(PORT_HTTP);
                        break;
                    case 1:
                        memcpy(curr_eth->h_source, mac_w, 6);
                        memcpy(curr_eth->h_dest, mac_u, 6);
                        curr_iph->saddr = ip_w;
                        curr_iph->daddr = ip_u;
                        curr_tcph->source = htons(PORT_HTTP);
                        curr_tcph->dest = htons(port_u);
                        break;
                    case 2:
                        memcpy(curr_eth->h_source, mac_w, 6);
                        memcpy(curr_eth->h_dest, mac_a, 6);
                        curr_iph->saddr = ip_w;
                        curr_iph->daddr = ip_a;
                        curr_tcph->source = htons(port_w_to_was);
                        curr_tcph->dest = htons(PORT_WAS);
                        break;
                    case 3:
                        memcpy(curr_eth->h_source, mac_a, 6);
                        memcpy(curr_eth->h_dest, mac_w, 6);
                        curr_iph->saddr = ip_a;
                        curr_iph->daddr = ip_w;
                        curr_tcph->source = htons(PORT_WAS);
                        curr_tcph->dest = htons(port_w_to_was);
                        break;
                    case 4:
                        memcpy(curr_eth->h_source, mac_a, 6);
                        memcpy(curr_eth->h_dest, mac_d, 6);
                        curr_iph->saddr = ip_a;
                        curr_iph->daddr = ip_d;
                        curr_tcph->source = htons(port_was_to_db);
                        curr_tcph->dest = htons(PORT_DB);
                        break;
                    case 5:
                        memcpy(curr_eth->h_source, mac_d, 6);
                        memcpy(curr_eth->h_dest, mac_a, 6);
                        curr_iph->saddr = ip_d;
                        curr_iph->daddr = ip_a;
                        curr_tcph->source = htons(PORT_DB);
                        curr_tcph->dest = htons(port_was_to_db);
                        break;
                }

                if (remaining_bytes == target_payload_len) {
                    int copy_len = (chunk_len > base_payload_len) ? base_payload_len : chunk_len;
                    memcpy(curr_payload_ptr, payload, copy_len);
                    if (chunk_len > copy_len) {
                        memset(curr_payload_ptr + copy_len, 'A', chunk_len - copy_len);
                    }
                } else {
                    memset(curr_payload_ptr, 'A', chunk_len);
                }

                curr_eth->h_proto = htons(ETH_P_IP);

                curr_iph->version = 4;
                curr_iph->ihl = 5;
                curr_iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + chunk_len);
                curr_iph->id = htons(rand() % 65535);
                curr_iph->frag_off = 0;
                curr_iph->ttl = 64;
                curr_iph->protocol = IPPROTO_TCP;
                curr_iph->check = 0;
                curr_iph->check = calculate_checksum((unsigned short *)curr_iph, sizeof(struct iphdr));

                curr_tcph->seq = htonl(seq_offset);
                curr_tcph->ack_seq = htonl(rand() % 1000000);
                curr_tcph->doff = 5;
                curr_tcph->fin = 0;
                curr_tcph->syn = 0;
                curr_tcph->rst = 0;
                curr_tcph->psh = 1;
                curr_tcph->ack = 1;
                curr_tcph->urg = 0;
                curr_tcph->window = htons(14600);
                curr_tcph->check = 0;
                curr_tcph->urg_ptr = 0;

                curr_tcph->check = compute_tcp_checksum(curr_iph, curr_tcph, curr_payload_ptr, chunk_len);

                int packet_size = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + chunk_len;
                iovecs[batch_idx].iov_len = packet_size;

                batch_idx++;

                if (batch_idx == BATCH_SIZE) {
                    int sent = sendmmsg(sock, msgs, batch_idx, 0);
                    if (sent > 0) {
                        for (int i = 0; i < sent; i++) {
                            total_bytes += iovecs[i].iov_len;
                        }
                        total_sent += sent;
                    }
                    batch_idx = 0;
                }

                seq_offset += chunk_len;
                remaining_bytes -= chunk_len;
            }

            flow_counts[current_flow]++;
            step++;

            if (target_pps > 0) {
                nanosleep(&sleep_time, NULL);
            }

            now = time(NULL);
            if (now - last_report >= 1) {
                uint64_t diff = total_sent - last_sent_count;
                double pps = (double)diff / (now - last_report);
                printf("[Stats] Total sent: %lu packets | Current Speed: %.2f PPS\n", total_sent, pps);
                last_report = now;
                last_sent_count = total_sent;
            }
        }

        // Flush batch
        if (batch_idx > 0) {
            int sent = sendmmsg(sock, msgs, batch_idx, 0);
            if (sent > 0) {
                for (int i = 0; i < sent; i++) {
                    total_bytes += iovecs[i].iov_len;
                }
                total_sent += sent;
            }
        }
        close(sock);
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

    if (config_file) free(config_file);
    if (if_name) free(if_name);
    return 0;
}
