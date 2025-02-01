#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h>
#include <stdint.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h> // Kernel definitions for IPPROTO_* and in_addr
#include <bpf/bpf_tracing.h> // For PT_REGS_PARM1 and PT_REGS_PARM2

// Define maps for egress and ingress traffic
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, uint32_t); // PID
    __type(value, uint64_t); // Timestamp
} egress_traffic_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct ip_key); // IP 5-tuple
    __type(value, uint32_t); // PID
} ingress_traffic_map SEC(".maps");

struct ip_key {
    uint32_t saddr;
    uint32_t daddr;
    uint16_t sport;
    uint16_t dport;
    uint8_t protocol;
};

// Manual implementation of htons for eBPF
static inline uint16_t bpf_htons(uint16_t hostshort) {
    return ((hostshort & 0xFF00) >> 8) | ((hostshort & 0x00FF) << 8);
}

SEC("kprobe/__dev_queue_xmit")
int handle_dev_queue_xmit(struct pt_regs *ctx) {
	bpf_printk("Egress kprobe triggered\n");
    char comm[16];
    uint32_t pid;
    uint64_t timestamp;

    // Get the current PID
    pid = bpf_get_current_pid_tgid() >> 32;

    // Get process name
    bpf_get_current_comm(&comm, sizeof(comm));

    // Get the current timestamp in nanoseconds
    timestamp = bpf_ktime_get_ns();

    // Log information for packets from the specific process
    bpf_printk("Egress Process: %s, PID: %u, Timestamp: %llu\n", comm, pid, timestamp);

    // Store egress traffic in the map
    bpf_map_update_elem(&egress_traffic_map, &pid, &timestamp, BPF_ANY);

    return 0;
}

SEC("kprobe/__netif_receive_skb")
int handle_netif_receive_skb(struct pt_regs *ctx) {
	bpf_printk("Ingress kprobe triggered\n");
    struct ip_key key = {};
    struct ethhdr eth;
    struct iphdr ip;
    struct tcphdr tcp;
    uint32_t pid = 0;

    // Get the packet data
    void *data = (void *)(long)PT_REGS_PARM1(ctx);
    void *data_end = (void *)(long)PT_REGS_PARM2(ctx);

    // Ensure the packet is large enough for an Ethernet header
    if (data + sizeof(struct ethhdr) > data_end)
        return 0;

    // Safely read the Ethernet header
    if (bpf_probe_read_kernel(&eth, sizeof(eth), data) < 0)
        return 0;

    // Check if the packet is IPv4
    if (eth.h_proto != bpf_htons(ETH_P_IP))
        return 0;

    // Ensure the packet is large enough for an IP header
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return 0;

    // Safely read the IP header
    if (bpf_probe_read_kernel(&ip, sizeof(ip), data + sizeof(struct ethhdr)) < 0)
        return 0;

    key.saddr = ip.saddr;
    key.daddr = ip.daddr;
    key.protocol = ip.protocol;

    if (ip.protocol == IPPROTO_TCP) {
        // Ensure the packet is large enough for a TCP header
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
            return 0;

        // Safely read the TCP header
        if (bpf_probe_read_kernel(&tcp, sizeof(tcp), data + sizeof(struct ethhdr) + sizeof(struct iphdr)) < 0)
            return 0;

        key.sport = tcp.source;
        key.dport = tcp.dest;
    }

    // Lookup PID in ingress traffic map
    uint32_t *pid_ptr = bpf_map_lookup_elem(&ingress_traffic_map, &key);
    if (pid_ptr) {
        pid = *pid_ptr;
        bpf_printk("Ingress Packet: PID: %u, Src: %u.%u.%u.%u, Dst: %u.%u.%u.%u\n",
                   pid, (key.saddr >> 24) & 0xff, (key.saddr >> 16) & 0xff,
                   (key.saddr >> 8) & 0xff, key.saddr & 0xff,
                   (key.daddr >> 24) & 0xff, (key.daddr >> 16) & 0xff,
                   (key.daddr >> 8) & 0xff, key.daddr & 0xff);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
