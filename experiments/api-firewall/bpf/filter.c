// +build ignore
#include <linux/bpf.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "GPL";

#define MAX_PPS 100
#define WINDOW_NS 1000000000 

struct stats {
    __u64 last_reset;
    __u64 count;
};

// Map to store per-IP packet counts
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);   // IPv4 address
    __type(value, struct stats);
} ip_stats SEC(".maps");

SEC("xdp")
int ddos_detector(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end) return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end) return XDP_PASS;

    __u32 src_ip = ip->saddr;
    __u64 now = bpf_ktime_get_ns();

    struct stats *s = bpf_map_lookup_elem(&ip_stats, &src_ip);
    if (s) {
        if (now - s->last_reset > WINDOW_NS) {
            s->last_reset = now;
            s->count = 1;
        } else {
            s->count++;
        }

        if (s->count > MAX_PPS) {
            return XDP_DROP; 
        }
    } else {
        struct stats new_s = { .last_reset = now, .count = 1 };
        bpf_map_update_elem(&ip_stats, &src_ip, &new_s, BPF_ANY);
    }

    return XDP_PASS;
}
