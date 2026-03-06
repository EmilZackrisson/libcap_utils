#include "caputils/filter.h"
#include "caputils/packet.h"
#include "caputils_int.h"

#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>

#include  "caputils/export.h"

#ifdef HAVE_PCAP
#include <pcap/pcap.h>
#endif



/* ============================================================
 * Ethernet address matcher
 * ============================================================ */
static int matchEth(const struct ether_addr *desired,
                    const struct ether_addr *mask,
                    const uint8_t net[ETH_ALEN])
{
    for (int i = 0; i < ETH_ALEN; i++) {
        uint8_t t = (net[i] & mask->ether_addr_octet[i]);
        if (t != desired->ether_addr_octet[i])
            return 0;
    }
    return 1;
}

/* ============================================================
 * VLAN helper
 * ============================================================ */
static const struct ether_vlan_header *
find_ether_vlan_header(const struct ethhdr *ether, uint16_t *h_proto)
{
    if (*h_proto == 0x8100) {
        const struct ether_vlan_header *vlan =
            (const struct ether_vlan_header *)ether;
        *h_proto = ntohs(vlan->h_proto);
        return vlan;
    }
    return NULL;
}

/* ============================================================
 * Transport layer header helpers
 * ============================================================ */
static const void *
find_ipproto_header(const void *pkt,
                    const struct ethhdr *ether,
                    const struct ip *ip)
{
    size_t vlan_offset = (ntohs(ether->h_proto) == 0x8100) ? 4 : 0;
    return (const uint8_t *)pkt + sizeof(struct ethhdr) + vlan_offset + (4 * ip->ip_hl);
}

const struct tcphdr *
find_tcp_header(const void *pkt,
                const struct ethhdr *ether,
                const struct ip *ip,
                uint16_t *src, uint16_t *dst)
{
    if (!(ip && ip->ip_p == IPPROTO_TCP))
        return NULL;

    const struct tcphdr *tcp =
        (const struct tcphdr *)find_ipproto_header(pkt, ether, ip);

    if (src) *src = ntohs(tcp->source);
    if (dst) *dst = ntohs(tcp->dest);

    return tcp;
}

const struct udphdr *
find_udp_header(const void *pkt,
                const struct ethhdr *ether,
                const struct ip *ip,
                uint16_t *src, uint16_t *dst)
{
    if (!(ip && ip->ip_p == IPPROTO_UDP))
        return NULL;

    const struct udphdr *udp =
        (const struct udphdr *)find_ipproto_header(pkt, ether, ip);

    if (src) *src = ntohs(udp->source);
    if (dst) *dst = ntohs(udp->dest);

    return udp;
}

/* ============================================================
 * Individual match functions (1:1 from original)
 * ============================================================ */

int filter_iface(const struct filter *filter, const char *iface)
{
    return (filter->index & FILTER_CI) && (strstr(iface, filter->iface) != NULL);
}

int filter_vlan_tci(const struct filter *filter,
                    const struct ether_vlan_header *vlan)
{
    return (filter->index & FILTER_VLAN) &&
           vlan &&
           ((ntohs(vlan->vlan_tci) & filter->vlan_tci_mask) == filter->vlan_tci);
}

int filter_h_proto(const struct filter *filter, uint16_t proto)
{
    return (filter->index & FILTER_ETH_TYPE) &&
           ((proto & filter->eth_type_mask) == filter->eth_type);
}

int filter_eth_src(const struct filter *filter, const struct ethhdr *ether)
{
    return (filter->index & FILTER_ETH_SRC) &&
           matchEth(&filter->eth_src, &filter->eth_src_mask, ether->h_source);
}

int filter_eth_dst(const struct filter *filter, const struct ethhdr *ether)
{
    return (filter->index & FILTER_ETH_DST) &&
           matchEth(&filter->eth_dst, &filter->eth_dst_mask, ether->h_dest);
}

int filter_ip_proto(const struct filter *filter, const struct ip *ip)
{
    return (filter->index & FILTER_IP_PROTO) &&
           ip && (ip->ip_p == filter->ip_proto);
}

int filter_ip_src(const struct filter *filter, const struct ip *ip)
{
    return (filter->index & FILTER_IP_SRC) &&
           ip &&
           ((ip->ip_src.s_addr & filter->ip_src_mask.s_addr) == filter->ip_src.s_addr);
}

int filter_ip_dst(const struct filter *filter, const struct ip *ip)
{
    return (filter->index & FILTER_IP_DST) &&
           ip &&
           ((ip->ip_dst.s_addr & filter->ip_dst_mask.s_addr) == filter->ip_dst.s_addr);
}

int filter_src_port(const struct filter *filter, uint16_t port)
{
    return (filter->index & FILTER_SRC_PORT) &&
           (filter->src_port == (port & filter->src_port_mask));
}

int filter_dst_port(const struct filter *filter, uint16_t port)
{
    return (filter->index & FILTER_DST_PORT) &&
           (filter->dst_port == (port & filter->dst_port_mask));
}

int filter_port(const struct filter *filter, uint16_t src, uint16_t dst)
{
    return (filter->index & FILTER_PORT) &&
           ((filter->port == (src & filter->port_mask)) ||
            (filter->port == (dst & filter->port_mask)));
}

int filter_mampid(const struct filter *filter, const char mampid[8])
{
    return (filter->index & FILTER_MAMPID) &&
           (strncmp(filter->mampid, mampid, 8) == 0);
}

int filter_start_time(const struct filter *filter, const timepico *t)
{
    return (filter->index & FILTER_START_TIME) &&
           (timecmp(&filter->starttime, t) <= 0);
}

int filter_end_time(const struct filter *filter, const timepico *t)
{
    return (filter->index & FILTER_END_TIME) &&
           (timecmp(&filter->endtime, t) > 0);
}

int filter_frame_dt(const struct filter *filter, const timepico t)
{
    if (!(filter->index & FILTER_FRAME_MAX_DT))
        return 0;

    if (timecmp(&t, &filter->frame_last_ts) < 0)
        return 1;

    timepico dt = timepico_sub(t, filter->frame_last_ts);
    return timecmp(&dt, &filter->frame_max_dt) <= 0;
}

int filter_frame_num(const struct filter *filter)
{
    if (!filter->frame_num) return 0;

    if (filter->frame_counter < filter->frame_num->lower) return 0;

    if (filter->frame_num->upper > 0 &&
        filter->frame_counter > filter->frame_num->upper) return 0;

    return 1;
}

/* ============================================================
 * Core match engine
 * ============================================================ */
static int
filter_core(const struct filter *filter,
            const void *pkt,
            struct cap_header *head)
{
    const struct ethhdr *ether = (const struct ethhdr *)pkt;
    uint16_t proto = ntohs(ether->h_proto);

    const struct ether_vlan_header *vlan =
        find_ether_vlan_header(ether, &proto);

    const struct ip *ip = find_ipv4_header(ether, NULL);

    uint16_t src = 0, dst = 0;
    find_tcp_header(pkt, ether, ip, &src, &dst);
    find_udp_header(pkt, ether, ip, &src, &dst);

    unsigned int match = 0;

    match |= filter_dst_port(filter, dst) << OFFSET_DST_PORT;
    match |= filter_src_port(filter, src) << OFFSET_SRC_PORT;
    match |= filter_ip_dst(filter, ip) << OFFSET_IP_DST;
    match |= filter_ip_src(filter, ip) << OFFSET_IP_SRC;
    match |= filter_ip_proto(filter, ip) << OFFSET_IP_PROTO;
    match |= filter_eth_dst(filter, ether) << OFFSET_ETH_DST;
    match |= filter_eth_src(filter, ether) << OFFSET_ETH_SRC;
    match |= filter_h_proto(filter, proto) << OFFSET_ETH_TYPE;
    match |= filter_vlan_tci(filter, vlan) << OFFSET_VLAN;
    match |= filter_iface(filter, head->nic) << OFFSET_IFACE;

    match |= filter_mampid(filter, head->mampid) << OFFSET_MAMPID;
    match |= filter_end_time(filter, &head->ts) << OFFSET_END_TIME;
    match |= filter_start_time(filter, &head->ts) << OFFSET_START_TIME;
    match |= filter_port(filter, src, dst) << OFFSET_PORT;
    match |= filter_frame_dt(filter, head->ts) << OFFSET_FRAME_MAX_DT;
    match |= filter_frame_num(filter) << OFFSET_FRAME_NUM;

    switch (filter->mode) {
        case FILTER_AND: return match == filter->index;
        case FILTER_OR:  return match > 0;
        default: abort();
    }
}

/* ============================================================
 * Public API — filter_match()
 * ============================================================ */
CAPUTILS_API 
int filter_match(struct filter *filter,
                 const void *pkt,
                 struct cap_header *head)
{
    assert(filter && pkt && head);

    if (filter->first) {
        filter->frame_last_ts = head->ts;
        filter->first = 0;
    }

    int match_core =
        (filter->index == 0) ||
        filter_core(filter, pkt, head);

#ifdef HAVE_PCAP
    int match_bpf =
        (filter->bpf_insn == NULL) ||
        bpf_filter(filter->bpf_insn, pkt, head->len, head->caplen);
#else
    int match_bpf = 1;
#endif

    int ok = match_core && match_bpf;

    /* prune old frame ranges */
    if (filter->frame_num &&
        filter->frame_num->upper > 0 &&
        filter->frame_counter > filter->frame_num->upper)
    {
        struct frame_num_node *next = filter->frame_num->next;
        free(filter->frame_num);
        filter->frame_num = next;
    }

    filter->frame_counter++;
    if (ok)
        filter->frame_last_ts = head->ts;

    return ok;
}
