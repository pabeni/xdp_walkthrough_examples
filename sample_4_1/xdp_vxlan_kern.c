// SPDX-License-Identifier: GPL-2.0

#define KBUILD_MODNAME "xdp_drop"
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <bpf/if_vlan.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include <bpf/bpf_helpers.h>
#include "xdp_vxlan_common.h"

struct vxlanhdr {
	__be32 vx_flags;
	__be32 vx_vni;
};

struct bpf_map_def SEC("maps") vxlan_decaps = {
	.type = BPF_MAP_TYPE_PERCPU_HASH,
	.key_size = sizeof(struct vxlan_decap_key),
	.value_size = sizeof(struct vxlan_decap_entry),
	.max_entries = 16,
};

struct bpf_map_def SEC("maps") vxlan_encaps = {
	.type = BPF_MAP_TYPE_PERCPU_HASH,
	.key_size = sizeof(int),
	.value_size = sizeof(struct vxlan_encap_entry),
	.max_entries = 16,
};

/* Parse IPV4 packet to get SRC, DST IP and protocol */
static inline int parse_ipv4(void *data, __u64 *nh_off, void *data_end,
			     __be32 *src, __be32 *dest)
{
	struct iphdr *iph = data + *nh_off;

	if (iph + 1 > data_end)
		return 0;

	*nh_off += iph->ihl << 2;

	*src = iph->saddr;
	*dest = iph->daddr;
	return iph->protocol;
}

/* Parse UDP packet to get source port, destination port and UDP header size */
static inline int parse_udp(void *data, __u64 th_off, void *data_end,
			     __be16 *src_port, __be16 *dest_port)
{
	struct udphdr *uh = data + th_off;

	if (uh + 1 > data_end)
		return 0;

	/* keep life easy and require 0-checksum */
	if (uh->check)
		return 0;

	*src_port = uh->source;
	*dest_port = uh->dest;
	return __constant_ntohs(uh->len);
}

static inline int parse_vxlan(void *data, __u64 offset, void *data_end)
{
	struct vxlanhdr *vxlanh = data + offset;

	if (vxlanh + 1 > data_end)
		return 0;

	if (vxlanh->vx_flags)
		return 0;

	return __constant_ntohl(vxlanh->vx_vni);
}


#define bpf_printk(fmt, ...)                                    \
({                                                              \
		char ____fmt[] = fmt;                            \
		bpf_trace_printk(____fmt, sizeof(____fmt),       \
				##__VA_ARGS__);                 \
})

SEC("prog")
int xdp_drop(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct vxlan_decap_entry *decap_entry;
	struct vxlan_decap_key decap_key;
	struct ethhdr *eth = data;
	struct stats_entry *stats;
	__u16 h_proto;
	__be32 src_ip;
	__be16 src_p;
	__u64 offset;
	unsigned len;
	int ipproto;

	bpf_printk("xdp_drop\n");

	offset = sizeof(*eth);
	if (data + offset > data_end)
		goto pass;

	/* parse vlan */
	h_proto = eth->h_proto;
	if (h_proto == __constant_htons(ETH_P_8021Q) ||
	    h_proto == __constant_htons(ETH_P_8021AD)) {
		struct vlan_hdr *vhdr;

		vhdr = data + offset;
		offset += sizeof(struct vlan_hdr);
		if (data + offset > data_end)
			goto pass;

		h_proto = vhdr->h_vlan_encapsulated_proto;
	}
	if (h_proto != __constant_htons(ETH_P_IP))
		goto pass;

	ipproto = parse_ipv4(data, &offset, data_end, &src_ip, &decap_key.addr);
	if (ipproto != IPPROTO_UDP)
		goto pass;

	len = parse_udp(data, offset, data_end, &src_p, &decap_key.port);
	if (len < sizeof(struct vxlanhdr))
		goto pass;
	if (len > data_end - data - offset)
		goto pass;

	offset += sizeof(struct udphdr);
	decap_key.id = parse_vxlan(data, offset, data_end);
	if (!decap_key.id)
		goto pass;

	decap_entry = bpf_map_lookup_elem(&vxlan_decaps, &decap_key);
	if (!decap_entry)
		goto pass;

	offset += sizeof(struct vxlanhdr);
	bpf_printk("xdp decap pkts %lld:%lld\n", decap_entry->packets, decap_entry->bytes);

	/* broken: no bytes are pulled from the packet */
	ctx->data += offset;
	decap_entry->packets++;
	decap_entry->bytes += ctx->data_end - ctx->data;

	/* sub-optimal performance wise */
	return bpf_redirect(decap_entry->ifindex, 0);

pass:
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";