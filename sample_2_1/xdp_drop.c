// SPDX-License-Identifier: GPL-2.0

#define KBUILD_MODNAME "xdp_drop"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>

#include "bpf_helpers.h"


/* Parse IPV4 packet to get SRC, DST IP and protocol */
static inline int parse_ipv4(void *data, __u64 nh_off, void *data_end,
			     __be32 *src, __be32 *dest)
{
	struct iphdr *iph = data + nh_off;

	*src = iph->saddr;
	*dest = iph->daddr;
	return iph->protocol;
}

SEC("prog")
int xdp_drop(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	__be32 dest_ip, src_ip;
	__u16 h_proto;
	__u64 nh_off;
	int ipproto;

	nh_off = sizeof(*eth);

	/* parse vlan */
	h_proto = eth->h_proto;
	if (h_proto == __constant_htons(ETH_P_8021Q) ||
	    h_proto == __constant_htons(ETH_P_8021AD)) {
		struct vlan_hdr *vhdr;

		vhdr = data + nh_off;
		nh_off += sizeof(struct vlan_hdr);
		h_proto = vhdr->h_vlan_encapsulated_proto;
	}
	if (h_proto != __constant_htons(ETH_P_IP))
		goto pass;

	ipproto = parse_ipv4(data, nh_off, data_end, &src_ip, &dest_ip);
	if (src_ip & 1)
		return XDP_DROP;

pass:
	return XDP_PASS;
}

