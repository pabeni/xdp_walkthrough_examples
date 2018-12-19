struct vxlan_decap_key {
	__be32 addr;
	__be16 port;
	int id;
};

struct vxlan_decap_entry {
	__u64 packets;
	__u64 bytes;
	int ifindex;
};

struct vxlan_encap_entry {
	char hdrs[ETH_HLEN + 20 + 8 + 8];
	int ifindex;
	__u64 packets;
	__u64 bytes;
};