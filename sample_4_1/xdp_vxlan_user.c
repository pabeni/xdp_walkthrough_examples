#include <arpa/inet.h>
#include <net/if.h>
#include <error.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include <linux/if_ether.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "xdp_vxlan_common.h"

#define MAX_TUNNELS 2

static bool interrupted;

static void sigint_handler(int signum)
{
	printf("interrupted\n");
	interrupted = true;
}

int main(int argc, char *argv[])
{
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type	= BPF_PROG_TYPE_XDP,
		.file		= "xdp_drop_kern.o",
	};
	struct vxlan_decap_key decap_key[MAX_TUNNELS];
	int nr_cpus = sysconf(_SC_NPROCESSORS_CONF);
	struct vxlan_decap_entry *decap_entry;
	int decap_ifindex[MAX_TUNNELS];
	struct bpf_object *obj;
	int prog_fd, map_fd;
	struct bpf_map *map;
	int tunnel_nr = 0;
	int ifindex;
	int i, j;

	if (argc < 2)
		error(1, 0, "syntax:%s <NIC> <decap target> <local ip> <local port> <vni>");

	decap_entry = calloc(nr_cpus, sizeof(struct vxlan_decap_entry));
	if (!decap_entry)
		error(1, 0, "can't allocate entry\n");

	if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd))
		error(1, errno, "can't load file %s", prog_load_attr.file);

	for (i = 1; i < argc - 5 && tunnel_nr < MAX_TUNNELS; ++i) {
		struct vxlan_decap_key *key = &decap_key[tunnel_nr];

		decap_ifindex[tunnel_nr] = if_nametoindex(argv[i]);
		if (!ifindex)
			error(1, errno, "unknown interface %s\n", argv[i]);
		if (bpf_set_link_xdp_fd(ifindex, prog_fd, 0) < 0)
			error(1, errno, "can't attach xdp program to interface %s:%d: "
				"%d:%s\n", argv[i], ifindex, errno, strerror(errno));

		map = bpf_object__find_map_by_name(obj, "vxlan_decaps");
		if (!map)
			error(1, errno, "can't load drop_map");
		map_fd = bpf_map__fd(map);
		if (map_fd < 0)
			error(1, errno, "can't get drop_map fd");

		++i;
		decap_entry[0].ifindex = if_nametoindex(argv[i]);
		if (!decap_entry[0].ifindex)
			error(1, errno, "unknown interface %s\n", argv[i]);
		for (j = 1; j < nr_cpus; ++j)
			decap_entry[j].ifindex = decap_entry[0].ifindex;

		++i;
		if (inet_pton(AF_INET, argv[i], &key->addr) != 1)
			error(1, errno, "invalid address %s\n", argv[i]);
		++i;
		key->port = htons(atoi(argv[i]));
		++i;
		key->id = atoi(argv[i]);

		/* likely broken: we need to attach a bpf on
		 * decap_entry[0].ifindex to allow redirect working on such
		 * device
		 */
		if (bpf_map_update_elem(map_fd, key, decap_entry, BPF_ANY))
			error(1, errno, "can't add decap %x:%d:%d\n", key->addr,
			      key->port, key->id);
		tunnel_nr++;
	}

	signal(SIGINT, sigint_handler);
	signal(SIGPIPE, sigint_handler);

	while (!interrupted) {
		sleep(1);

		for (i = 0; i < tunnel_nr; ++i) {
			struct vxlan_decap_key *key = &decap_key[i];
			struct vxlan_decap_entry all = { 0, 0, 0};

			if (bpf_map_lookup_elem(map_fd, key, decap_entry))
				error(1, errno, "no stats for tunnel %x:%d:%d\n",
				      key->addr, key->port, key->id);

			for (j = 0; j < nr_cpus; j++) {
				all.packets += decap_entry[j].packets;
				all.bytes += decap_entry[j].bytes;
			}

			printf("tunnel %x:%d:%d drop %lld:%lld\n", key->addr,
			       key->port, key->id, all.packets, all.bytes);
		}
	}

	for (i = 0; i < tunnel_nr; ++i)
		bpf_set_link_xdp_fd(decap_ifindex[i], -1, 0);
	return 0;
}