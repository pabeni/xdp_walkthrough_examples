#include <arpa/inet.h>
#include <net/if.h>
#include <error.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "xdp_drop_common.h"

#define MAX_ADDR 2

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
	struct stats_entry entry;
	char *dev_name = argv[1];
	struct bpf_object *obj;
	__be32 saddr[MAX_ADDR];
	int prog_fd, map_fd;
	struct bpf_map *map;
	int saddr_nr = 0;
	int ifindex;
	int i;

	if (argc < 2)
		error(1, 0, "syntax:%s <NIV> [<ipv4 addr>..]");

	if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd))
		error(1, errno, "can't load file %s", prog_load_attr.file);

	ifindex = if_nametoindex(dev_name);
	if (!ifindex)
		error(1, errno, "unknown interface %s\n", dev_name);
	if (bpf_set_link_xdp_fd(ifindex, prog_fd, 0) < 0)
		error(1, errno, "can't attach xdp program to interface %s:%d: "
		        "%d:%s\n", dev_name, ifindex, errno, strerror(errno));

	map = bpf_object__find_map_by_name(obj, "drop_map");
	if (!map)
		error(1, errno, "can't load drop_map");
	map_fd = bpf_map__fd(map);
	if (map_fd < 0)
		error(1, errno, "can't get drop_map fd");


	for (i = 2; i < argc && saddr_nr < MAX_ADDR; ++i) {
		__be32 ipv4_addr;
		if (inet_pton(AF_INET, argv[i], &ipv4_addr) != 1)
			error(1, errno, "invalid address %s\n", argv[i]);

		memset(&entry, 0, sizeof(entry));
		if (bpf_map_update_elem(map_fd, &ipv4_addr, &entry, BPF_ANY))
			error(1, errno, "can't add address %x\n", ipv4_addr);
		saddr[saddr_nr] = ipv4_addr;
		saddr_nr++;
	}

	signal(SIGINT, sigint_handler);
	signal(SIGPIPE, sigint_handler);

	while (!interrupted) {
		sleep(1);

		for (i = 0; i < saddr_nr; ++i) {
			__be32 ipv4_addr = saddr[i];
			if (bpf_map_lookup_elem(map_fd, &ipv4_addr, &entry))
				error(1, errno, "no stats for address %x\n",
				      ipv4_addr);
			printf("addr %x drop %lld:%lld\n", ipv4_addr,
			       entry.packets, entry.bytes);
		}
	}

	bpf_set_link_xdp_fd(ifindex, -1, 0);
	return 0;
}