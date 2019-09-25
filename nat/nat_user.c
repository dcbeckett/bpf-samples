// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
// Copyright (c) 2020 Netronome Systems, Inc.

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <sys/resource.h>

#include "nat_common.h"

const char *prefix = "/sys/fs/bpf/";
static char *instance_name;
static __u32 xdp_flags;
static char *progname;
static int ifindex;

#define PATH_MAX 256

struct cmd {
	const char *cmd;
	int (*func)(int argc, char **argv);
};

static int do_help(int argc, char **argv)
{
	fprintf(stderr,
		"%s [OPTS] <CMD> [ARGS]\n"
		"\n"
		"CMD:\n"
		"  load <instance name for pinning maps>\n"
		"	load program and maps, start polling\n"
		"\n"
		"  mapfill <instance_name>\n"
		"		key_daddr <ipv4> key_dport <port>\n"
		"		val_daddr <ipv4> val_dport <port>\n"
		"		val_saddr <ipv4> val_dmac <mac_addr>\n"
		"		[aggressive_reap <0 or 1>]\n"
		"	add new entry to rules map\n"
		"\n"
		"  mapunfill <instance_name>\n"
		"               key_daddr <ipv4> key_dport <port>\n"
		"       delete entry in rules map\n"
		"\n"
		"ARGS:\n"
		"  -i	interface\n"
		"\n"
		"OPTS:\n"
		"  -h	help\n"
		"  -H	Hardware Mode (XDPOFFLOAD)\n"
		"  -N	Native Mode (XDPDRV)\n"
		"  -S	SKB Mode (XDPGENERIC)\n"
		"\n", progname);

	return 0;
}

static void usage(void)
{
	do_help(0, NULL);
}

#define NEXT_ARG()	({ argc--; argv++; if (argc < 0) usage(); })
#define NEXT_ARGP()	({ (*argc)--; (*argv)++; if (*argc < 0) usage(); })
#define BAD_ARG()	({ p_err("what is '%s'?", *argv); -1; })
#define GET_ARG()	({ argc--; *argv++; })
#define REQ_ARGS(cnt)							\
	({								\
		int _cnt = (cnt);					\
		bool _res;						\
									\
		if (argc < _cnt) {					\
			p_err("'%s' needs at least %d arguments, %d found", \
			      argv[-1], _cnt, argc);			\
			_res = false;					\
		} else {						\
			_res = true;					\
		}							\
		_res;							\
	})

static void p_err(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "Error: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
}

static int do_unpinning(char *path)
{
	if (unlink(path)) {
		p_err("failed to unpin %s: %s", path, strerror(errno));
		return -1;
	}

	printf("unpinned map at %s\n", path);
	return 0;
}

static void exit_prog(int sig)
{
	char path[PATH_MAX];
	int fixed_len;

	printf("unloading program...\n");
	bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);

	fixed_len = strlen(prefix) + 1;

	snprintf(path, sizeof(path) - fixed_len, "%s%s_rules", prefix,
		 instance_name);
	do_unpinning(path);
	snprintf(path, sizeof(path) - fixed_len, "%s%s_flows", prefix,
		 instance_name);
	do_unpinning(path);
	snprintf(path, sizeof(path) - fixed_len, "%s%s_stats", prefix,
		 instance_name);
	do_unpinning(path);

	exit(sig);
}

void set_max_rlimit(void)
{
	struct rlimit rinf = { RLIM_INFINITY, RLIM_INFINITY };

	setrlimit(RLIMIT_MEMLOCK, &rinf);
}

static void do_pinning(struct bpf_object *obj, char *filename, char *map_name)
{
	struct bpf_map *map;
	char path[PATH_MAX];
	int fixed_len;
	int map_fd;

	fixed_len = strlen(prefix) + 1;
	snprintf(path, sizeof(path) - fixed_len, "%s%s", prefix, filename);

	map = bpf_object__find_map_by_name(obj, map_name);
	if (!map) {
		p_err("failed to find map %s", map_name);
		bpf_object__close(obj);
		exit_prog(-1);
	}

	map_fd = bpf_map__fd(map);
	if (map_fd < 0) {
		p_err("failed to find map fd for server mapping");
		bpf_object__close(obj);
		exit_prog(-1);
	}

	if (bpf_obj_pin(map_fd, path)) {
		p_err("failed to pin map: %s", strerror(errno));
		bpf_object__close(obj);
		exit_prog(-1);
	}

	printf("Pinned map at %s\n", path);
}

static int do_load(int argc, char **argv)
{
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type = BPF_PROG_TYPE_XDP,
		.file = "nat_kern.o",
	};
	struct bpf_object *obj;
	char filename[32];
	int prog_fd;

	if (!REQ_ARGS(1))
		return -1;

	set_max_rlimit();

	if (xdp_flags & XDP_FLAGS_HW_MODE)
		prog_load_attr.ifindex = ifindex;

	/* use libbpf to load program */
	if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd)) {
		p_err("failed to load file");
		return -1;
	}

	if (prog_fd < 1) {
		p_err("error creating prog_fd");
		bpf_object__close(obj);
		return -1;
	}

	/* Pin maps */
	instance_name = argv[0];

	snprintf(filename, sizeof(filename), "%s_rules", instance_name);
	do_pinning(obj, filename, "server_rules");

	snprintf(filename, sizeof(filename), "%s_flows", instance_name);
	do_pinning(obj, filename, "nat_flows_map");

	snprintf(filename, sizeof(filename), "%s_stats", instance_name);
	do_pinning(obj, filename, "prog_stats");

	/* use libbpf to link program to interface with corresponding flags */
	if (bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags) < 0) {
		p_err("error setting fd onto xdp");
		bpf_object__close(obj);
		exit_prog(-1);
	}

	signal(SIGINT, exit_prog);
	signal(SIGTERM, exit_prog);

	printf("ctrl + c to exit\n");
	while (1)
		usleep(500000);

	return 0;
}

static int do_map_fill(int argc, char **argv)
{
	struct ether_addr *val_dmac = NULL;
	struct rule_value newval = {};
	bool aggressive_reap = 0;
	struct pkt_dst key = {};
	__u32 key_daddr = 0;
	__u16 key_dport = 0;
	__u32 val_saddr = 0;
	__u32 val_daddr = 0;
	__u16 val_dport = 0;
	char path[PATH_MAX];
	unsigned long tmp;
	int fixed_len;
	char *endptr;
	int map_fd;

	if (!REQ_ARGS(1))
		return -1;

	instance_name = argv[0];
	NEXT_ARG();

	fixed_len = strlen(prefix) + 1;
	snprintf(path, sizeof(path) - fixed_len, "%s%s_rules", prefix,
		 instance_name);

	map_fd = bpf_obj_get(path);
	if (map_fd < 0) {
		p_err("failed to get map fd from id");
		return -1;
	}

	while (argc) {
		if (!strcmp(*argv, "key_daddr")) {
			NEXT_ARG();
			if (!REQ_ARGS(1))
				return -1;

			if (inet_pton(AF_INET, argv[0], &key_daddr) != 1) {
				p_err("failed to parse key_daddr");
				return -1;
			}
		} else if (!strcmp(*argv, "key_dport")) {
			NEXT_ARG();
			if (!REQ_ARGS(1))
				return -1;

			tmp = strtoul(argv[0], &endptr, 0);
			if (*endptr != '\0' || tmp > 0xffff) {
				p_err("failed to parse key_dport");
				return -1;
			}
			key_dport = htons(tmp);
		} else if (!strcmp(*argv, "val_saddr")) {
			NEXT_ARG();
			if (!REQ_ARGS(1))
				return -1;

			if (inet_pton(AF_INET, argv[0], &val_saddr) != 1) {
				p_err("failed to parse val_saddr");
				return -1;
			}
		} else if (!strcmp(*argv, "val_daddr")) {
			NEXT_ARG();
			if (!REQ_ARGS(1))
				return -1;

			if (inet_pton(AF_INET, argv[0], &val_daddr) != 1) {
				p_err("failed to parse val_daddr");
				return -1;
			}
		} else if (!strcmp(*argv, "val_dport")) {
			NEXT_ARG();
			if (!REQ_ARGS(1))
				return -1;

			tmp = strtoul(argv[0], &endptr, 0);
			if (*endptr != '\0' || tmp > 0xffff) {
				p_err("failed to parse val_dport");
				return -1;
			}
			val_dport = htons(tmp);
		} else if (!strcmp(*argv, "val_dmac")) {
			NEXT_ARG();
			if (!REQ_ARGS(1))
				return -1;

			val_dmac = ether_aton(argv[0]);
			if (!val_dmac) {
				p_err("failed to parse ether address");
				return -1;
			}
		} else if (!strcmp(*argv, "aggressive_reap")) {
			NEXT_ARG();
			if (!REQ_ARGS(1))
				return -1;

			tmp = strtoul(argv[0], &endptr, 0);
			if (*endptr != '\0' || tmp > 1) {
				p_err("failed to parse aggressive_reap");
				return -1;
			}
			aggressive_reap = htons(tmp);
		} else {
			p_err("expected no more arguments, 'key_daddr'," \
			      "'key_dport', 'val_saddr', 'val_daddr'," \
			      "'val_dport', 'val_dmac', 'aggressive_reap'," \
			      " got: '%s'?",
			      *argv);
			return -1;
		}
		NEXT_ARG();
	}

	key.daddr = key_daddr;
	key.dport = key_dport;

	newval.saddr = val_saddr;
	newval.daddr = val_daddr;
	newval.dport = val_dport;
	newval.aggressive_reap = aggressive_reap;

	if (val_dmac)
		memcpy(&newval.dmac, val_dmac, sizeof(struct ether_addr));

	if (bpf_map_update_elem(map_fd, &key, &newval, BPF_ANY)) {
		p_err("failed to update map: %s", strerror(errno));
		return -1;
	}

	return 0;
}

static int do_map_unfill(int argc, char **argv)
{
	struct pkt_dst key = {};
	unsigned long tmp = 0;
	__u32 key_daddr = 0;
	__u16 key_dport = 0;
	char path[PATH_MAX];
	int fixed_len;
	char *endptr;
	int map_fd;

	if (!REQ_ARGS(1))
		return -1;

	instance_name = argv[0];
	NEXT_ARG();

	fixed_len = strlen(prefix) + 1;
	snprintf(path, sizeof(path) - fixed_len, "%s%s_rules", prefix,
		 instance_name);

	map_fd = bpf_obj_get(path);
	if (map_fd < 0) {
		p_err("failed to get map fd from id");
		return -1;
	}

	while (argc) {
		if (!strcmp(*argv, "key_daddr")) {
			NEXT_ARG();
			if (!REQ_ARGS(1))
				return -1;

			if (inet_pton(AF_INET, argv[0], &key_daddr) != 1) {
				p_err("failed to parse key_daddr");
				return -1;
			}
		} else if (!strcmp(*argv, "key_dport")) {
			NEXT_ARG();
			if (!REQ_ARGS(1))
				return -1;

			tmp = strtoul(argv[0], &endptr, 0);
			if (*endptr != '\0' || tmp > 0xffff) {
				p_err("failed to parse key_dport");
				return -1;
			}
			key_dport = htons(tmp);
		} else {
			p_err("expected no more arguments, 'key_daddr', 'key_dport' got: '%s'?",
			      *argv);
			return -1;
		}
		NEXT_ARG();
	}

	key.daddr = key_daddr;
	key.dport = key_dport;

	if (bpf_map_delete_elem(map_fd, &key)) {
		p_err("failed to delete map entry: %s", strerror(errno));
		return -1;
	}

	return 0;
}

static const struct cmd cmds[] = {
	{ "help",	do_help },
	{ "load",	do_load },
	{ "mapfill",	do_map_fill },
	{ "mapunfill",  do_map_unfill },
	{ 0 }
};

static int
cmd_select(const struct cmd *cmds, int argc, char **argv)
{
	unsigned int i;

	if (argc < 1 && cmds[0].func)
		return cmds[0].func(argc, argv);

	for (i = 0; cmds[i].func; i++)
		if (!strcmp(*argv, cmds[i].cmd))
			return cmds[i].func(argc - 1, argv + 1);

	do_help(argc, argv);

	return -1;
}

int main(int argc, char **argv)
{
	int opt;

	progname = argv[0];
	xdp_flags = XDP_FLAGS_DRV_MODE; /* default to DRV */
	if (argc == 1) {
		usage();
		return -1;
	}

	while ((opt = getopt(argc, argv, "hHi:NS")) != -1) {
		switch (opt) {
		case 'h':
			usage();
			return 0;
		case 'H':
			xdp_flags = XDP_FLAGS_HW_MODE;
			break;
		case 'i':
			ifindex = if_nametoindex(optarg);
			if (ifindex == 0) {
				p_err("invalid interface");
				return -1;
			}
			break;
		case 'N':
			xdp_flags = XDP_FLAGS_DRV_MODE;
			break;
		case 'S':
			xdp_flags = XDP_FLAGS_SKB_MODE;
			break;
		default:
			return -1;
		}
	}

	argc -= optind;
	argv += optind;
	if (argc < 0)
		usage();

	return cmd_select(cmds, argc, argv);
}
