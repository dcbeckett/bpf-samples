/* SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause) */
/* Copyright (c) 2020 Netronome Systems, Inc. */

#define MAX_CPU			128

#define FLOW_ADD		0
#define FLOW_ADD_REAP		1
#define FLOW_DELETE		2

#define STATS_FLOW		0
#define STATS_REAP_ACTIVE	1

struct pkt_dst {
	__u32 daddr;
	__u16 dport;
} __attribute__((__packed__));

struct rule_value {
	__u32 saddr;
	__u32 daddr;
	__u16 dport;
	__u8 dmac[6];
	bool aggressive_reap;
};

struct flow_key {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
};

struct egress_nat_value {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u8 dmac[6];
	bool aggressive_reap;
	__u64 pkt_cnt;
	__u64 byte_cnt;
};

/* Perf Event Map */
struct perf_value {
	struct flow_key client;
	struct egress_nat_value client_nat;
	__u16 action;
} __attribute__((__packed__));
