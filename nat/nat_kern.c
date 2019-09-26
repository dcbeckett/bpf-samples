// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
// Copyright (c) 2020 Netronome Systems, Inc.

#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "nat_common.h"

#define MAX_LISTEN_PORTS	2048
#define MAX_CLIENTS		1500000
#define MAX_FLOWS		(MAX_CLIENTS * 2)

#define IP_FRAGMENTED		0xFF3F
#define MAX_TCP_PORT		0xFFFF /* power of 2 */

#define LOG_REAP_FLOWS		0 /* Notify host app about reap flows */

/* Next Hop Map */
struct bpf_map_def SEC("maps") server_rules = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct pkt_dst),
	.value_size = sizeof(struct rule_value),
	.max_entries = MAX_LISTEN_PORTS,
};

/* Active Flows Map */
struct bpf_map_def SEC("maps") nat_flows_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct flow_key),
	.value_size = sizeof(struct egress_nat_value),
	.max_entries = MAX_FLOWS,
};

/* Perf Events - New Conns Notifier */
struct bpf_map_def SEC("maps") perf_map = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = MAX_CPU,
};

/* Stats Map */
struct bpf_map_def SEC("maps") prog_stats = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u64),
	.max_entries = 2,
};

static __always_inline void notify_host(struct xdp_md *ctx,
					struct flow_key *ingress,
					struct egress_nat_value *egress,
					__u16 action)
{
	struct perf_value perf_log = {};

	memcpy(&perf_log.client, ingress, sizeof(struct flow_key));
	memcpy(&perf_log.client_nat, egress, sizeof(struct egress_nat_value));
	perf_log.action = action;
	bpf_perf_event_output(ctx, &perf_map, 0 | BPF_F_CURRENT_CPU,
			      &perf_log, sizeof(perf_log));
}

static __always_inline int get_unique_nat_port(__u32 nat_saddr, __u32 nat_daddr,
					       __u16 nat_dport)
{
	struct egress_nat_value *value;
	struct flow_key nat_id = {};

	nat_id.daddr = nat_saddr;
	nat_id.saddr = nat_daddr;
	nat_id.sport = nat_dport;

	#pragma clang loop unroll(full)
	for (int i = 0; i < 16; i++) { /* 16 attempts to find a unique tuple */
		nat_id.dport = bpf_get_prandom_u32() & MAX_TCP_PORT;
		if (nat_id.dport == 0) /* disallow port 0 */
			nat_id.dport++;

		value = bpf_map_lookup_elem(&nat_flows_map, &nat_id);
		if (!value) /* tuple available within map */
			return nat_id.dport;
	}
	return 0;
}

static void update_header_field(__u16 *csum, __u16 *old_val, __u16 *new_val)
{
	__u32 new_csum_value;
	__u32 new_csum_comp;
	__u32 undo;

	/* Get old sum of headers by getting one's compliment and adding
	 * one's compliment of old header value (effectively subtracking)
	 */
	undo = ~((__u32) *csum) + ~((__u32) *old_val);

	/* Check for old header overflow and compensate
	 * Add new header value
	 */
	new_csum_value = undo + (undo < ~((__u32) *old_val)) + (__u32) *new_val;

	/* Check for new header overflow and compensate */
	new_csum_comp = new_csum_value + (new_csum_value < ((__u32) *new_val));

	/* Add any overflow of the 16 bit value to itself */
	new_csum_comp = (new_csum_comp & 0xFFFF) + (new_csum_comp >> 16);

	/* Check that overflow added above did not cause another overflow */
	new_csum_comp = (new_csum_comp & 0xFFFF) + (new_csum_comp >> 16);

	/* Cast to 16 bit one's compliment of sum of headers */
	*csum = (__u16) ~new_csum_comp;

	/* Update header to new value */
	*old_val = *new_val;
}

static __always_inline int process_packet(struct xdp_md *ctx, __u64 off)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct egress_nat_value return_egress_nat = {};
	struct egress_nat_value new_egress_nat = {};
	struct egress_nat_value *egress_nat;
	struct flow_key return_ingress_flow = {};
	struct flow_key ingress_flow = {};
	struct pkt_dst rule_key = {};
	struct ethhdr *eth = data;
	struct rule_value *rule_val;
	struct udphdr *udp;
	struct iphdr *iph;
	__u16 nat_port = 0;
	__u64 *stats_cntr;
	__u16 *p_iph_16;
	__u32 stats_key;
	bool reap_flow;
	__u32 csum = 0;
	__u16 err = 0;

	iph = data + off;
	if ((void *) (iph + 1) > data_end)
		return XDP_PASS;
	if (iph->ihl != 5)
		return XDP_PASS;

	off += sizeof(struct iphdr);

	/* do not support fragmented packets as L4 headers may be missing */
	if (iph->frag_off & IP_FRAGMENTED)
		return XDP_PASS;

	/* Only process UDP */
	if (iph->protocol != IPPROTO_UDP)
		return XDP_PASS;

	udp = data + off;
	if ((void *) (udp + 1) > data_end)
		return XDP_PASS;

	/* [Client] -> ingress_flow -> [BPF] -> egress_nat -> [Server] */
	ingress_flow.saddr = iph->saddr;
	ingress_flow.daddr = iph->daddr;
	ingress_flow.sport = udp->source;
	ingress_flow.dport = udp->dest;

	/* Lookup flow map to see if NAT exists */
	egress_nat = bpf_map_lookup_elem(&nat_flows_map, &ingress_flow);
	if (!egress_nat) {
		/* Generate a new NAT flow, get nat dest from map */
		rule_key.daddr = ingress_flow.daddr;
		rule_key.dport = ingress_flow.dport;
		rule_val = bpf_map_lookup_elem(&server_rules, &rule_key);
		if (!rule_val)
			return XDP_PASS; /* if rule does not exist, pass */

		new_egress_nat.saddr = rule_val->saddr;
		new_egress_nat.daddr = rule_val->daddr;
		new_egress_nat.dport = rule_val->dport;

		/* Generate unique nat port, Map NAT is stored in return dir */
		nat_port = get_unique_nat_port(rule_val->saddr, rule_val->daddr,
					       rule_val->dport);
		if (nat_port == 0)
			return XDP_ABORTED; /* no unique port available */
		new_egress_nat.sport = nat_port;

		new_egress_nat.pkt_cnt = 0;
		new_egress_nat.byte_cnt = 0;
		new_egress_nat.aggressive_reap = 0;
		memcpy(new_egress_nat.dmac, rule_val->dmac,
		       sizeof(rule_val->dmac));

		/* If this is a reap udp ping flow the forward flow will not be
		 * installed into the map, as there should be no further packets
		 * from the Client.
		 */
		reap_flow = rule_val->aggressive_reap;
		if (!reap_flow) {
			err = bpf_map_update_elem(&nat_flows_map, &ingress_flow,
						  &new_egress_nat, BPF_NOEXIST);
			if (err)
				return XDP_ABORTED;

			notify_host(ctx, &ingress_flow, &new_egress_nat,
				    FLOW_ADD);
		} else if (LOG_REAP_FLOWS) {
			notify_host(ctx, &ingress_flow, &new_egress_nat,
				    FLOW_ADD_REAP);
		}

		/* Add return direction to tuple map for use by future packets
		 * [Client] <- return_egress_nat <- [BPF] <- return_ingress_flow <- [Server]
		 */
		return_ingress_flow.saddr = new_egress_nat.daddr;
		return_ingress_flow.daddr = new_egress_nat.saddr;
		return_ingress_flow.sport = new_egress_nat.dport;
		return_ingress_flow.dport = nat_port;

		return_egress_nat.saddr = ingress_flow.daddr;
		return_egress_nat.daddr = ingress_flow.saddr;
		return_egress_nat.sport = ingress_flow.dport;
		return_egress_nat.dport = ingress_flow.sport;
		return_egress_nat.pkt_cnt = 0;
		return_egress_nat.byte_cnt = 0;
		return_egress_nat.aggressive_reap = reap_flow;
		memcpy(return_egress_nat.dmac, eth->h_source,
		       sizeof(eth->h_source));

		err = bpf_map_update_elem(&nat_flows_map, &return_ingress_flow,
					  &return_egress_nat, BPF_NOEXIST);
		if (err) {
			/* If collision, clean up previous entry and abort */
			bpf_map_delete_elem(&nat_flows_map,
					    &ingress_flow);
			return XDP_ABORTED;
		}

		if (!reap_flow)
			stats_key = STATS_FLOW;
		else
			stats_key = STATS_REAP_ACTIVE;

		stats_cntr = bpf_map_lookup_elem(&prog_stats, &stats_key);
		if (stats_cntr)
			__sync_fetch_and_add(stats_cntr, 1);

		/* Update packet with egress NAT values from stack */
		memcpy(eth->h_source, eth->h_dest, sizeof(eth->h_dest));
		memcpy(eth->h_dest, new_egress_nat.dmac,
		       sizeof(new_egress_nat.dmac));

		update_header_field(&udp->check, &udp->dest,
				    &new_egress_nat.dport);
		update_header_field(&udp->check, &udp->source,
				    &new_egress_nat.sport);

		update_header_field(&udp->check, (__u16 *) &iph->saddr,
				    (__u16 *) &new_egress_nat.saddr);
		update_header_field(&udp->check, (__u16 *) &iph->saddr + 1,
				    (__u16 *) &new_egress_nat.saddr + 1);
		update_header_field(&udp->check, (__u16 *) &iph->daddr,
				    (__u16 *) &new_egress_nat.daddr);
		update_header_field(&udp->check, (__u16 *) &iph->daddr + 1,
				    (__u16 *) &new_egress_nat.daddr + 1);

	} else {
		/* Update packet with egress NAT values from map
		 * Note: Code duplication is required for calculated NAT values
		 * vs pre-existing map values to allow for the NFP JIT
		 * to know which hw memory location the NAT data will be
		 * obtained from
		 */
		memcpy(eth->h_source, eth->h_dest, sizeof(eth->h_dest));
		memcpy(eth->h_dest, egress_nat->dmac, sizeof(egress_nat->dmac));

		update_header_field(&udp->check, &udp->dest,
				    &egress_nat->dport);
		update_header_field(&udp->check, &udp->source,
				    &egress_nat->sport);

		update_header_field(&udp->check, (__u16 *) &iph->saddr,
				    (__u16 *) &egress_nat->saddr);
		update_header_field(&udp->check, (__u16 *) &iph->saddr + 1,
				    (__u16 *) &egress_nat->saddr + 1);
		update_header_field(&udp->check, (__u16 *) &iph->daddr,
				    (__u16 *) &egress_nat->daddr);
		update_header_field(&udp->check, (__u16 *) &iph->daddr + 1,
				    (__u16 *) &egress_nat->daddr + 1);

		if (egress_nat->aggressive_reap) {
			/* if it's the response pkt for the reap, cleanup map */
			err = bpf_map_delete_elem(&nat_flows_map,
						  &ingress_flow);
			if (err == 0) {
				stats_key = STATS_REAP_ACTIVE;
				stats_cntr = bpf_map_lookup_elem(&prog_stats,
								 &stats_key);
				if (stats_cntr)
					__sync_fetch_and_add(stats_cntr, -1);
				if (LOG_REAP_FLOWS)
					notify_host(ctx, &ingress_flow,
						    egress_nat, FLOW_DELETE);
			}
		} else {
			/* increment tuple flow counters */
			__sync_fetch_and_add(&egress_nat->pkt_cnt, 1);
			__sync_fetch_and_add(&egress_nat->byte_cnt,
					     data_end - data);
		}
	}

	/* Update IPv4 header checksum */
	iph->check = 0;
	p_iph_16 = (__u16 *)iph;
	#pragma clang loop unroll(full)
	for (int i = 0; i < (int)sizeof(*iph) >> 1; i++)
		csum += *p_iph_16++;
	iph->check = ~((csum & 0xffff) + (csum >> 16));

	return XDP_TX;
}

SEC("xdp")
int nat_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	__u32 eth_proto;
	__u32 nh_off;

	nh_off = sizeof(struct ethhdr);
	if (data + nh_off > data_end)
		return XDP_PASS;
	eth_proto = eth->h_proto;

	/* Nat only accepts IPv4 traffic */
	if (eth_proto == bpf_htons(ETH_P_IP))
		return process_packet(ctx, nh_off);
	else
		return XDP_PASS;
}
char _license[] SEC("license") = "Dual BSD/GPL";
