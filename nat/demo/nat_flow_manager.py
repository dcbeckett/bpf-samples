#!/usr/bin/env python3
# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
# Copyright (c) 2020 Netronome Systems, Inc.

import argparse
import json
import os
import subprocess
import sys
import time
from bpftool_utils import *
from datetime import datetime

def key_to_str(key):
    '''
    flow key stored in layout SRC_IP|DST_IP|SRC_PORT|DST_PORT
    parse hex digits from string, then convert to integer
    '''
    src_hex = [key[0:2], key[2:4], key[4:6], key[6:8]]
    client_src = [int(byte, 16) for byte in src_hex]

    dst_hex = [key[8:10], key[10:12], key[12:14], key[14:16]]
    client_dst = [int(byte, 16) for byte in dst_hex]

    src_port_hex = [key[16:20]]
    client_sport = [int(byte, 16) for byte in src_port_hex]

    dst_port_hex = [key[20:24]]
    client_dport = [int(byte, 16) for byte in dst_port_hex]

    client_sip = '%s.%s.%s.%s' % (client_src[0], client_src[1],
                                  client_src[2], client_src[3])

    client_dip = '%s.%s.%s.%s' % (client_dst[0], client_dst[1],
                                  client_dst[2], client_dst[3])

    key_str = ("%s:%s -> %s:%s" % (client_sip, client_sport[0],
                                client_dip, client_dport[0]))
    return key_str

def get_reverse_flow_key(nat_value):
    '''
    Egress NAT stored as SRC_IP|DST_IP|SRC_PORT|DST_PORT
    Swap SRC and DST directions to obtain the reverse flow's ingress key
    '''
    reverse_key = nat_value[4:8]
    reverse_key.extend(nat_value[0:4])
    reverse_key.extend(nat_value[10:12])
    reverse_key.extend(nat_value[8:10])
    return ''.join([byte.replace('0x', '') for byte in reverse_key])

def main():
    batchfile = "batchfile.txt"
    flow_state = {}
    n_deleted = 0

    parser = argparse.ArgumentParser(description="Display NAT statistics")
    parser.add_argument('-i', '--interface', action='store', required=True,
                        help='xdp network interface')
    parser.add_argument('-v', '--verbose', action='store_true', required=False,
                        help='Show each flow stats', default=False)
    parser.add_argument('--inactive_time', action='store', required=False,
                        type=int, default=15, help='flow idle time for statistics')
    parser.add_argument('--expire_time', action='store', required=False,
                        type=int, default=60, help='idle time to trigger flow deletion')
    parser.add_argument('--poll_time', action='store', required=False, type=int,
                        default=10, help='time between BPF map polls')
    args = parser.parse_args()
    interface = args.interface

    while True:
        clock = time.time()
        batch_delete = ""
        map_vals = {}
        n_active = 0
        n_idle = 0
        pr = ""
        n = 0

        # get current NAT BPF map data
        try:
            map_id = get_map_ids(interface)[1]
            map_vals = dump_map(map_id)
            xdp_type = get_map_dev(map_id)
            header = ("== NAT statistics [%s] ==\n\n" % xdp_type)
        except:
            print("Error accessing eBPF map")
            time.sleep(1)
            continue

        # parse map values
        for record in map_vals:
            expire_flow = 0
            extra_str = ""
            n += 1

            key = ''.join([byte.replace('0x', '') for byte in record['key']])
            map_pkt = hex_list_to_int(record['value'][24:32])
            map_bw = hex_list_to_int(record['value'][32:40])

            # check for new flow
            if key not in flow_state:
                flow_state[key] = [map_pkt, map_bw, clock]

            # get previous flow values
            old_pkt = flow_state[key][0]
            old_bw = flow_state[key][1]
            old_clock = flow_state[key][2]

            if map_pkt > old_pkt: # update with curr time if flow is in-use
               flow_state[key] = [map_pkt, map_bw, clock]

            # check if flow is idle and requires cleanup
            if old_clock < (clock - args.expire_time):
                # also check the reverse direction before removal
                reverse = get_reverse_flow_key(record['value'][0:12])
                if reverse not in flow_state:
                    # aggressive reap flow (no rev dir)
                    expire_flow = 1
                elif flow_state[reverse][2] < (clock - args.expire_time):
                    # reverse direction has also expired, safe to remove
                    expire_flow = 1
                else:
                    # reverse direction is still in-use, keep this flow active
                    n_idle += 1
                    extra_str = "[IDLE_1WAY]"
            elif old_clock < (clock - args.inactive_time):
                # flow is idle - mark this as idle for user stats counter
                n_idle += 1
                extra_str = "[IDLE %2ds]" % int(clock - old_clock)
            else:
                n_active += 1

            if expire_flow:
                # remove flow from BPF map and statistics
                del flow_state[key]
                batch_delete += bpftool_delete(map_id, key)
                extra_str = "[REMOVE]"
                n_deleted += 1

            pr += ("{:4d}\t{:40s} {:12,} pkts {:15,} Bytes {:8s}\n"
                  .format(n, key_to_str(key), map_pkt, map_bw, extra_str))

        execute_batch(batchfile, batch_delete);

        os.system("clear")
        print(header)

        if args.verbose:
            print(pr)

        now = datetime.now()
        s = ("{:9s} \t Active: {:7,}\tInactive: {:7,}\tExpired: {:7,} \n"
                  .format(now.strftime("%d/%m/%Y %H:%M:%S"), n_active, n_idle,
                          n_deleted))
        print(s)
        time.sleep(max(0, args.poll_time - (time.time() - clock)))

if __name__== "__main__":
  main()
